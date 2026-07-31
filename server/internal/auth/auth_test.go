package auth_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tildra/tildra/server/internal/auth"
	"github.com/tildra/tildra/server/internal/model"
	"github.com/tildra/tildra/server/internal/store/memory"
)

// The authentication package, which had no tests of its own.
//
// It is the only thing standing between a bearer token and every mailbox on
// the server, and almost all of its behaviour is negative: what it refuses. A
// round trip that succeeds proves the happy path and nothing about the
// refusals, so most of what follows is the refusals.
//
// The store is the real in-memory one rather than a double: it is a production
// implementation that the conformance suite already holds to the same contract
// as Postgres, and token expiry is enforced there rather than here — a fact
// worth exercising rather than assuming.

const (
	accountID = "ACCT0123456789ABCDEFGHJKMN"
	deviceID  = "DEV0123456789ABCDEFGHJKMNP"
)

type device struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

// registered puts a device in the store with a real Ed25519 identity key.
func registered(t *testing.T, s *memory.Store) device {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	// A device belongs to an account; the store refuses an orphan.
	err = s.CreateAccount(context.Background(), &model.Account{ID: accountID, CreatedAt: time.Now()})
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	err = s.UpsertDevice(context.Background(), &model.Device{
		AccountID:   accountID,
		DeviceID:    deviceID,
		Name:        "Test iPhone",
		IdentityKey: pub,
		CreatedAt:   time.Now(),
	})
	if err != nil {
		t.Fatalf("upsert device: %v", err)
	}
	return device{pub: pub, priv: priv}
}

// signChallenge is what an honest client does: sign the challenge under the
// auth context prefix.
func signChallenge(d device, chal []byte) []byte {
	return ed25519.Sign(d.priv, append([]byte("tildra-auth-challenge-v1:"), chal...))
}

// ---------------------------------------------------------------------------
// Registration proof
// ---------------------------------------------------------------------------

func TestRegistrationProofAcceptsAFreshSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	msg := []byte("tildra-account-create-v1:" + now.UTC().Format(time.RFC3339))

	if err := auth.VerifyRegistrationProof(pub, ed25519.Sign(priv, msg), now, now); err != nil {
		t.Fatalf("a fresh proof should verify: %v", err)
	}
}

func TestRegistrationProofRefusesAnotherKeysSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	msg := []byte("tildra-account-create-v1:" + now.UTC().Format(time.RFC3339))

	err := auth.VerifyRegistrationProof(pub, ed25519.Sign(otherPriv, msg), now, now)
	if err != auth.ErrBadSignature {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

func TestRegistrationProofRefusesAStaleOrFutureTimestamp(t *testing.T) {
	// Both directions: a captured proof must not be usable next week, and a
	// phone whose clock runs fast must not be able to mint one for later.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()

	for _, drift := range []time.Duration{-10 * time.Minute, 10 * time.Minute} {
		ts := now.Add(drift)
		msg := []byte("tildra-account-create-v1:" + ts.UTC().Format(time.RFC3339))
		err := auth.VerifyRegistrationProof(pub, ed25519.Sign(priv, msg), ts, now)
		if err != auth.ErrProofStale {
			t.Fatalf("drift %v: want ErrProofStale, got %v", drift, err)
		}
	}
}

func TestRegistrationProofRefusesAKeyOfTheWrongLength(t *testing.T) {
	// Checked before the signature, so a short key is named rather than
	// arriving as a panic out of ed25519.Verify.
	now := time.Now()
	err := auth.VerifyRegistrationProof(make([]byte, 16), make([]byte, 64), now, now)
	if err != auth.ErrBadIdentityKey {
		t.Fatalf("want ErrBadIdentityKey, got %v", err)
	}
}

func TestRegistrationProofRefusesASignatureWithoutTheContextPrefix(t *testing.T) {
	// Domain separation. Without the prefix, a signature this key made for any
	// other purpose over the same bytes would register an account.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	bare := []byte(now.UTC().Format(time.RFC3339))

	err := auth.VerifyRegistrationProof(pub, ed25519.Sign(priv, bare), now, now)
	if err != auth.ErrBadSignature {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Challenge and token
// ---------------------------------------------------------------------------

func TestChallengeRoundTripMintsAToken(t *testing.T) {
	s := memory.New()
	d := registered(t, s)
	a := auth.New(s)
	ctx := context.Background()

	chal := a.IssueChallenge(accountID, deviceID)
	token, expires, err := a.RedeemChallenge(ctx, accountID, deviceID, chal, signChallenge(d, chal))
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if token == "" {
		t.Fatal("no token")
	}
	if !expires.After(time.Now().Add(29 * 24 * time.Hour)) {
		t.Fatalf("token expires too soon: %v", expires)
	}

	p, err := a.Authenticate(ctx, token)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if p.AccountID != accountID || p.DeviceID != deviceID {
		t.Fatalf("wrong principal: %+v", p)
	}
}

func TestOnlyTheHashOfTheTokenIsStored(t *testing.T) {
	// The package's own claim: a database leak must not hand an attacker live
	// sessions. The token is looked up by its SHA-256 and the raw value is
	// never written down, so lookup by the raw bytes finds nothing.
	s := memory.New()
	d := registered(t, s)
	a := auth.New(s)
	ctx := context.Background()

	chal := a.IssueChallenge(accountID, deviceID)
	token, _, err := a.RedeemChallenge(ctx, accountID, deviceID, chal, signChallenge(d, chal))
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}

	if _, _, err := s.LookupAuthToken(ctx, []byte(token)); err == nil {
		t.Fatal("the raw token resolved: it is being stored in the clear")
	}
	sum := sha256.Sum256([]byte(token))
	if _, _, err := s.LookupAuthToken(ctx, sum[:]); err != nil {
		t.Fatalf("the hash should resolve: %v", err)
	}
}

func TestAChallengeIsSpentEvenWhenTheSignatureIsWrong(t *testing.T) {
	// A failed attempt does not get a second guess at the same nonce. This is
	// the difference between one shot at forging a signature and unlimited
	// shots against a challenge that stays valid for two minutes.
	s := memory.New()
	d := registered(t, s)
	a := auth.New(s)
	ctx := context.Background()

	chal := a.IssueChallenge(accountID, deviceID)
	if _, _, err := a.RedeemChallenge(ctx, accountID, deviceID, chal, make([]byte, 64)); err != auth.ErrBadSignature {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}

	// Now the right signature, on the same challenge.
	_, _, err := a.RedeemChallenge(ctx, accountID, deviceID, chal, signChallenge(d, chal))
	if err != auth.ErrBadChallenge {
		t.Fatalf("the challenge should have been consumed; got %v", err)
	}
}

func TestAChallengeCannotBeRedeemedTwice(t *testing.T) {
	s := memory.New()
	d := registered(t, s)
	a := auth.New(s)
	ctx := context.Background()

	chal := a.IssueChallenge(accountID, deviceID)
	sig := signChallenge(d, chal)
	if _, _, err := a.RedeemChallenge(ctx, accountID, deviceID, chal, sig); err != nil {
		t.Fatalf("first redeem: %v", err)
	}
	if _, _, err := a.RedeemChallenge(ctx, accountID, deviceID, chal, sig); err != auth.ErrBadChallenge {
		t.Fatalf("replay should fail with ErrBadChallenge, got %v", err)
	}
}

func TestAChallengeIsBoundToTheDeviceItWasIssuedFor(t *testing.T) {
	// Otherwise one device's challenge is a token for another.
	s := memory.New()
	d := registered(t, s)
	a := auth.New(s)
	ctx := context.Background()

	chal := a.IssueChallenge(accountID, deviceID)
	sig := signChallenge(d, chal)

	if _, _, err := a.RedeemChallenge(ctx, accountID, "DEVSOMEONEELSE0000000000AA", chal, sig); err != auth.ErrBadChallenge {
		t.Fatalf("wrong device: want ErrBadChallenge, got %v", err)
	}
	if _, _, err := a.RedeemChallenge(ctx, "ACCTSOMEONEELSE00000000AAA", deviceID, chal, sig); err != auth.ErrBadChallenge {
		t.Fatalf("wrong account: want ErrBadChallenge, got %v", err)
	}
}

func TestAnUnknownChallengeIsRefused(t *testing.T) {
	s := memory.New()
	d := registered(t, s)
	a := auth.New(s)

	forged := make([]byte, 32)
	if _, err := rand.Read(forged); err != nil {
		t.Fatal(err)
	}
	_, _, err := a.RedeemChallenge(context.Background(), accountID, deviceID, forged, signChallenge(d, forged))
	if err != auth.ErrBadChallenge {
		t.Fatalf("want ErrBadChallenge, got %v", err)
	}
}

func TestAChallengeSignatureNeedsTheAuthContext(t *testing.T) {
	// Domain separation again, in the direction that matters most: a signature
	// over the bare challenge bytes must not authenticate. Any signature Tildra
	// asks a key to make carries a distinct prefix precisely so that one
	// protocol's signature is never valid in another.
	s := memory.New()
	d := registered(t, s)
	a := auth.New(s)

	chal := a.IssueChallenge(accountID, deviceID)
	bare := ed25519.Sign(d.priv, chal)

	_, _, err := a.RedeemChallenge(context.Background(), accountID, deviceID, chal, bare)
	if err != auth.ErrBadSignature {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

func TestEveryChallengeIsDistinct(t *testing.T) {
	// A repeated nonce would make a captured signature replayable.
	a := auth.New(memory.New())
	seen := map[string]bool{}
	for i := 0; i < 256; i++ {
		key := base64.StdEncoding.EncodeToString(a.IssueChallenge(accountID, deviceID))
		if seen[key] {
			t.Fatal("a challenge repeated")
		}
		seen[key] = true
	}
}

func TestAnUnknownTokenDoesNotAuthenticate(t *testing.T) {
	a := auth.New(memory.New())
	if _, err := a.Authenticate(context.Background(), "not-a-token"); err != auth.ErrUnauthorized {
		t.Fatalf("want ErrUnauthorized, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

func TestBearerTokenParsing(t *testing.T) {
	cases := []struct {
		header string
		want   string
		ok     bool
	}{
		{"Bearer abc", "abc", true},
		{"bearer abc", "abc", true}, // case-insensitive scheme
		{"BEARER abc", "abc", true},
		{"Bearer ", "", false}, // empty token is not a token
		{"Bearer", "", false},
		{"Basic abc", "", false},
		{"", "", false},
		{"abc", "", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if c.header != "" {
			r.Header.Set("Authorization", c.header)
		}
		got, ok := auth.BearerToken(r)
		if ok != c.ok || got != c.want {
			t.Fatalf("header %q: got (%q,%v) want (%q,%v)", c.header, got, ok, c.want, c.ok)
		}
	}
}

func TestMiddlewarePassesThePrincipalThroughAndRefusesTheRest(t *testing.T) {
	s := memory.New()
	d := registered(t, s)
	a := auth.New(s)
	ctx := context.Background()

	chal := a.IssueChallenge(accountID, deviceID)
	token, _, err := a.RedeemChallenge(ctx, accountID, deviceID, chal, signChallenge(d, chal))
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}

	var seen auth.Principal
	var reached bool
	handler := a.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		reached = true
		seen, _ = auth.FromContext(r.Context())
	}))

	for _, c := range []struct {
		name   string
		header string
		status int
	}{
		{"no header", "", http.StatusUnauthorized},
		{"wrong scheme", "Basic " + token, http.StatusUnauthorized},
		{"unknown token", "Bearer nonsense", http.StatusUnauthorized},
	} {
		reached = false
		r := httptest.NewRequest(http.MethodGet, "/v1/keys/count", nil)
		if c.header != "" {
			r.Header.Set("Authorization", c.header)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != c.status {
			t.Fatalf("%s: got %d want %d", c.name, w.Code, c.status)
		}
		if reached {
			t.Fatalf("%s: the handler ran anyway", c.name)
		}
		// A 401 that does not say how to authenticate is a 401 a client cannot
		// act on.
		if w.Header().Get("WWW-Authenticate") == "" {
			t.Fatalf("%s: no WWW-Authenticate header", c.name)
		}
	}

	reached = false
	r := httptest.NewRequest(http.MethodGet, "/v1/keys/count", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if !reached {
		t.Fatalf("a valid token was refused: %d", w.Code)
	}
	if seen.AccountID != accountID || seen.DeviceID != deviceID {
		t.Fatalf("wrong principal reached the handler: %+v", seen)
	}
}

func TestFromContextIsEmptyWithoutTheMiddleware(t *testing.T) {
	// A handler mounted outside the middleware by mistake must not read as
	// authenticated-as-nobody.
	if _, ok := auth.FromContext(context.Background()); ok {
		t.Fatal("an unauthenticated context reported a principal")
	}
}
