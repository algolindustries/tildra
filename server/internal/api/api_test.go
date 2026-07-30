package api_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tildra/tildra/server/internal/api"
	"github.com/tildra/tildra/server/internal/auth"
	"github.com/tildra/tildra/server/internal/config"
	"github.com/tildra/tildra/server/internal/gateway"
	"github.com/tildra/tildra/server/internal/model"
	"github.com/tildra/tildra/server/internal/push"
	"github.com/tildra/tildra/server/internal/store"
	"github.com/tildra/tildra/server/internal/store/memory"
	"github.com/tildra/tildra/server/internal/transparency"
	"github.com/tildra/tildra/server/internal/turn"
)

type harness struct {
	t        *testing.T
	srv      *httptest.Server
	store    *memory.Store
	client   *http.Client
	notifier *push.Recording
	tlog     *transparency.Log
}

// logStorage adapts the Store to the transparency log, mirroring cmd/tildrad.
type logStorage struct{ st store.Store }

func (l *logStorage) AppendEntry(ctx context.Context, e *transparency.Entry) error {
	m := &model.LogEntry{
		Handle: e.Handle, AccountID: e.AccountID,
		IdentityKey: e.IdentityKey, RecordedAt: e.RecordedAt,
	}
	if err := l.st.AppendLogEntry(ctx, m); err != nil {
		return err
	}
	e.Index = m.Index
	return nil
}

func (l *logStorage) Entries(ctx context.Context, from, to int64) ([]*transparency.Entry, error) {
	rows, err := l.st.LogEntries(ctx, from, to)
	if err != nil {
		return nil, err
	}
	out := make([]*transparency.Entry, 0, len(rows))
	for _, r := range rows {
		out = append(out, &transparency.Entry{
			Index: r.Index, Handle: r.Handle, AccountID: r.AccountID,
			IdentityKey: r.IdentityKey, RecordedAt: r.RecordedAt,
		})
	}
	return out, nil
}

func (l *logStorage) Size(ctx context.Context) (int64, error) { return l.st.LogSize(ctx) }

func (l *logStorage) LatestForHandle(ctx context.Context, handle string) (*transparency.Entry, error) {
	r, err := l.st.LatestLogEntryForHandle(ctx, handle)
	if err != nil {
		return nil, err
	}
	return &transparency.Entry{
		Index: r.Index, Handle: r.Handle, AccountID: r.AccountID,
		IdentityKey: r.IdentityKey, RecordedAt: r.RecordedAt,
	}, nil
}

// handleProof is the proof shape returned alongside a handle lookup.
type handleProof struct {
	AccountID string `json:"accountId"`
	Handle    string `json:"handle"`
	Proof     *struct {
		Entry       transparency.Entry          `json:"entry"`
		Inclusion   [][]byte                    `json:"inclusion"`
		Consistency [][]byte                    `json:"consistency"`
		Head        transparency.SignedTreeHead `json:"head"`
	} `json:"proof"`
}

func newHarness(t *testing.T) *harness {
	return newHarnessWith(t, nil)
}

// newHarnessWith lets a test change the deployment configuration — TURN, for
// instance, which is off by default exactly as it is for a fresh server.
func newHarnessWith(t *testing.T, configure func(*config.Config)) *harness {
	t.Helper()
	st := memory.New()
	cfg := &config.Config{MaxEnvelopeBytes: 256 << 10, EnvelopeTTL: time.Hour}
	if configure != nil {
		configure(cfg)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	authn := auth.New(st)
	hub := gateway.NewHub(st, log)
	notifier := &push.Recording{}
	_, signKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("log key: %v", err)
	}
	tlog := transparency.NewLog(&logStorage{st}, signKey)
	s := api.New(cfg, st, authn, hub, notifier, tlog, log)

	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return &harness{t: t, srv: srv, store: st, client: srv.Client(), notifier: notifier, tlog: tlog}
}

func (h *harness) do(method, path, token string, body any) (*http.Response, []byte) {
	h.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			h.t.Fatalf("marshal body: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, h.srv.URL+path, rdr)
	if err != nil {
		h.t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, data
}

// account is a fully registered, authenticated test device.
type account struct {
	pub       ed25519.PublicKey
	priv      ed25519.PrivateKey
	accountID string
	deviceID  string
	token     string
}

// register walks the real client flow: prove key possession, create the
// account, redeem a challenge for a token.
func (h *harness) register(name string) *account {
	h.t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		h.t.Fatalf("keygen: %v", err)
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	proof := ed25519.Sign(priv, []byte("tildra-account-create-v1:"+ts))

	resp, body := h.do(http.MethodPost, "/v1/accounts", "", map[string]any{
		"identityKey": pub,
		"deviceName":  name,
		"proofTs":     ts,
		"proof":       proof,
	})
	if resp.StatusCode != http.StatusCreated {
		h.t.Fatalf("register: status %d body %s", resp.StatusCode, body)
	}
	var created struct {
		AccountID string `json:"accountId"`
		DeviceID  string `json:"deviceId"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		h.t.Fatalf("decode register response: %v", err)
	}

	a := &account{pub: pub, priv: priv, accountID: created.AccountID, deviceID: created.DeviceID}
	a.token = h.login(a)
	return a
}

func (h *harness) login(a *account) string {
	h.t.Helper()
	resp, body := h.do(http.MethodGet,
		"/v1/auth/challenge?account="+a.accountID+"&device="+a.deviceID, "", nil)
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("challenge: status %d body %s", resp.StatusCode, body)
	}
	var ch struct {
		Challenge []byte `json:"challenge"`
	}
	if err := json.Unmarshal(body, &ch); err != nil {
		h.t.Fatalf("decode challenge: %v", err)
	}

	sig := ed25519.Sign(a.priv, append([]byte("tildra-auth-challenge-v1:"), ch.Challenge...))
	resp, body = h.do(http.MethodPost, "/v1/auth/token", "", map[string]any{
		"accountId": a.accountID,
		"deviceId":  a.deviceID,
		"challenge": ch.Challenge,
		"signature": sig,
	})
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("token: status %d body %s", resp.StatusCode, body)
	}
	var tok struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		h.t.Fatalf("decode token: %v", err)
	}
	if tok.Token == "" {
		h.t.Fatal("token: empty")
	}
	return tok.Token
}

// keyUpload builds a plausible bundle. The prekey values are random bytes —
// the server only checks that they carry a valid identity-key signature, which
// is exactly the property under test.
func keyUpload(a *account, oneTimeCount int) model.KeyUpload {
	randKey := func() []byte {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			panic(err)
		}
		return b
	}
	signed := func(id uint32) model.PreKey {
		pk := randKey()
		return model.PreKey{ID: id, PublicKey: pk, Signature: ed25519.Sign(a.priv, pk)}
	}
	up := model.KeyUpload{
		IdentityKey:  a.pub,
		SignedPreKey: signed(1),
		SignedPQKey:  signed(2),
	}
	for i := range oneTimeCount {
		up.OneTimeKeys = append(up.OneTimeKeys, model.PreKey{ID: uint32(100 + i), PublicKey: randKey()})
		up.OneTimePQ = append(up.OneTimePQ, model.PreKey{ID: uint32(200 + i), PublicKey: randKey()})
	}
	return up
}

func TestRegisterAndAuthenticate(t *testing.T) {
	h := newHarness(t)
	a := h.register("Test Phone")

	if a.accountID == "" || a.deviceID == "" {
		t.Fatal("expected non-empty account and device IDs")
	}
	// The token must actually work on an authenticated route.
	resp, body := h.do(http.MethodGet, "/v1/keys/count", a.token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("keys/count with valid token: status %d body %s", resp.StatusCode, body)
	}
}

func TestRegistrationRejectsBadProof(t *testing.T) {
	h := newHarness(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	ts := time.Now().UTC().Format(time.RFC3339)

	// Signed by a key that is not the one being registered.
	proof := ed25519.Sign(otherPriv, []byte("tildra-account-create-v1:"+ts))
	resp, _ := h.do(http.MethodPost, "/v1/accounts", "", map[string]any{
		"identityKey": pub, "deviceName": "Impostor", "proofTs": ts, "proof": proof,
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for mismatched proof, got %d", resp.StatusCode)
	}
}

func TestRegistrationRejectsStaleProof(t *testing.T) {
	h := newHarness(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ts := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	proof := ed25519.Sign(priv, []byte("tildra-account-create-v1:"+ts))

	resp, _ := h.do(http.MethodPost, "/v1/accounts", "", map[string]any{
		"identityKey": pub, "deviceName": "Replay", "proofTs": ts, "proof": proof,
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for stale proof, got %d", resp.StatusCode)
	}
}

func TestChallengeIsSingleUse(t *testing.T) {
	h := newHarness(t)
	a := h.register("Once")

	_, body := h.do(http.MethodGet, "/v1/auth/challenge?account="+a.accountID+"&device="+a.deviceID, "", nil)
	var ch struct {
		Challenge []byte `json:"challenge"`
	}
	if err := json.Unmarshal(body, &ch); err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	sig := ed25519.Sign(a.priv, append([]byte("tildra-auth-challenge-v1:"), ch.Challenge...))
	req := map[string]any{
		"accountId": a.accountID, "deviceId": a.deviceID,
		"challenge": ch.Challenge, "signature": sig,
	}
	if resp, _ := h.do(http.MethodPost, "/v1/auth/token", "", req); resp.StatusCode != http.StatusOK {
		t.Fatalf("first redemption should succeed, got %d", resp.StatusCode)
	}
	// Replaying a captured (challenge, signature) pair must not mint a second
	// token — this is the whole point of consuming the challenge.
	if resp, _ := h.do(http.MethodPost, "/v1/auth/token", "", req); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed challenge should be rejected, got %d", resp.StatusCode)
	}
}

func TestUnauthenticatedRoutesAreRejected(t *testing.T) {
	h := newHarness(t)
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/v1/keys/count"},
		{http.MethodPost, "/v1/messages"},
		{http.MethodGet, "/v1/backup"},
		{http.MethodPost, "/v1/mailboxes"},
	} {
		resp, _ := h.do(tc.method, tc.path, "", nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s: expected 401, got %d", tc.method, tc.path, resp.StatusCode)
		}
	}
}

func TestKeyUploadAndBundleFetch(t *testing.T) {
	h := newHarness(t)
	bob := h.register("Bob Phone")
	alice := h.register("Alice Phone")

	up := keyUpload(bob, 3)
	if resp, body := h.do(http.MethodPut, "/v1/keys", bob.token, up); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("put keys: status %d body %s", resp.StatusCode, body)
	}

	resp, body := h.do(http.MethodGet, "/v1/keys/"+bob.accountID+"/"+bob.deviceID, alice.token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get bundle: status %d body %s", resp.StatusCode, body)
	}
	var bundle model.PreKeyBundle
	if err := json.Unmarshal(body, &bundle); err != nil {
		t.Fatalf("decode bundle: %v", err)
	}
	if !bytes.Equal(bundle.IdentityKey, bob.pub) {
		t.Error("bundle identity key does not match the registered key")
	}
	if bundle.OneTimeKey == nil || bundle.OneTimePQKey == nil {
		t.Fatal("expected one-time keys in the bundle")
	}
	// Both signed prekeys must verify under the identity key, or the client
	// would reject the bundle.
	if !ed25519.Verify(bundle.IdentityKey, bundle.SignedPreKey.PublicKey, bundle.SignedPreKey.Signature) {
		t.Error("signed prekey signature does not verify")
	}
	if !ed25519.Verify(bundle.IdentityKey, bundle.SignedPQKey.PublicKey, bundle.SignedPQKey.Signature) {
		t.Error("signed PQ prekey signature does not verify")
	}
}

func TestOneTimePreKeysAreConsumedExactlyOnce(t *testing.T) {
	h := newHarness(t)
	bob := h.register("Bob")
	alice := h.register("Alice")

	const count = 3
	h.do(http.MethodPut, "/v1/keys", bob.token, keyUpload(bob, count))

	seen := map[uint32]bool{}
	for i := range count {
		_, body := h.do(http.MethodGet, "/v1/keys/"+bob.accountID+"/"+bob.deviceID, alice.token, nil)
		var b model.PreKeyBundle
		if err := json.Unmarshal(body, &b); err != nil {
			t.Fatalf("decode bundle %d: %v", i, err)
		}
		if b.OneTimeKey == nil {
			t.Fatalf("bundle %d: expected a one-time key", i)
		}
		if seen[b.OneTimeKey.ID] {
			t.Fatalf("one-time prekey %d handed out twice", b.OneTimeKey.ID)
		}
		seen[b.OneTimeKey.ID] = true
	}

	// Exhausted: the bundle must still be served, degrading to the signed
	// prekey rather than failing the handshake outright.
	_, body := h.do(http.MethodGet, "/v1/keys/"+bob.accountID+"/"+bob.deviceID, alice.token, nil)
	var b model.PreKeyBundle
	if err := json.Unmarshal(body, &b); err != nil {
		t.Fatalf("decode exhausted bundle: %v", err)
	}
	if b.OneTimeKey != nil {
		t.Error("expected no one-time key once the pool is exhausted")
	}
	if len(b.SignedPreKey.PublicKey) == 0 {
		t.Error("exhausted bundle must still carry the signed prekey")
	}
}

func TestKeyUploadRejectsForgedSignature(t *testing.T) {
	h := newHarness(t)
	a := h.register("Forger")
	up := keyUpload(a, 1)
	up.SignedPreKey.Signature[0] ^= 0xff

	if resp, _ := h.do(http.MethodPut, "/v1/keys", a.token, up); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for a bad prekey signature, got %d", resp.StatusCode)
	}
}

func TestKeyUploadRejectsIdentityKeySwap(t *testing.T) {
	h := newHarness(t)
	a := h.register("Swapper")

	// An attacker with a stolen bearer token tries to replace the device's
	// identity key with one they control. Allowing this would let them
	// impersonate the device to every future contact.
	evilPub, evilPriv, _ := ed25519.GenerateKey(rand.Reader)
	evil := &account{pub: evilPub, priv: evilPriv}
	up := keyUpload(evil, 1)

	resp, _ := h.do(http.MethodPut, "/v1/keys", a.token, up)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 for an identity key swap, got %d", resp.StatusCode)
	}
}

func TestSealedSenderRoundTrip(t *testing.T) {
	h := newHarness(t)
	bob := h.register("Bob")
	alice := h.register("Alice")

	const mailbox = "mb_0123456789abcdef0123456789abcdef"
	if resp, body := h.do(http.MethodPost, "/v1/mailboxes", bob.token, map[string]any{
		"mailboxes": []string{mailbox}, "ttlHours": 48,
	}); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("register mailbox: status %d body %s", resp.StatusCode, body)
	}

	ciphertext := []byte("this would be a sealed-sender envelope")
	resp, body := h.do(http.MethodPost, "/v1/messages", alice.token, map[string]any{
		"mailbox": mailbox, "ciphertext": ciphertext,
	})
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("send: status %d body %s", resp.StatusCode, body)
	}

	queued, err := h.store.Dequeue(context.Background(), mailbox, 10)
	if err != nil {
		t.Fatalf("dequeue: %v", err)
	}
	if len(queued) != 1 {
		t.Fatalf("expected 1 queued envelope, got %d", len(queued))
	}
	if !bytes.Equal(queued[0].Ciphertext, ciphertext) {
		t.Error("ciphertext was altered in transit")
	}

	// After acking, the envelope must be gone — "deleted on delivery" is a
	// claim the README makes, so it gets a test.
	if err := h.store.Ack(context.Background(), mailbox, []string{queued[0].ID}); err != nil {
		t.Fatalf("ack: %v", err)
	}
	remaining, _ := h.store.Dequeue(context.Background(), mailbox, 10)
	if len(remaining) != 0 {
		t.Fatalf("expected the queue to be empty after ack, got %d", len(remaining))
	}
}

func TestSendToUnknownMailboxIsRejected(t *testing.T) {
	h := newHarness(t)
	alice := h.register("Alice")
	resp, _ := h.do(http.MethodPost, "/v1/messages", alice.token, map[string]any{
		"mailbox": "mb_nonexistent_0000000000000000", "ciphertext": []byte("hi"),
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for an unknown mailbox, got %d", resp.StatusCode)
	}
}

func TestMailboxCannotBeHijacked(t *testing.T) {
	h := newHarness(t)
	bob := h.register("Bob")
	mallory := h.register("Mallory")

	const mailbox = "mb_0123456789abcdef0123456789abcdef"
	h.do(http.MethodPost, "/v1/mailboxes", bob.token, map[string]any{"mailboxes": []string{mailbox}})

	// Claiming someone else's mailbox would redirect their mail.
	resp, _ := h.do(http.MethodPost, "/v1/mailboxes", mallory.token, map[string]any{"mailboxes": []string{mailbox}})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 when claiming another account's mailbox, got %d", resp.StatusCode)
	}
}

func TestOversizedEnvelopeIsRejected(t *testing.T) {
	h := newHarness(t)
	alice := h.register("Alice")
	bob := h.register("Bob")
	const mailbox = "mb_0123456789abcdef0123456789abcdef"
	h.do(http.MethodPost, "/v1/mailboxes", bob.token, map[string]any{"mailboxes": []string{mailbox}})

	resp, _ := h.do(http.MethodPost, "/v1/messages", alice.token, map[string]any{
		"mailbox": mailbox, "ciphertext": make([]byte, (256<<10)+1),
	})
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for an oversized envelope, got %d", resp.StatusCode)
	}
}

func TestHandleClaimAndResolve(t *testing.T) {
	h := newHarness(t)
	a := h.register("Ayse")
	b := h.register("Baris")

	if resp, body := h.do(http.MethodPut, "/v1/handle", a.token, map[string]any{"handle": "ayse"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("claim handle: status %d body %s", resp.StatusCode, body)
	}
	resp, body := h.do(http.MethodGet, "/v1/handles/ayse", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resolve handle: status %d body %s", resp.StatusCode, body)
	}
	var got struct {
		AccountID string `json:"accountId"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.AccountID != a.accountID {
		t.Errorf("handle resolved to %q, want %q", got.AccountID, a.accountID)
	}

	if resp, _ := h.do(http.MethodPut, "/v1/handle", b.token, map[string]any{"handle": "AYSE"}); resp.StatusCode != http.StatusConflict {
		t.Errorf("expected 409 for a taken handle (case-insensitively), got %d", resp.StatusCode)
	}
	if resp, _ := h.do(http.MethodPut, "/v1/handle", b.token, map[string]any{"handle": "no spaces"}); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for an invalid handle, got %d", resp.StatusCode)
	}
}

func TestDeviceListOmitsLastSeen(t *testing.T) {
	h := newHarness(t)
	a := h.register("Watched")
	b := h.register("Watcher")

	_, body := h.do(http.MethodGet, "/v1/devices/"+a.accountID, b.token, nil)
	if bytes.Contains(body, []byte("lastSeen")) {
		t.Errorf("device list leaks lastSeen, which the threat model forbids: %s", body)
	}
}

func TestBackupIsOpaqueAndPrivate(t *testing.T) {
	h := newHarness(t)
	a := h.register("Owner")
	b := h.register("Snoop")

	blob := []byte("encrypted-under-the-recovery-phrase")
	if resp, _ := h.do(http.MethodPut, "/v1/backup", a.token, map[string]any{"blob": blob}); resp.StatusCode != http.StatusNoContent {
		t.Fatal("put backup failed")
	}

	resp, body := h.do(http.MethodGet, "/v1/backup", a.token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get backup: status %d", resp.StatusCode)
	}
	var got struct {
		Blob []byte `json:"blob"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode backup: %v", err)
	}
	if !bytes.Equal(got.Blob, blob) {
		t.Error("backup blob was not returned verbatim")
	}

	// Another account must not see it. Backups are keyed by principal, and
	// there is no route that takes an account ID.
	resp, _ = h.do(http.MethodGet, "/v1/backup", b.token, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected another account to see no backup, got %d", resp.StatusCode)
	}
}

func TestLogoutRevokesToken(t *testing.T) {
	h := newHarness(t)
	a := h.register("Leaver")

	if resp, _ := h.do(http.MethodPost, "/v1/auth/logout", a.token, nil); resp.StatusCode != http.StatusNoContent {
		t.Fatal("logout failed")
	}
	if resp, _ := h.do(http.MethodGet, "/v1/keys/count", a.token, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Error("revoked token still works")
	}
}

func TestPushTokenRegistration(t *testing.T) {
	h := newHarness(t)
	a := h.register("Phone")

	for _, tc := range []struct {
		name     string
		body     map[string]any
		wantCode int
	}{
		{"valid expo token", map[string]any{"platform": "expo", "token": "ExponentPushToken[abc]"}, http.StatusNoContent},
		{"unknown platform", map[string]any{"platform": "carrier-pigeon", "token": "x"}, http.StatusBadRequest},
		{"empty token", map[string]any{"platform": "expo", "token": ""}, http.StatusBadRequest},
		{"oversized token", map[string]any{"platform": "fcm", "token": strings.Repeat("x", 513)}, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := h.do(http.MethodPut, "/v1/push", a.token, tc.body)
			if resp.StatusCode != tc.wantCode {
				t.Fatalf("status %d body %s, want %d", resp.StatusCode, body, tc.wantCode)
			}
		})
	}

	stored, err := h.store.GetPushToken(context.Background(), a.accountID, a.deviceID)
	if err != nil {
		t.Fatalf("token was not stored: %v", err)
	}
	if stored.Token != "ExponentPushToken[abc]" {
		t.Errorf("stored token is %q", stored.Token)
	}

	if resp, _ := h.do(http.MethodDelete, "/v1/push", a.token, nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: status %d", resp.StatusCode)
	}
	if _, err := h.store.GetPushToken(context.Background(), a.accountID, a.deviceID); err == nil {
		t.Error("token survived deletion")
	}
}

func TestPushWakesAnOfflineDevice(t *testing.T) {
	h := newHarness(t)
	bob := h.register("Bob")
	alice := h.register("Alice")

	const mailbox = "mb_0123456789abcdef0123456789abcdef"
	h.do(http.MethodPost, "/v1/mailboxes", bob.token, map[string]any{"mailboxes": []string{mailbox}})
	h.do(http.MethodPut, "/v1/push", bob.token, map[string]any{
		"platform": "expo", "token": "ExponentPushToken[bob]",
	})

	// Bob has no socket open, so the envelope queues and a wake is sent.
	resp, _ := h.do(http.MethodPost, "/v1/messages", alice.token, map[string]any{
		"mailbox": mailbox, "ciphertext": []byte("sealed"),
	})
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("send: status %d", resp.StatusCode)
	}

	// The wake runs detached from the request, so give it a moment.
	deadline := time.Now().Add(3 * time.Second)
	var sent []model.PushToken
	for time.Now().Before(deadline) {
		if sent = h.notifier.Sent(); len(sent) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if len(sent) != 1 {
		t.Fatalf("sent %d notifications, want 1", len(sent))
	}
	if sent[0].Token != "ExponentPushToken[bob]" {
		t.Errorf("woke the wrong device: %q", sent[0].Token)
	}
	// The notifier is handed a token and nothing about the message. If this
	// ever carried a sender or a preview, Apple and Google would learn who is
	// talking to whom.
	if sent[0].AccountID != bob.accountID {
		t.Errorf("token belongs to %q, want Bob", sent[0].AccountID)
	}
}

func TestNoPushWithoutARegisteredToken(t *testing.T) {
	h := newHarness(t)
	bob := h.register("Bob")
	alice := h.register("Alice")

	const mailbox = "mb_0123456789abcdef0123456789abcdef"
	h.do(http.MethodPost, "/v1/mailboxes", bob.token, map[string]any{"mailboxes": []string{mailbox}})

	h.do(http.MethodPost, "/v1/messages", alice.token, map[string]any{
		"mailbox": mailbox, "ciphertext": []byte("sealed"),
	})
	time.Sleep(300 * time.Millisecond)

	if sent := h.notifier.Sent(); len(sent) != 0 {
		t.Errorf("sent %d notifications for a device with no token", len(sent))
	}
}

func TestHandleLookupCarriesAVerifiableProof(t *testing.T) {
	h := newHarness(t)
	a := h.register("Ayse")

	if resp, body := h.do(http.MethodPut, "/v1/handle", a.token, map[string]any{"handle": "ayse"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("claim handle: %d %s", resp.StatusCode, body)
	}

	resp, body := h.do(http.MethodGet, "/v1/handles/ayse", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resolve: %d %s", resp.StatusCode, body)
	}
	var got handleProof
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Proof == nil {
		t.Fatal("no proof was returned")
	}

	// Everything a client checks, checked here: the tree head is signed by the
	// log key, and the entry is genuinely in the tree that head commits to.
	if err := got.Proof.Head.Verify(h.tlog.PublicKey()); err != nil {
		t.Fatalf("tree head signature: %v", err)
	}

	leaf := transparency.HashLeaf(got.Proof.Entry.Encode())
	err := transparency.VerifyInclusion(
		leaf, int(got.Proof.Entry.Index), int(got.Proof.Head.Size),
		got.Proof.Inclusion, got.Proof.Head.RootHash,
	)
	if err != nil {
		t.Fatalf("inclusion proof: %v", err)
	}

	// The binding must be the account's real identity key, not something else.
	if !bytes.Equal(got.Proof.Entry.IdentityKey, a.pub) {
		t.Error("the logged identity key is not the device's")
	}
	if got.Proof.Entry.AccountID != a.accountID {
		t.Error("the logged account is not the one that claimed the handle")
	}
}

func TestTreeHeadIsPublicAndSigned(t *testing.T) {
	h := newHarness(t)
	a := h.register("Ayse")
	h.do(http.MethodPut, "/v1/handle", a.token, map[string]any{"handle": "ayse"})

	// Unauthenticated: a log only anyone can watch is worth watching.
	resp, body := h.do(http.MethodGet, "/v1/transparency/head", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("head: %d %s", resp.StatusCode, body)
	}
	var head transparency.SignedTreeHead
	if err := json.Unmarshal(body, &head); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if head.Size < 1 {
		t.Fatalf("tree is empty after a handle was claimed")
	}
	if err := head.Verify(h.tlog.PublicKey()); err != nil {
		t.Fatalf("published head does not verify: %v", err)
	}

	// A forged head must not verify under the real key.
	forged := head
	forged.Size += 1
	if err := forged.Verify(h.tlog.PublicKey()); err == nil {
		t.Error("a head with an altered size verified")
	}
}

func TestLogGrowsConsistentlyAcrossClaims(t *testing.T) {
	h := newHarness(t)

	var sizes []int64
	var roots [][]byte
	for i := 0; i < 5; i++ {
		a := h.register(fmt.Sprintf("Device%d", i))
		h.do(http.MethodPut, "/v1/handle", a.token, map[string]any{
			"handle": fmt.Sprintf("user%d", i),
		})
		head := h.tlog.Head()
		sizes = append(sizes, head.Size)
		roots = append(roots, head.RootHash)
	}

	// Every earlier view of the log must remain a prefix of every later one.
	// This is the property that makes a silent key swap impossible.
	entries, err := h.store.LogEntries(context.Background(), 0, sizes[len(sizes)-1])
	if err != nil {
		t.Fatalf("entries: %v", err)
	}
	hashes := make([][]byte, 0, len(entries))
	for _, e := range entries {
		hashes = append(hashes, transparency.HashLeaf(transparency.Entry{
			Index: e.Index, Handle: e.Handle, AccountID: e.AccountID,
			IdentityKey: e.IdentityKey, RecordedAt: e.RecordedAt,
		}.Encode()))
	}

	for i := range sizes {
		for j := i; j < len(sizes); j++ {
			path, err := transparency.ConsistencyProof(hashes, int(sizes[i]), int(sizes[j]))
			if err != nil {
				t.Fatalf("proof %d->%d: %v", sizes[i], sizes[j], err)
			}
			if err := transparency.VerifyConsistency(
				int(sizes[i]), int(sizes[j]), path, roots[i], roots[j],
			); err != nil {
				t.Fatalf("consistency %d->%d: %v", sizes[i], sizes[j], err)
			}
		}
	}
}

func TestReclaimingTheSameHandleDoesNotGrowTheLog(t *testing.T) {
	// A log that grows on every no-op re-registration is one nobody can audit.
	h := newHarness(t)
	a := h.register("Ayse")

	h.do(http.MethodPut, "/v1/handle", a.token, map[string]any{"handle": "ayse"})
	first := h.tlog.Size()
	h.do(http.MethodPut, "/v1/handle", a.token, map[string]any{"handle": "ayse"})

	if h.tlog.Size() != first {
		t.Errorf("log grew from %d to %d on an unchanged re-registration", first, h.tlog.Size())
	}
}

func TestSweepDestroysExpiredEnvelopes(t *testing.T) {
	st := memory.New()
	ctx := context.Background()

	if err := st.CreateAccount(ctx, &model.Account{ID: "ACCT"}); err != nil {
		t.Fatalf("create account: %v", err)
	}
	if err := st.RegisterMailbox(ctx, &model.Mailbox{
		ID: "mb", AccountID: "ACCT", DeviceID: "DEV", ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("register mailbox: %v", err)
	}
	old := &model.Envelope{ID: "old", Mailbox: "mb", Ciphertext: []byte("stale"), ServerTS: time.Now().Add(-48 * time.Hour)}
	fresh := &model.Envelope{ID: "new", Mailbox: "mb", Ciphertext: []byte("recent"), ServerTS: time.Now()}
	for _, e := range []*model.Envelope{old, fresh} {
		if err := st.Enqueue(ctx, e); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}

	n, err := st.Sweep(ctx, time.Now(), 24*time.Hour)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n != 1 {
		t.Errorf("swept %d envelopes, want 1", n)
	}
	left, _ := st.Dequeue(ctx, "mb", 10)
	if len(left) != 1 || left[0].ID != "new" {
		t.Errorf("sweep kept the wrong envelopes: %+v", left)
	}
}

func TestStoreReportsMissingKeys(t *testing.T) {
	st := memory.New()
	_, err := st.TakeBundle(context.Background(), "nobody", "nodevice")
	if err == nil {
		t.Fatal("expected an error for a device with no published keys")
	}
	if err != store.ErrNoPreKeys {
		t.Errorf("got %v, want ErrNoPreKeys", err)
	}
}

// ---------------------------------------------------------------------------
// TURN
// ---------------------------------------------------------------------------

const turnSecret = "shared-with-coturn"

func turnHarness(t *testing.T) *harness {
	return newHarnessWith(t, func(c *config.Config) {
		c.TURNSecret = turnSecret
		c.TURNURLs = []string{"turn:turn.example:3478?transport=udp"}
		c.TURNTTL = time.Hour
	})
}

func TestTurnIssuesACredentialCoturnWouldAccept(t *testing.T) {
	h := turnHarness(t)
	a := h.register("Alice")

	resp, body := h.do(http.MethodGet, "/v1/turn", a.token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}

	var cred turn.Credential
	if err := json.Unmarshal(body, &cred); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(cred.URLs) != 1 || cred.URLs[0] != "turn:turn.example:3478?transport=udp" {
		t.Fatalf("urls = %v", cred.URLs)
	}

	// The check that matters: the relay, not this server, decides whether a
	// credential is good.
	cfg := turn.Config{Secret: turnSecret}
	if !cfg.Verify(cred.Username, cred.Password, time.Now()) {
		t.Fatal("the relay would reject the credential this server issued")
	}
	if cred.ExpiresAt <= time.Now().Unix() {
		t.Fatalf("ExpiresAt %d is not in the future", cred.ExpiresAt)
	}
}

func TestTurnCredentialCannotBeTracedToAnAccount(t *testing.T) {
	// The relay sees the username and nothing else. If it carried an account
	// id, the TURN log would say who relayed media and when — which is the one
	// thing this server is built not to know.
	h := turnHarness(t)
	alice := h.register("Alice")
	bob := h.register("Bob")

	names := map[string]bool{}
	for _, a := range []*account{alice, bob, alice, bob} {
		_, body := h.do(http.MethodGet, "/v1/turn", a.token, nil)
		var cred turn.Credential
		if err := json.Unmarshal(body, &cred); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if strings.Contains(cred.Username, a.accountID) || strings.Contains(cred.Username, a.deviceID) {
			t.Fatalf("username %q carries the account or device id", cred.Username)
		}
		name := strings.SplitN(cred.Username, ":", 2)[1]
		if names[name] {
			t.Fatalf("two issuances shared the name %q, which links them", name)
		}
		names[name] = true
	}
}

func TestTurnRefusesWithoutAToken(t *testing.T) {
	h := turnHarness(t)
	resp, _ := h.do(http.MethodGet, "/v1/turn", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestTurnSaysSoWhenNoRelayIsConfigured(t *testing.T) {
	// Silence here would be worse than an error: the client holds an incoming
	// call to relay-only candidates until it is answered, and it cannot keep
	// that promise with nowhere to relay through. It has to be told.
	h := newHarness(t)
	a := h.register("Alice")

	resp, body := h.do(http.MethodGet, "/v1/turn", a.token, nil)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d body %s, want 503", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "TURN") {
		t.Fatalf("body %s does not say what is missing", body)
	}
}

func TestTurnCredentialIsNotCached(t *testing.T) {
	h := turnHarness(t)
	a := h.register("Alice")
	resp, _ := h.do(http.MethodGet, "/v1/turn", a.token, nil)
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store on a bearer token", got)
	}
}

// ---------------------------------------------------------------------------
// Recovery blobs
// ---------------------------------------------------------------------------

const lookupID = "0123456789abcdef0123456789abcdef"

func TestRecoveryBlobIsReadableWithoutAuthenticating(t *testing.T) {
	// The caller is somebody who has lost the device that knew their account
	// id. There is nothing for them to authenticate with, which is the whole
	// reason this endpoint exists separately from /v1/backup.
	h := newHarness(t)
	a := h.register("Alice")

	blob := []byte("ciphertext the server cannot open")
	resp, body := h.do(http.MethodPut, "/v1/recovery/"+lookupID, a.token, map[string]any{"blob": blob})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("put: status %d body %s", resp.StatusCode, body)
	}

	resp, body = h.do(http.MethodGet, "/v1/recovery/"+lookupID, "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get: status %d body %s", resp.StatusCode, body)
	}
	var got struct {
		Blob []byte `json:"blob"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(got.Blob) != string(blob) {
		t.Fatalf("blob = %q, want %q", got.Blob, blob)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}
}

func TestRecoveryBlobCannotBeTakenOver(t *testing.T) {
	// Writing requires knowing the id, which requires the phrase — but if an
	// id ever leaks, the account that claimed it keeps it.
	h := newHarness(t)
	alice := h.register("Alice")
	bob := h.register("Bob")

	if resp, _ := h.do(http.MethodPut, "/v1/recovery/"+lookupID, alice.token,
		map[string]any{"blob": []byte("alice")}); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("alice put: %d", resp.StatusCode)
	}
	resp, _ := h.do(http.MethodPut, "/v1/recovery/"+lookupID, bob.token,
		map[string]any{"blob": []byte("bob")})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("bob put: status %d, want 409", resp.StatusCode)
	}

	_, body := h.do(http.MethodGet, "/v1/recovery/"+lookupID, "", nil)
	if !strings.Contains(string(body), "YWxpY2U=") { // base64("alice")
		t.Fatalf("a refused takeover changed the blob: %s", body)
	}
}

func TestRecoveryBlobRequiresAuthenticationToWrite(t *testing.T) {
	h := newHarness(t)
	resp, _ := h.do(http.MethodPut, "/v1/recovery/"+lookupID, "", map[string]any{"blob": []byte("x")})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestRecoveryBlobRejectsAMalformedLookupId(t *testing.T) {
	// The id is hex derived from a phrase. Anything else is either a mistake
	// or somebody probing, and neither should reach the store.
	h := newHarness(t)
	a := h.register("Alice")
	for _, bad := range []string{"short", strings.Repeat("f", 65), "ZZZZ0123456789abcdef0123456789ab", "../etc"} {
		resp, _ := h.do(http.MethodGet, "/v1/recovery/"+bad, "", nil)
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("GET %q returned 200", bad)
		}
		resp, _ = h.do(http.MethodPut, "/v1/recovery/"+bad, a.token, map[string]any{"blob": []byte("x")})
		if resp.StatusCode == http.StatusNoContent {
			t.Fatalf("PUT %q was accepted", bad)
		}
	}
}

func TestUnknownRecoveryBlobIsANotFound(t *testing.T) {
	h := newHarness(t)
	resp, _ := h.do(http.MethodGet, "/v1/recovery/"+strings.Repeat("a", 32), "", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestRecoveryBlobIsSizeBounded(t *testing.T) {
	// Readable without authenticating, so this is the one worth keeping cheap
	// to serve.
	h := newHarness(t)
	a := h.register("Alice")
	resp, _ := h.do(http.MethodPut, "/v1/recovery/"+lookupID, a.token,
		map[string]any{"blob": make([]byte, (256<<10)+1)})
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
}
