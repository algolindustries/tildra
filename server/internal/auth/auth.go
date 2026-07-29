// Package auth handles device authentication.
//
// There are no passwords. A device proves it holds the private half of its
// Ed25519 identity key by signing a server-issued challenge; in exchange it
// gets a bearer token. The server stores only SHA-256 of that token, so a
// database leak does not hand an attacker live sessions.
package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tildra/tildra/server/internal/id"
	"github.com/tildra/tildra/server/internal/store"
)

var (
	ErrUnauthorized   = errors.New("unauthorized")
	ErrBadChallenge   = errors.New("challenge unknown or expired")
	ErrBadSignature   = errors.New("signature verification failed")
	ErrProofStale     = errors.New("registration proof timestamp out of range")
	ErrBadIdentityKey = errors.New("identity key must be a 32-byte Ed25519 public key")
)

const (
	// ChallengeTTL is short on purpose: a challenge is used seconds after it
	// is issued, and a long window only helps an attacker who has captured one.
	ChallengeTTL = 2 * time.Minute
	// TokenTTL bounds the damage of a stolen token. Clients refresh silently.
	TokenTTL = 30 * 24 * time.Hour

	// registrationContext is the domain separator for the proof-of-possession
	// signature at account creation. Any signature Tildra asks a key to make
	// carries a distinct prefix, so one protocol's signature is never valid in
	// another.
	registrationContext = "tildra-account-create-v1:"
	challengeContext    = "tildra-auth-challenge-v1:"

	// proofSkew is how far a registration proof's timestamp may drift from
	// server time. Generous enough for a phone with a lazy clock, tight enough
	// that a captured proof is not reusable next week.
	proofSkew = 5 * time.Minute
)

type challenge struct {
	accountID string
	deviceID  string
	expires   time.Time
}

// Authenticator issues challenges and validates tokens.
type Authenticator struct {
	store store.Store

	mu         sync.Mutex
	challenges map[string]challenge // base64(challenge) -> metadata
}

func New(s store.Store) *Authenticator {
	a := &Authenticator{store: s, challenges: map[string]challenge{}}
	return a
}

// VerifyRegistrationProof checks that whoever is registering holds the private
// key for identityKey, and that they did so recently.
func VerifyRegistrationProof(identityKey, proof []byte, ts time.Time, now time.Time) error {
	if len(identityKey) != ed25519.PublicKeySize {
		return ErrBadIdentityKey
	}
	if d := now.Sub(ts); d > proofSkew || d < -proofSkew {
		return ErrProofStale
	}
	msg := []byte(registrationContext + ts.UTC().Format(time.RFC3339))
	if !ed25519.Verify(ed25519.PublicKey(identityKey), msg, proof) {
		return ErrBadSignature
	}
	return nil
}

// IssueChallenge returns a fresh random challenge bound to one device.
func (a *Authenticator) IssueChallenge(accountID, deviceID string) []byte {
	c := id.NewToken()
	key := base64.StdEncoding.EncodeToString(c)

	a.mu.Lock()
	a.challenges[key] = challenge{accountID, deviceID, time.Now().Add(ChallengeTTL)}
	// Opportunistic cleanup — the map is small and this avoids a goroutine.
	if len(a.challenges) > 4096 {
		now := time.Now()
		for k, v := range a.challenges {
			if now.After(v.expires) {
				delete(a.challenges, k)
			}
		}
	}
	a.mu.Unlock()
	return c
}

// RedeemChallenge verifies a signature over a previously issued challenge and,
// on success, mints a bearer token. The challenge is consumed either way — a
// failed attempt does not get a second guess at the same nonce.
func (a *Authenticator) RedeemChallenge(ctx context.Context, accountID, deviceID string, chal, sig []byte) (string, time.Time, error) {
	key := base64.StdEncoding.EncodeToString(chal)

	a.mu.Lock()
	c, ok := a.challenges[key]
	delete(a.challenges, key)
	a.mu.Unlock()

	if !ok || time.Now().After(c.expires) {
		return "", time.Time{}, ErrBadChallenge
	}
	if c.accountID != accountID || c.deviceID != deviceID {
		return "", time.Time{}, ErrBadChallenge
	}

	dev, err := a.store.GetDevice(ctx, accountID, deviceID)
	if err != nil {
		return "", time.Time{}, ErrUnauthorized
	}
	if len(dev.IdentityKey) != ed25519.PublicKeySize {
		return "", time.Time{}, ErrBadIdentityKey
	}

	msg := append([]byte(challengeContext), chal...)
	if !ed25519.Verify(ed25519.PublicKey(dev.IdentityKey), msg, sig) {
		return "", time.Time{}, ErrBadSignature
	}

	tokenBytes := id.NewToken()
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	sum := sha256.Sum256([]byte(token))
	expires := time.Now().Add(TokenTTL)
	if err := a.store.PutAuthToken(ctx, sum[:], accountID, deviceID, expires); err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}

// Principal is the authenticated caller attached to a request context.
type Principal struct {
	AccountID string
	DeviceID  string
}

type ctxKey struct{}

// FromContext returns the authenticated principal, if any.
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(Principal)
	return p, ok
}

// Authenticate resolves a bearer token to a principal.
func (a *Authenticator) Authenticate(ctx context.Context, token string) (Principal, error) {
	sum := sha256.Sum256([]byte(token))
	accountID, deviceID, err := a.store.LookupAuthToken(ctx, sum[:])
	if err != nil {
		return Principal{}, ErrUnauthorized
	}
	return Principal{AccountID: accountID, DeviceID: deviceID}, nil
}

// Middleware rejects unauthenticated requests.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := BearerToken(r)
		if !ok {
			unauthorized(w)
			return
		}
		p, err := a.Authenticate(r.Context(), token)
		if err != nil {
			unauthorized(w)
			return
		}
		_ = a.store.TouchDevice(r.Context(), p.AccountID, p.DeviceID, time.Now())
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, p)))
	})
}

// BearerToken extracts a token from the Authorization header.
func BearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	return h[len(prefix):], true
}

// ConstantTimeEqual compares two secrets without leaking length-prefix timing.
func ConstantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="tildra"`)
	http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
}
