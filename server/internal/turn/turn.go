// Package turn issues short-lived credentials for a TURN relay.
//
// A call that cannot find a direct path between two devices needs a relay, and
// a relay that anyone can use is an open bandwidth donation. The standard
// answer is coturn's `use-auth-secret` mode: the TURN server and this server
// share a secret, and this server hands clients a username/password pair the
// TURN server can verify without ever being told about accounts.
//
// Two properties matter here and neither is incidental.
//
// **The credential says nothing about who asked for it.** The REST convention
// puts an arbitrary name after the expiry timestamp, and every deployment
// guide fills it with a user id. Doing that would put an account identifier in
// the TURN server's logs for every call — a log that says which account
// relayed media, when, and for how long, sitting next to a messenger whose
// whole design is that the server cannot see that. So the name is random per
// issuance. The TURN server only checks the MAC; it has no use for the name.
//
// **The credential expires.** It is a bearer token for bandwidth. A leaked
// one is bounded by the TTL and nothing else, so the TTL is short enough to
// matter and long enough to outlive a call that started just before it was
// fetched.
package turn

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // see the note below
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SHA-1 appears exactly once in this codebase, here. It is not hashing
// anything an attacker gets to choose a collision for — it is the MAC that
// coturn's REST convention specifies, and HMAC-SHA1 is still sound. Everywhere
// else SHA-1 is refused on sight, so the exception is written down rather than
// left to be discovered.

// ErrNotConfigured is returned when the deployment has no TURN relay. Calls
// still work when both devices can reach each other directly; what is lost is
// the relay-only path, and the client is told rather than left to discover it
// as a call that never connects.
var ErrNotConfigured = errors.New("turn: no relay is configured")

// DefaultTTL is how long an issued credential stays valid.
//
// Two hours: long enough that a credential fetched at the start of a long call
// does not expire mid-conversation (TURN checks it at allocation time, but a
// re-allocation after a network change would fail), short enough that a leaked
// one is not a standing grant.
const DefaultTTL = 2 * time.Hour

// Config is what a deployment provides.
type Config struct {
	// Secret is shared with the TURN server (coturn's `static-auth-secret`).
	Secret string
	// URLs are the relay addresses handed to clients, e.g.
	// "turn:turn.example:3478?transport=udp" or "turns:turn.example:5349".
	URLs []string
	TTL  time.Duration
}

// Credential is one issuance.
type Credential struct {
	URLs      []string `json:"urls"`
	Username  string   `json:"username"`
	Password  string   `json:"credential"`
	ExpiresAt int64    `json:"expiresAt"`
}

// Configured reports whether a relay is available at all.
func (c Config) Configured() bool {
	return c.Secret != "" && len(c.URLs) > 0
}

// Issue mints a credential valid until now+TTL.
func (c Config) Issue(now time.Time) (Credential, error) {
	if !c.Configured() {
		return Credential{}, ErrNotConfigured
	}
	ttl := c.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}

	// 8 random bytes rather than an account id. Enough that two issuances do
	// not collide in a TURN log; carries nothing about who asked.
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Credential{}, fmt.Errorf("turn: %w", err)
	}

	expiry := now.Add(ttl).Unix()
	username := fmt.Sprintf("%d:%s", expiry, hex.EncodeToString(nonce[:]))

	mac := hmac.New(sha1.New, []byte(c.Secret))
	mac.Write([]byte(username))

	return Credential{
		URLs:      c.URLs,
		Username:  username,
		Password:  base64.StdEncoding.EncodeToString(mac.Sum(nil)),
		ExpiresAt: expiry,
	}, nil
}

// Verify recomputes a credential the way a TURN server would.
//
// The server never calls this — coturn does the checking. It exists so the
// tests can assert that what is issued is what the relay will accept, rather
// than only that the code agrees with itself.
func (c Config) Verify(username, password string, now time.Time) bool {
	parts := strings.SplitN(username, ":", 2)
	if len(parts) != 2 {
		return false
	}
	expiry, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false
	}
	if now.Unix() > expiry {
		return false
	}

	mac := hmac.New(sha1.New, []byte(c.Secret))
	mac.Write([]byte(username))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(password))
}

// ParseURLs splits and trims the comma-separated form used in the environment.
func ParseURLs(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
