// Package config loads server configuration from the environment.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/tildra/tildra/server/internal/turn"
)

type Config struct {
	Addr string

	// DatabaseURL selects the backend. Empty means the in-memory store, which
	// is fine for development and a terrible idea in production — the server
	// logs a warning at startup when it happens.
	DatabaseURL string

	// EnvelopeTTL is the hard ceiling on how long an undelivered message may
	// sit on the server. Delivered messages are destroyed immediately on ack.
	EnvelopeTTL time.Duration

	// MaxEnvelopeBytes bounds a single message. Large media goes through the
	// (separately encrypted) attachment store, not the message queue.
	MaxEnvelopeBytes int64

	// MaxAttachmentBytes bounds a single encrypted blob. Large enough for a
	// phone photo or a short video, small enough that one upload cannot fill
	// the disk.
	MaxAttachmentBytes int64

	// AttachmentTTL is how long a blob is held. Shorter than the envelope TTL:
	// an attachment nobody fetched in a week is one nobody is going to.
	AttachmentTTL time.Duration

	// PushProvider selects how devices are woken: "expo", or "none" (the
	// default). A server without push still works — clients receive on
	// reconnect — so this is a deployment choice, not a required one.
	PushProvider string

	// TransparencyKey is the base64 Ed25519 seed the log signs tree heads with.
	// Empty disables the log; handle lookups then carry no proof.
	TransparencyKey string

	// ProvisioningTTL bounds a device-linking window. Short on purpose: it only
	// has to last as long as pointing one phone at another and comparing six
	// digits, and a long window is a long time for a stale code to be usable.
	ProvisioningTTL time.Duration

	// TURNSecret is shared with a coturn relay running in `use-auth-secret`
	// mode. Empty means no relay: calls then work only when the two devices
	// can reach each other directly.
	TURNSecret string

	// TURNURLs are the relay addresses handed to clients, comma-separated in
	// the environment.
	TURNURLs []string

	// TURNTTL bounds an issued relay credential. It is a bearer token for
	// bandwidth, so it expires.
	TURNTTL time.Duration

	SweepInterval time.Duration
}

func Load() (*Config, error) {
	c := &Config{
		Addr:               env("TILDRA_ADDR", ":8080"),
		DatabaseURL:        os.Getenv("TILDRA_DATABASE_URL"),
		EnvelopeTTL:        30 * 24 * time.Hour,
		MaxEnvelopeBytes:   256 << 10, // 256 KiB
		MaxAttachmentBytes: 32 << 20,  // 32 MiB
		AttachmentTTL:      7 * 24 * time.Hour,
		PushProvider:       env("TILDRA_PUSH_PROVIDER", "none"),
		TransparencyKey:    os.Getenv("TILDRA_TRANSPARENCY_KEY"),
		ProvisioningTTL:    5 * time.Minute,
		TURNSecret:         os.Getenv("TILDRA_TURN_SECRET"),
		TURNURLs:           turn.ParseURLs(os.Getenv("TILDRA_TURN_URLS")),
		TURNTTL:            turn.DefaultTTL,
		SweepInterval:      10 * time.Minute,
	}
	if v := os.Getenv("TILDRA_ENVELOPE_TTL"); v != "" {
		d, err := positiveDuration("TILDRA_ENVELOPE_TTL", v)
		if err != nil {
			return nil, err
		}
		c.EnvelopeTTL = d
	}
	if v := os.Getenv("TILDRA_MAX_ENVELOPE_BYTES"); v != "" {
		n, err := positiveBytes("TILDRA_MAX_ENVELOPE_BYTES", v)
		if err != nil {
			return nil, err
		}
		c.MaxEnvelopeBytes = n
	}
	if v := os.Getenv("TILDRA_MAX_ATTACHMENT_BYTES"); v != "" {
		n, err := positiveBytes("TILDRA_MAX_ATTACHMENT_BYTES", v)
		if err != nil {
			return nil, err
		}
		c.MaxAttachmentBytes = n
	}
	if v := os.Getenv("TILDRA_ATTACHMENT_TTL"); v != "" {
		d, err := positiveDuration("TILDRA_ATTACHMENT_TTL", v)
		if err != nil {
			return nil, err
		}
		c.AttachmentTTL = d
	}
	if v := os.Getenv("TILDRA_TURN_TTL"); v != "" {
		d, err := positiveDuration("TILDRA_TURN_TTL", v)
		if err != nil {
			return nil, err
		}
		c.TURNTTL = d
	}
	// Half a configuration is worse than none: a secret with no URLs, or URLs
	// with no secret, would silently behave as "no relay" and the operator
	// would find out when a call failed to connect for one user in ten.
	if (c.TURNSecret == "") != (len(c.TURNURLs) == 0) {
		return nil, fmt.Errorf("TILDRA_TURN_SECRET and TILDRA_TURN_URLS must be set together")
	}
	return c, nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// positiveDuration parses a duration and refuses one that is not positive.
//
// Every bound in this package is enforced by comparing against it, so zero
// does not mean "no limit" — it means the opposite, silently. A zero envelope
// TTL puts the sweep's cutoff at `now` and destroys every undelivered message
// on the next pass ten minutes later; a zero attachment TTL stores blobs that
// have already expired; a zero relay TTL issues credentials that are dead on
// arrival. Refusing at startup is the argument the TURN pairing already makes:
// the operator should find this out from the server, not from a user.
func positiveDuration(key, v string) (time.Duration, error) {
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive, got %q", key, v)
	}
	return d, nil
}

// positiveBytes is the same argument for the size limits: a maximum of zero
// rejects every message as too large rather than allowing any size.
func positiveBytes(key, v string) (int64, error) {
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	if n <= 0 {
		return 0, fmt.Errorf("%s must be positive, got %q", key, v)
	}
	return n, nil
}
