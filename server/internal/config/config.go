// Package config loads server configuration from the environment.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
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
		SweepInterval:      10 * time.Minute,
	}
	if v := os.Getenv("TILDRA_ENVELOPE_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("TILDRA_ENVELOPE_TTL: %w", err)
		}
		c.EnvelopeTTL = d
	}
	if v := os.Getenv("TILDRA_MAX_ENVELOPE_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("TILDRA_MAX_ENVELOPE_BYTES: %w", err)
		}
		c.MaxEnvelopeBytes = n
	}
	if v := os.Getenv("TILDRA_MAX_ATTACHMENT_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("TILDRA_MAX_ATTACHMENT_BYTES: %w", err)
		}
		c.MaxAttachmentBytes = n
	}
	if v := os.Getenv("TILDRA_ATTACHMENT_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("TILDRA_ATTACHMENT_TTL: %w", err)
		}
		c.AttachmentTTL = d
	}
	return c, nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
