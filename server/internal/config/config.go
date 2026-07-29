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

	SweepInterval time.Duration
}

func Load() (*Config, error) {
	c := &Config{
		Addr:             env("TILDRA_ADDR", ":8080"),
		DatabaseURL:      os.Getenv("TILDRA_DATABASE_URL"),
		EnvelopeTTL:      30 * 24 * time.Hour,
		MaxEnvelopeBytes: 256 << 10, // 256 KiB
		SweepInterval:    10 * time.Minute,
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
	return c, nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
