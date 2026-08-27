package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/algolindustries/tildra/server/internal/config"
)

// Configuration loading, which had no tests.
//
// The interesting part is not that a variable is read — it is what `Load`
// refuses. This file already carries the principle in the TURN check: half a
// configuration is worse than none, because the operator finds out when a call
// fails to connect for one user in ten. The same argument applies to every
// bound the server enforces, and those were not checked at all.

// clean removes every TILDRA_ variable this package reads, so a developer's
// shell cannot decide what the defaults look like.
func clean(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"TILDRA_ADDR",
		"TILDRA_DATABASE_URL",
		"TILDRA_ENVELOPE_TTL",
		"TILDRA_MAX_ENVELOPE_BYTES",
		"TILDRA_MAX_ATTACHMENT_BYTES",
		"TILDRA_ATTACHMENT_TTL",
		"TILDRA_PUSH_PROVIDER",
		"TILDRA_TRANSPARENCY_KEY",
		"TILDRA_TURN_SECRET",
		"TILDRA_TURN_URLS",
		"TILDRA_TURN_TTL",
	} {
		t.Setenv(k, "")
	}
}

func load(t *testing.T) *config.Config {
	t.Helper()
	c, err := config.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return c
}

func TestDefaults(t *testing.T) {
	clean(t)
	c := load(t)

	if c.Addr != ":8080" {
		t.Errorf("Addr = %q", c.Addr)
	}
	if c.DatabaseURL != "" {
		t.Errorf("DatabaseURL = %q; empty means the in-memory store", c.DatabaseURL)
	}
	if c.PushProvider != "none" {
		t.Errorf("PushProvider = %q; a server without push still works", c.PushProvider)
	}
	if c.EnvelopeTTL != 30*24*time.Hour {
		t.Errorf("EnvelopeTTL = %v", c.EnvelopeTTL)
	}
	if c.AttachmentTTL != 7*24*time.Hour {
		t.Errorf("AttachmentTTL = %v", c.AttachmentTTL)
	}
	if c.AttachmentTTL >= c.EnvelopeTTL {
		t.Errorf("the attachment TTL should be the shorter of the two: %v vs %v",
			c.AttachmentTTL, c.EnvelopeTTL)
	}
	if c.MaxEnvelopeBytes != 256<<10 {
		t.Errorf("MaxEnvelopeBytes = %d", c.MaxEnvelopeBytes)
	}
	if c.MaxAttachmentBytes != 32<<20 {
		t.Errorf("MaxAttachmentBytes = %d", c.MaxAttachmentBytes)
	}
	if c.MaxEnvelopeBytes >= c.MaxAttachmentBytes {
		t.Errorf("large media is supposed to go through the attachment store: %d vs %d",
			c.MaxEnvelopeBytes, c.MaxAttachmentBytes)
	}
	if len(c.TURNURLs) != 0 || c.TURNSecret != "" {
		t.Errorf("no relay by default, got %q %v", c.TURNSecret, c.TURNURLs)
	}
}

func TestEachVariableIsRead(t *testing.T) {
	clean(t)
	t.Setenv("TILDRA_ADDR", "127.0.0.1:9999")
	t.Setenv("TILDRA_DATABASE_URL", "postgres://localhost/tildra")
	t.Setenv("TILDRA_ENVELOPE_TTL", "48h")
	t.Setenv("TILDRA_MAX_ENVELOPE_BYTES", "1024")
	t.Setenv("TILDRA_MAX_ATTACHMENT_BYTES", "2048")
	t.Setenv("TILDRA_ATTACHMENT_TTL", "1h")
	t.Setenv("TILDRA_PUSH_PROVIDER", "expo")
	t.Setenv("TILDRA_TRANSPARENCY_KEY", "seed")
	t.Setenv("TILDRA_TURN_TTL", "30m")

	c := load(t)

	if c.Addr != "127.0.0.1:9999" ||
		c.DatabaseURL != "postgres://localhost/tildra" ||
		c.EnvelopeTTL != 48*time.Hour ||
		c.MaxEnvelopeBytes != 1024 ||
		c.MaxAttachmentBytes != 2048 ||
		c.AttachmentTTL != time.Hour ||
		c.PushProvider != "expo" ||
		c.TransparencyKey != "seed" ||
		c.TURNTTL != 30*time.Minute {
		t.Fatalf("a variable did not reach the config: %+v", c)
	}
}

func TestAMalformedValueIsNamed(t *testing.T) {
	// An operator staring at a startup failure needs to know which line of
	// their unit file is wrong.
	for _, c := range []struct{ key, value string }{
		{"TILDRA_ENVELOPE_TTL", "soon"},
		{"TILDRA_MAX_ENVELOPE_BYTES", "lots"},
		{"TILDRA_MAX_ATTACHMENT_BYTES", "32MB"},
		{"TILDRA_ATTACHMENT_TTL", "a week"},
		{"TILDRA_TURN_TTL", "600"},
	} {
		t.Run(c.key, func(t *testing.T) {
			clean(t)
			t.Setenv(c.key, c.value)
			_, err := config.Load()
			if err == nil {
				t.Fatalf("%s=%q was accepted", c.key, c.value)
			}
			if !strings.Contains(err.Error(), c.key) {
				t.Fatalf("the error does not name the variable: %v", err)
			}
		})
	}
}

func TestABoundOfZeroOrLessIsRefused(t *testing.T) {
	// Every one of these parses. Every one of them turns the server into one
	// that quietly destroys or refuses mail:
	//
	//   - an envelope TTL of zero makes the sweep's cutoff `now`, so every
	//     undelivered message is destroyed on the next pass, ten minutes later;
	//   - a maximum envelope size of zero rejects every message as too large;
	//   - an attachment TTL of zero stores blobs that have already expired;
	//   - a relay credential TTL of zero issues credentials that are dead on
	//     arrival.
	//
	// This file already argues the case in the TURN check: half a
	// configuration is worse than none, because the operator finds out from a
	// user rather than from the server.
	for _, c := range []struct{ key, value string }{
		{"TILDRA_ENVELOPE_TTL", "0s"},
		{"TILDRA_ENVELOPE_TTL", "-1h"},
		{"TILDRA_MAX_ENVELOPE_BYTES", "0"},
		{"TILDRA_MAX_ENVELOPE_BYTES", "-1"},
		{"TILDRA_MAX_ATTACHMENT_BYTES", "0"},
		{"TILDRA_MAX_ATTACHMENT_BYTES", "-4096"},
		{"TILDRA_ATTACHMENT_TTL", "0s"},
		{"TILDRA_ATTACHMENT_TTL", "-1m"},
		{"TILDRA_TURN_TTL", "0s"},
		{"TILDRA_TURN_TTL", "-5m"},
	} {
		t.Run(c.key+"="+c.value, func(t *testing.T) {
			clean(t)
			t.Setenv(c.key, c.value)
			_, err := config.Load()
			if err == nil {
				t.Fatalf("%s=%q was accepted", c.key, c.value)
			}
			if !strings.Contains(err.Error(), c.key) {
				t.Fatalf("the error does not name the variable: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The relay, which is the one pairing the file already refuses to half-do
// ---------------------------------------------------------------------------

func TestRelayMustBeConfiguredWholeOrNotAtAll(t *testing.T) {
	t.Run("secret without urls", func(t *testing.T) {
		clean(t)
		t.Setenv("TILDRA_TURN_SECRET", "s3cret")
		if _, err := config.Load(); err == nil {
			t.Fatal("a secret with no URLs was accepted")
		}
	})

	t.Run("urls without secret", func(t *testing.T) {
		clean(t)
		t.Setenv("TILDRA_TURN_URLS", "turn:relay.example:3478")
		if _, err := config.Load(); err == nil {
			t.Fatal("URLs with no secret were accepted")
		}
	})

	t.Run("both", func(t *testing.T) {
		clean(t)
		t.Setenv("TILDRA_TURN_SECRET", "s3cret")
		t.Setenv("TILDRA_TURN_URLS", "turn:relay.example:3478")
		c := load(t)
		if c.TURNSecret != "s3cret" || len(c.TURNURLs) != 1 {
			t.Fatalf("got %q %v", c.TURNSecret, c.TURNURLs)
		}
	})

	t.Run("neither", func(t *testing.T) {
		clean(t)
		load(t) // no relay is a supported deployment
	})
}

func TestRelayURLsAreSplitAndTrimmed(t *testing.T) {
	clean(t)
	t.Setenv("TILDRA_TURN_SECRET", "s3cret")
	t.Setenv("TILDRA_TURN_URLS", " turn:a.example:3478 , turns:b.example:5349 ,, ")

	c := load(t)

	want := []string{"turn:a.example:3478", "turns:b.example:5349"}
	if len(c.TURNURLs) != len(want) {
		t.Fatalf("got %v want %v", c.TURNURLs, want)
	}
	for i := range want {
		if c.TURNURLs[i] != want[i] {
			t.Fatalf("got %v want %v", c.TURNURLs, want)
		}
	}
}

func TestAListOfSeparatorsIsNotAConfiguredRelay(t *testing.T) {
	// " , , " parses to nothing. Treating that as "URLs are set" would pair a
	// secret with an empty list and pass the check that exists to prevent
	// exactly that.
	clean(t)
	t.Setenv("TILDRA_TURN_SECRET", "s3cret")
	t.Setenv("TILDRA_TURN_URLS", " , , ")

	if _, err := config.Load(); err == nil {
		t.Fatal("a secret paired with an empty URL list was accepted")
	}
}
