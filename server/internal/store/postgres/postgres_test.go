package postgres_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tildra/tildra/server/internal/store"
	"github.com/tildra/tildra/server/internal/store/postgres"
	"github.com/tildra/tildra/server/internal/store/storetest"
)

// TestConformance runs the same suite as the in-memory store.
//
// Skips without TILDRA_TEST_DATABASE_URL so `go test ./...` works on a machine
// with no database. CI always sets it — a conformance suite that silently
// skips in the one environment that matters is not a conformance suite.
func TestConformance(t *testing.T) {
	url := os.Getenv("TILDRA_TEST_DATABASE_URL")
	if url == "" {
		// Skipping locally is a convenience. Skipping in CI would mean the two
		// store implementations are free to drift in the one environment
		// that is supposed to catch it, so there it is a failure.
		if os.Getenv("CI") != "" {
			t.Fatal("TILDRA_TEST_DATABASE_URL must be set in CI: the Postgres conformance suite must not silently skip")
		}
		t.Skip("set TILDRA_TEST_DATABASE_URL to run the Postgres conformance suite")
	}
	t.Logf("running the conformance suite against %s", redact(url))

	counter := 0
	storetest.Run(t, func(t *testing.T) store.Store {
		// Each test gets its own schema rather than a shared truncated one, so
		// a leak between tests shows up as a failure instead of as a mystery.
		counter++
		schema := fmt.Sprintf("tildra_test_%d_%d", time.Now().UnixNano(), counter)
		s := openWithSchema(t, url, schema)
		return s
	})
}

func openWithSchema(t *testing.T, url, schema string) store.Store {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		admin.Close()
		t.Fatalf("create schema: %v", err)
	}
	admin.Close()

	scoped := url
	if containsQuery(url) {
		scoped += "&search_path=" + schema
	} else {
		scoped += "?search_path=" + schema
	}

	s, err := postgres.Open(ctx, scoped)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	t.Cleanup(func() {
		_ = s.Close()
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		admin, err := pgxpool.New(cleanupCtx, url)
		if err != nil {
			return
		}
		defer admin.Close()
		_, _ = admin.Exec(cleanupCtx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
	})

	return s
}

// redact strips the password before a connection string reaches a test log,
// which CI stores and displays publicly.
func redact(url string) string {
	at := strings.LastIndex(url, "@")
	scheme := strings.Index(url, "://")
	if at < 0 || scheme < 0 || at < scheme {
		return url
	}
	return url[:scheme+3] + "***" + url[at:]
}

func containsQuery(url string) bool {
	for i := 0; i < len(url); i++ {
		if url[i] == '?' {
			return true
		}
	}
	return false
}
