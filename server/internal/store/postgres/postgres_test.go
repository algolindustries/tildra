package postgres_test

import (
	"context"
	"fmt"
	"os"
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
		t.Skip("set TILDRA_TEST_DATABASE_URL to run the Postgres conformance suite")
	}

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

func containsQuery(url string) bool {
	for i := 0; i < len(url); i++ {
		if url[i] == '?' {
			return true
		}
	}
	return false
}
