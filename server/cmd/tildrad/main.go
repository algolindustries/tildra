// Command tildrad is the Tildra server.
//
// It terminates client connections, hands out public key bundles, and moves
// sealed envelopes between mailboxes. It holds no key material capable of
// reading a message, by construction — see docs/PROTOCOL.md.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tildra/tildra/server/internal/api"
	"github.com/tildra/tildra/server/internal/auth"
	"github.com/tildra/tildra/server/internal/config"
	"github.com/tildra/tildra/server/internal/gateway"
	"github.com/tildra/tildra/server/internal/model"
	"github.com/tildra/tildra/server/internal/push"
	"github.com/tildra/tildra/server/internal/store"
	"github.com/tildra/tildra/server/internal/store/memory"
	"github.com/tildra/tildra/server/internal/store/postgres"
	"github.com/tildra/tildra/server/internal/transparency"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load()
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var st store.Store
	if cfg.DatabaseURL == "" {
		log.Warn("TILDRA_DATABASE_URL is unset — using the in-memory store. " +
			"Accounts and messages will be lost on restart. Do not run this in production.")
		st = memory.New()
	} else {
		openCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		pg, err := postgres.Open(openCtx, cfg.DatabaseURL)
		cancel()
		if err != nil {
			log.Error("postgres", "err", err)
			os.Exit(1)
		}
		log.Info("connected to postgres, migrations applied")
		st = pg
	}
	defer st.Close()

	authn := auth.New(st)
	hub := gateway.NewHub(st, log)

	var notifier push.Notifier = push.Nop{}
	switch cfg.PushProvider {
	case "expo":
		notifier = push.NewExpo(log)
		log.Info("push notifications enabled", "provider", "expo")
	case "", "none":
		log.Info("push notifications disabled; devices receive on reconnect")
	default:
		log.Error("unknown TILDRA_PUSH_PROVIDER", "value", cfg.PushProvider)
		os.Exit(1)
	}

	tlog, err := openTransparencyLog(ctx, cfg, st, log)
	if err != nil {
		log.Error("transparency log", "err", err)
		os.Exit(1)
	}

	srv := api.New(cfg, st, authn, hub, notifier, tlog, log)

	httpSrv := &http.Server{
		Addr:    cfg.Addr,
		Handler: srv.Handler(),
		// No WriteTimeout: it would guillotine long-lived WebSockets. The
		// gateway enforces its own per-write deadline instead.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go sweepLoop(ctx, st, cfg, log)

	go func() {
		log.Info("tildrad listening", "addr", cfg.Addr, "envelopeTTL", cfg.EnvelopeTTL)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("listen", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Error("shutdown", "err", err)
	}
}

// openTransparencyLog loads the key transparency log, if one is configured.
//
// The signing key lives in the environment rather than the database: a log
// whose key sits next to its contents can be rewritten wholesale by whoever
// takes the database, which defeats the point.
func openTransparencyLog(
	ctx context.Context,
	cfg *config.Config,
	st store.Store,
	log *slog.Logger,
) (*transparency.Log, error) {
	if cfg.TransparencyKey == "" {
		log.Warn("TILDRA_TRANSPARENCY_KEY is unset — running without a key transparency log. " +
			"Handle lookups will carry no proof, and key substitution is detectable only by " +
			"comparing safety numbers.")
		return nil, nil
	}

	seed, err := base64.StdEncoding.DecodeString(cfg.TransparencyKey)
	if err != nil {
		return nil, fmt.Errorf("TILDRA_TRANSPARENCY_KEY is not base64: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("TILDRA_TRANSPARENCY_KEY must decode to %d bytes", ed25519.SeedSize)
	}

	tlog := transparency.NewLog(&logStorage{st}, ed25519.NewKeyFromSeed(seed))
	if err := tlog.Load(ctx); err != nil {
		return nil, fmt.Errorf("load log: %w", err)
	}
	log.Info("key transparency log loaded",
		"entries", tlog.Size(),
		"logKey", base64.StdEncoding.EncodeToString(tlog.PublicKey()))
	return tlog, nil
}

// logStorage adapts the Store to what the log needs.
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

// sweepLoop destroys expired envelopes, mailboxes and tokens on a timer. This
// is the mechanism behind the retention promise in the README — without it,
// "deleted after delivery" is only true for messages that were delivered.
func sweepLoop(ctx context.Context, st store.Store, cfg *config.Config, log *slog.Logger) {
	t := time.NewTicker(cfg.SweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, err := st.Sweep(context.Background(), time.Now(), cfg.EnvelopeTTL)
			if err != nil {
				log.Error("sweep", "err", err)
				continue
			}
			if n > 0 {
				log.Info("swept expired envelopes", "count", n)
			}
		}
	}
}
