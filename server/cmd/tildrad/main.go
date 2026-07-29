// Command tildrad is the Tildra server.
//
// It terminates client connections, hands out public key bundles, and moves
// sealed envelopes between mailboxes. It holds no key material capable of
// reading a message, by construction — see docs/PROTOCOL.md.
package main

import (
	"context"
	"errors"
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
	"github.com/tildra/tildra/server/internal/store"
	"github.com/tildra/tildra/server/internal/store/memory"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load()
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}

	var st store.Store
	if cfg.DatabaseURL == "" {
		log.Warn("TILDRA_DATABASE_URL is unset — using the in-memory store. " +
			"Accounts and messages will be lost on restart. Do not run this in production.")
		st = memory.New()
	} else {
		log.Error("postgres store is not wired up yet; set TILDRA_DATABASE_URL='' to use memory")
		os.Exit(1)
	}
	defer st.Close()

	authn := auth.New(st)
	hub := gateway.NewHub(st, log)
	srv := api.New(cfg, st, authn, hub, log)

	httpSrv := &http.Server{
		Addr:    cfg.Addr,
		Handler: srv.Handler(),
		// No WriteTimeout: it would guillotine long-lived WebSockets. The
		// gateway enforces its own per-write deadline instead.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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
