// Command tildra-auditor watches a Tildra key transparency log.
//
// Run it against any Tildra server. It reads the whole log, checks that every
// tree head is consistent with every head it saw before, and re-derives the
// root from the entries the server actually served. Anything that does not add
// up is printed and the process exits non-zero.
//
//	tildra-auditor -server https://api.tildra.chat -state ./auditor.json
//	tildra-auditor -server https://api.tildra.chat -watch 5m
//
// Publishing the checkpoint file is the point of running one. An auditor that
// keeps its view to itself proves only that the log it personally saw was
// internally consistent; two auditors comparing published checkpoints is what
// establishes they were shown the same log.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tildra/tildra/server/internal/auditor"
)

func main() {
	server := flag.String("server", "", "base URL of the Tildra server to audit (required)")
	statePath := flag.String("state", "auditor.json", "where to read and write the checkpoint")
	watch := flag.Duration("watch", 0, "keep auditing on this interval instead of exiting")
	compare := flag.String("compare", "", "path to another auditor's published checkpoint to cross-check")
	flag.Parse()

	if *server == "" {
		fmt.Fprintln(os.Stderr, "tildra-auditor: -server is required")
		flag.Usage()
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	source := auditor.NewHTTPSource(*server)
	a := auditor.New(source)

	if saved, err := readCheckpoint(*statePath); err == nil {
		// Resume re-reads and re-verifies the whole log rather than trusting
		// the file, so a tampered state file cannot make the auditor attest to
		// something it never checked.
		if err := a.Resume(ctx, saved); err != nil {
			fmt.Fprintf(os.Stderr, "tildra-auditor: could not resume from %s: %v\n", *statePath, err)
			os.Exit(1)
		}
		fmt.Printf("resumed at %s\n", saved)
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "tildra-auditor: reading %s: %v\n", *statePath, err)
		os.Exit(1)
	}

	if *compare != "" {
		other, err := readCheckpoint(*compare)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tildra-auditor: reading %s: %v\n", *compare, err)
			os.Exit(1)
		}
		if err := auditor.CompareCheckpoints(ctx, a.Checkpoint(), other, source.Consistency); err != nil {
			fmt.Fprintf(os.Stderr, "\nSPLIT VIEW: %v\n", err)
			fmt.Fprintf(os.Stderr, "  mine:   %s\n  theirs: %s\n", a.Checkpoint(), other)
			os.Exit(1)
		}
		fmt.Printf("checkpoints agree: %s\n", other)
	}

	failed := runOnce(ctx, a, *statePath)
	if *watch == 0 {
		if failed {
			os.Exit(1)
		}
		return
	}

	ticker := time.NewTicker(*watch)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// A watching auditor keeps going after a finding rather than
			// exiting: the operator needs to know whether the problem persists,
			// and a process that dies on first sight of trouble stops watching
			// exactly when watching matters.
			runOnce(ctx, a, *statePath)
		}
	}
}

// runOnce audits and reports. Returns true if anything critical was found.
func runOnce(ctx context.Context, a *auditor.Auditor, statePath string) bool {
	findings, err := a.Audit(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit failed: %v\n", err)
		return true
	}

	criticalCount := 0
	for _, f := range findings {
		prefix := "note"
		if f.Critical {
			prefix = "CRITICAL"
			criticalCount++
		}
		fmt.Printf("%s [%s] %s\n", prefix, f.Kind, f.Detail)
	}

	checkpoint := a.Checkpoint()
	if criticalCount == 0 {
		if err := writeCheckpoint(statePath, checkpoint); err != nil {
			fmt.Fprintf(os.Stderr, "could not write %s: %v\n", statePath, err)
			return true
		}
		fmt.Printf("ok  %s  checked at %s\n",
			checkpoint, checkpoint.CheckedAt.Format(time.RFC3339))
		return false
	}

	// The checkpoint is deliberately not advanced past a critical finding.
	// Recording a head the auditor does not believe would make the next run
	// compare against a lie.
	fmt.Fprintf(os.Stderr,
		"\n%d critical finding(s); checkpoint left at %s\n", criticalCount, checkpoint)
	return true
}

func readCheckpoint(path string) (auditor.Checkpoint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return auditor.Checkpoint{}, err
	}
	return auditor.UnmarshalCheckpoint(data)
}

func writeCheckpoint(path string, c auditor.Checkpoint) error {
	data, err := auditor.MarshalCheckpoint(c)
	if err != nil {
		return err
	}
	// Written via a temporary file: a checkpoint truncated by a crash is a
	// checkpoint that cannot be resumed from, and this file is the auditor's
	// entire memory.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
