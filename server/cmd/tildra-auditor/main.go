// Command tildra-auditor watches a Tildra key transparency log.
//
// Run it against any Tildra server. It reads the whole log, checks that every
// tree head is consistent with every head it saw before, and re-derives the
// root from the entries the server actually served. Anything that does not add
// up is printed and the process exits non-zero.
//
//	tildra-auditor -server https://api.tildra.chat -state ./auditor.json
//	tildra-auditor -server https://api.tildra.chat -watch 5m
//	tildra-auditor -server https://api.tildra.chat -key ./auditor.key -publish ./checkpoint.json
//
// Publishing the checkpoint file is the point of running one. An auditor that
// keeps its view to itself proves only that the log it personally saw was
// internally consistent; two auditors comparing published checkpoints is what
// establishes they were shown the same log.
//
// Sign what you publish. Two operators who know each other can exchange
// unsigned files and compare them, but the case that protects a *user* is a
// phone fetching a checkpoint over the network — and there, an unsigned
// document is worth nothing, because whoever serves it can write whatever
// makes the two views agree. Generate a key with -genkey, publish the public
// half once somewhere people already trust you, and clients pin it.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/algolindustries/tildra/server/internal/auditor"
)

func main() {
	server := flag.String("server", "", "base URL of the Tildra server to audit (required)")
	statePath := flag.String("state", "auditor.json", "where to read and write the checkpoint")
	watch := flag.Duration("watch", 0, "keep auditing on this interval instead of exiting")
	compare := flag.String("compare", "", "path to another auditor's published checkpoint to cross-check")
	keyPath := flag.String("key", "", "base64 Ed25519 seed to sign published checkpoints with")
	publish := flag.String("publish", "", "where to write the signed checkpoint for others to fetch")
	genkey := flag.Bool("genkey", false, "generate an auditor signing key, print it, and exit")
	flag.Parse()

	if *genkey {
		if err := generateKey(os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "tildra-auditor: %v\n", err)
			os.Exit(1)
		}
		return
	}

	var signingKey ed25519.PrivateKey
	if *keyPath != "" {
		var err error
		signingKey, err = readSigningKey(*keyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tildra-auditor: reading %s: %v\n", *keyPath, err)
			os.Exit(1)
		}
	}
	// Publishing an unsigned checkpoint is worse than not publishing: it looks
	// like an attestation and is not one. Refused rather than warned about.
	if *publish != "" && signingKey == nil {
		fmt.Fprintln(os.Stderr, "tildra-auditor: -publish needs -key; an unsigned checkpoint attests to nothing")
		os.Exit(2)
	}

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
		other, err := readPublishedCheckpoint(*compare)
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

	failed := runOnce(ctx, a, *statePath, *publish, signingKey)
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
			runOnce(ctx, a, *statePath, *publish, signingKey)
		}
	}
}

// runOnce audits and reports. Returns true if anything critical was found.
func runOnce(
	ctx context.Context,
	a *auditor.Auditor,
	statePath, publishPath string,
	signingKey ed25519.PrivateKey,
) bool {
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
		if publishPath != "" {
			if err := writeSignedCheckpoint(publishPath, signingKey, checkpoint); err != nil {
				fmt.Fprintf(os.Stderr, "could not write %s: %v\n", publishPath, err)
				return true
			}
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

// generateKey prints a fresh auditor identity. The public half is what
// operators publish and clients pin; the seed never leaves the machine.
func generateKey(out io.Writer) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "# Keep the seed secret. Publish the public key.\n")
	fmt.Fprintf(out, "seed:      %s\n", base64.StdEncoding.EncodeToString(priv.Seed()))
	fmt.Fprintf(out, "publicKey: %s\n", base64.StdEncoding.EncodeToString(pub))
	return nil
}

func readSigningKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("the key file is not base64: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("an auditor seed is %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// readPublishedCheckpoint accepts both the signed and the older unsigned form,
// and says which it got. An unsigned checkpoint from a peer you exchanged
// files with by hand is still useful; one fetched over a network is not, and
// the difference is the operator's to judge.
func readPublishedCheckpoint(path string) (auditor.Checkpoint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return auditor.Checkpoint{}, err
	}
	sc, err := auditor.UnmarshalSignedCheckpoint(data)
	if err != nil {
		return auditor.Checkpoint{}, err
	}
	if len(sc.Signature) == 0 {
		fmt.Fprintf(os.Stderr, "note: %s is unsigned; it attests to nothing on its own\n", path)
		return sc.Checkpoint, nil
	}
	if len(sc.AuditorKey) != ed25519.PublicKeySize {
		return auditor.Checkpoint{}, errors.New("signed checkpoint carries no auditor key")
	}
	if err := auditor.VerifyCheckpoint(sc.AuditorKey, sc); err != nil {
		return auditor.Checkpoint{}, err
	}
	fmt.Printf("checkpoint signed by %s\n", base64.StdEncoding.EncodeToString(sc.AuditorKey))
	return sc.Checkpoint, nil
}

func writeSignedCheckpoint(path string, key ed25519.PrivateKey, c auditor.Checkpoint) error {
	data, err := auditor.MarshalSignedCheckpoint(auditor.SignCheckpoint(key, c))
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	// 0644, not 0600: the whole point is that other people read it.
	if err := os.WriteFile(tmp, append(data, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
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
