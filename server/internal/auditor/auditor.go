// Package auditor watches a Tildra transparency log.
//
// The log's proofs protect a client against the server it is talking to. They
// do not protect anyone against a server that shows a consistent, forked view
// to a group of people who never compare notes. Gossip between contacts closes
// much of that, but only for people who message each other.
//
// An auditor is the third leg: an independent process that reads the whole
// log, checks every head against every previous head, and re-derives the root
// from the entries the server actually served. It has no account and no stake
// in any conversation, so it notices a fork whether or not the people inside
// it ever talk.
//
// What it can prove: that the log it is being shown is internally consistent
// and append-only, and that the entries add up to the roots being signed.
// What it cannot prove alone: that this is the same log everyone else sees —
// for that, auditors have to publish their checkpoints, which is why Checkpoint
// is a serialisable, publishable thing rather than private state.
package auditor

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/tildra/tildra/server/internal/transparency"
)

// Finding is something the auditor wants a human to look at.
type Finding struct {
	Kind     string              `json:"kind"`
	Detail   string              `json:"detail"`
	At       time.Time           `json:"at"`
	TreeSize int64               `json:"treeSize"`
	Critical bool                `json:"critical"`
	LogEntry *transparency.Entry `json:"entry,omitempty"`
}

// Finding kinds. Critical ones mean the log is not what it claims to be;
// the rest are things worth a person's attention but not proof of an attack.
const (
	// The log key changed. Either the operator rotated it — which they must
	// announce out of band — or this is a different log wearing the same URL.
	KindLogKeyChanged = "log-key-changed"
	// A tree head did not verify under the log key.
	KindBadSignature = "bad-signature"
	// The log got smaller. Entries were removed.
	KindShrank = "log-shrank"
	// A consistency proof between two heads failed: history was rewritten.
	KindInconsistent = "inconsistent"
	// The entries the server served do not hash to the root it signed.
	KindRootMismatch = "root-mismatch"
	// A handle was bound to a different identity key. Legitimate when someone
	// reinstalls; also exactly what a key substitution looks like.
	KindRebinding = "handle-rebound"
)

// Checkpoint is the auditor's view of the log, in a form it can publish.
//
// Two auditors comparing checkpoints is what turns "this log is internally
// consistent" into "this log is the same one you were shown".
type Checkpoint struct {
	Size      int64     `json:"size"`
	RootHash  []byte    `json:"rootHash"`
	LogKey    []byte    `json:"logKey"`
	CheckedAt time.Time `json:"checkedAt"`
}

func (c Checkpoint) String() string {
	return fmt.Sprintf("size=%d root=%s", c.Size, base64.StdEncoding.EncodeToString(c.RootHash))
}

// Source is the log as the auditor sees it. An interface so the auditor can be
// tested without a network, and so a mirror or an on-disk copy can be audited
// the same way as a live server.
type Source interface {
	Head(ctx context.Context) (transparency.SignedTreeHead, error)
	Consistency(ctx context.Context, first, second int64) ([][]byte, error)
	Entries(ctx context.Context, from, to int64) ([]*transparency.Entry, error)
}

// Auditor holds the running view of one log.
type Auditor struct {
	source Source

	checkpoint Checkpoint
	leafHashes [][]byte
	// bindings tracks the latest key seen per handle, so a rebinding can be
	// reported rather than silently accepted.
	bindings map[string][]byte
}

func New(source Source) *Auditor {
	return &Auditor{source: source, bindings: map[string][]byte{}}
}

// Checkpoint returns the auditor's current view.
func (a *Auditor) Checkpoint() Checkpoint { return a.checkpoint }

// Resume restores a previously published checkpoint.
//
// The auditor re-downloads and re-verifies every entry from zero rather than
// trusting the leaf hashes in a checkpoint — a checkpoint attests to a root,
// not to the entries behind it, and an auditor that trusts its own stale
// working state is one bad restart away from attesting to nonsense.
func (a *Auditor) Resume(ctx context.Context, c Checkpoint) error {
	a.checkpoint = Checkpoint{LogKey: c.LogKey}
	a.leafHashes = nil
	a.bindings = map[string][]byte{}

	if c.Size == 0 {
		return nil
	}
	if _, err := a.ingest(ctx, 0, c.Size); err != nil {
		return err
	}
	root := transparency.RootHash(a.leafHashes)
	if string(root) != string(c.RootHash) {
		return fmt.Errorf("resumed checkpoint does not match the log: %w", transparency.ErrProofFailed)
	}
	a.checkpoint = c
	return nil
}

// Audit fetches the current head and checks everything it can.
//
// Returns every finding rather than the first: an operator looking at a
// suspect log wants the whole picture, and stopping at the first problem hides
// whether it was isolated.
func (a *Auditor) Audit(ctx context.Context) ([]Finding, error) {
	head, err := a.source.Head(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch head: %w", err)
	}

	var findings []Finding
	at := time.Now().UTC()

	if len(a.checkpoint.LogKey) == 0 {
		// First run: trust on first use, and say so by recording the key.
		a.checkpoint.LogKey = head.LogKey
	} else if string(a.checkpoint.LogKey) != string(head.LogKey) {
		return append(findings, Finding{
			Kind: KindLogKeyChanged, At: at, TreeSize: head.Size, Critical: true,
			Detail: fmt.Sprintf("log key changed from %s to %s",
				base64.StdEncoding.EncodeToString(a.checkpoint.LogKey),
				base64.StdEncoding.EncodeToString(head.LogKey)),
		}), nil
	}

	if err := head.Verify(ed25519.PublicKey(a.checkpoint.LogKey)); err != nil {
		return append(findings, Finding{
			Kind: KindBadSignature, At: at, TreeSize: head.Size, Critical: true,
			Detail: err.Error(),
		}), nil
	}

	if head.Size < a.checkpoint.Size {
		return append(findings, Finding{
			Kind: KindShrank, At: at, TreeSize: head.Size, Critical: true,
			Detail: fmt.Sprintf("log shrank from %d to %d entries", a.checkpoint.Size, head.Size),
		}), nil
	}

	// Consistency against what we saw last time. This is the check that
	// catches a rewrite.
	if a.checkpoint.Size > 0 && head.Size > a.checkpoint.Size {
		proof, err := a.source.Consistency(ctx, a.checkpoint.Size, head.Size)
		if err != nil {
			return append(findings, Finding{
				Kind: KindInconsistent, At: at, TreeSize: head.Size, Critical: true,
				Detail: fmt.Sprintf("server could not prove consistency %d -> %d: %v",
					a.checkpoint.Size, head.Size, err),
			}), nil
		}
		err = transparency.VerifyConsistency(
			int(a.checkpoint.Size), int(head.Size), proof, a.checkpoint.RootHash, head.RootHash)
		if err != nil {
			return append(findings, Finding{
				Kind: KindInconsistent, At: at, TreeSize: head.Size, Critical: true,
				Detail: err.Error(),
			}), nil
		}
	}

	// Download the new entries and check they add up to the root that was
	// signed. A consistency proof says the tree grew; this says the tree is
	// made of the entries the server is willing to show.
	rebindings, err := a.ingest(ctx, a.checkpoint.Size, head.Size)
	if err != nil {
		return append(findings, Finding{
			Kind: KindRootMismatch, At: at, TreeSize: head.Size, Critical: true,
			Detail: fmt.Sprintf("could not read entries %d..%d: %v", a.checkpoint.Size, head.Size, err),
		}), nil
	}
	findings = append(findings, rebindings...)

	if computed := transparency.RootHash(a.leafHashes); string(computed) != string(head.RootHash) {
		return append(findings, Finding{
			Kind: KindRootMismatch, At: at, TreeSize: head.Size, Critical: true,
			Detail: fmt.Sprintf("entries hash to %s but the signed head claims %s",
				base64.StdEncoding.EncodeToString(computed),
				base64.StdEncoding.EncodeToString(head.RootHash)),
		}), nil
	}

	a.checkpoint = Checkpoint{
		Size: head.Size, RootHash: head.RootHash, LogKey: head.LogKey, CheckedAt: at,
	}
	return findings, nil
}

// ingest downloads a range of entries, hashes them, and reports rebindings.
func (a *Auditor) ingest(ctx context.Context, from, to int64) ([]Finding, error) {
	var findings []Finding
	const batch = 500

	for start := from; start < to; start += batch {
		end := start + batch
		if end > to {
			end = to
		}
		entries, err := a.source.Entries(ctx, start, end)
		if err != nil {
			return nil, err
		}
		if int64(len(entries)) != end-start {
			return nil, fmt.Errorf("expected %d entries in %d..%d, got %d",
				end-start, start, end, len(entries))
		}

		for _, e := range entries {
			if e.Index != int64(len(a.leafHashes)) {
				return nil, fmt.Errorf("entry claims index %d but the log is %d long",
					e.Index, len(a.leafHashes))
			}
			if previous, seen := a.bindings[e.Handle]; seen && string(previous) != string(e.IdentityKey) {
				// Legitimate when someone reinstalls, and also exactly what a
				// key substitution looks like. The auditor cannot tell them
				// apart, so it reports rather than judges.
				findings = append(findings, Finding{
					Kind: KindRebinding, At: time.Now().UTC(), TreeSize: int64(len(a.leafHashes)),
					LogEntry: e,
					Detail:   fmt.Sprintf("@%s was rebound to a different identity key", e.Handle),
				})
			}
			a.bindings[e.Handle] = e.IdentityKey
			a.leafHashes = append(a.leafHashes, transparency.HashLeaf(e.Encode()))
		}
	}
	return findings, nil
}

// MarshalCheckpoint renders a checkpoint for publication.
func MarshalCheckpoint(c Checkpoint) ([]byte, error) { return json.MarshalIndent(c, "", "  ") }

// UnmarshalCheckpoint parses a published checkpoint.
func UnmarshalCheckpoint(data []byte) (Checkpoint, error) {
	var c Checkpoint
	if err := json.Unmarshal(data, &c); err != nil {
		return Checkpoint{}, err
	}
	if c.Size < 0 || (c.Size > 0 && len(c.RootHash) != transparency.HashSize) {
		return Checkpoint{}, errors.New("malformed checkpoint")
	}
	return c, nil
}

// CompareCheckpoints is what makes independent auditors worth running.
//
// Two auditors that watched the same log must agree; if the smaller is not a
// prefix of the larger, they were shown different logs and the operator is
// running a split view. Neither auditor can establish that alone.
func CompareCheckpoints(
	ctx context.Context,
	mine, theirs Checkpoint,
	proofs func(ctx context.Context, first, second int64) ([][]byte, error),
) error {
	if len(mine.LogKey) != 0 && len(theirs.LogKey) != 0 &&
		string(mine.LogKey) != string(theirs.LogKey) {
		return fmt.Errorf("%w: the two auditors are watching different logs", transparency.ErrProofFailed)
	}
	if mine.Size == theirs.Size {
		if string(mine.RootHash) != string(theirs.RootHash) {
			return fmt.Errorf("%w: same tree size, different roots — split view",
				transparency.ErrProofFailed)
		}
		return nil
	}

	first, second := mine, theirs
	if theirs.Size < mine.Size {
		first, second = theirs, mine
	}
	proof, err := proofs(ctx, first.Size, second.Size)
	if err != nil {
		return fmt.Errorf("%w: no proof linking %d to %d: %v",
			transparency.ErrProofFailed, first.Size, second.Size, err)
	}
	return transparency.VerifyConsistency(
		int(first.Size), int(second.Size), proof, first.RootHash, second.RootHash)
}
