package auditor_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/tildra/tildra/server/internal/auditor"
	"github.com/tildra/tildra/server/internal/transparency"
)

// fakeLog is a log the test can manipulate, including in ways an honest server
// never would — which is the point.
type fakeLog struct {
	signKey ed25519.PrivateKey
	entries []*transparency.Entry

	// Levers for misbehaviour.
	forgeRoot     []byte
	hideEntries   bool
	refuseProofs  bool
	overrideKey   ed25519.PrivateKey
	consistencyOf func(first, second int64) ([][]byte, error)
}

func newFakeLog(t *testing.T) *fakeLog {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return &fakeLog{signKey: key}
}

func (f *fakeLog) append(handle, accountID string, key byte) *transparency.Entry {
	identity := make([]byte, 32)
	for i := range identity {
		identity[i] = key
	}
	e := &transparency.Entry{
		Index: int64(len(f.entries)), Handle: handle, AccountID: accountID,
		IdentityKey: identity,
	}
	f.entries = append(f.entries, e)
	return e
}

func (f *fakeLog) hashes() [][]byte {
	out := make([][]byte, 0, len(f.entries))
	for _, e := range f.entries {
		out = append(out, transparency.HashLeaf(e.Encode()))
	}
	return out
}

func (f *fakeLog) Head(context.Context) (transparency.SignedTreeHead, error) {
	size := int64(len(f.entries))
	root := transparency.RootHash(f.hashes())
	if f.forgeRoot != nil {
		root = f.forgeRoot
	}
	key := f.signKey
	if f.overrideKey != nil {
		key = f.overrideKey
	}

	// Signed the same way the real log signs, so a signature over a *forged*
	// root is still valid. The auditor has to catch the root by re-deriving it,
	// not by leaning on the signature.
	return transparency.SignTreeHead(key, size, root, time.Now()), nil
}

func (f *fakeLog) Consistency(_ context.Context, first, second int64) ([][]byte, error) {
	if f.refuseProofs {
		return nil, errors.New("no such tree sizes")
	}
	if f.consistencyOf != nil {
		return f.consistencyOf(first, second)
	}
	return transparency.ConsistencyProof(f.hashes(), int(first), int(second))
}

func (f *fakeLog) Entries(_ context.Context, from, to int64) ([]*transparency.Entry, error) {
	if f.hideEntries {
		return nil, errors.New("entries unavailable")
	}
	if from < 0 || to > int64(len(f.entries)) || from > to {
		return nil, fmt.Errorf("range %d..%d out of bounds", from, to)
	}
	return f.entries[from:to], nil
}

func ctx() context.Context { return context.Background() }

func critical(findings []auditor.Finding) []auditor.Finding {
	var out []auditor.Finding
	for _, f := range findings {
		if f.Critical {
			out = append(out, f)
		}
	}
	return out
}

func hasKind(findings []auditor.Finding, kind string) bool {
	for _, f := range findings {
		if f.Kind == kind {
			return true
		}
	}
	return false
}

func TestAuditsAGrowingHonestLog(t *testing.T) {
	log := newFakeLog(t)
	a := auditor.New(log)

	for round := 0; round < 5; round++ {
		log.append(fmt.Sprintf("user%d", round), fmt.Sprintf("ACCOUNT%d", round), byte(round))
		findings, err := a.Audit(ctx())
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if c := critical(findings); len(c) != 0 {
			t.Fatalf("round %d: unexpected critical findings: %+v", round, c)
		}
		if a.Checkpoint().Size != int64(round+1) {
			t.Fatalf("round %d: checkpoint size %d", round, a.Checkpoint().Size)
		}
	}
}

func TestAnEmptyLogIsFine(t *testing.T) {
	a := auditor.New(newFakeLog(t))
	findings, err := a.Audit(ctx())
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if len(critical(findings)) != 0 {
		t.Errorf("an empty log produced findings: %+v", findings)
	}
}

func TestDetectsARewrittenLog(t *testing.T) {
	log := newFakeLog(t)
	a := auditor.New(log)

	for i := 0; i < 4; i++ {
		log.append(fmt.Sprintf("user%d", i), "ACCOUNT", byte(i))
	}
	if _, err := a.Audit(ctx()); err != nil {
		t.Fatalf("initial audit: %v", err)
	}

	// Rewrite an entry the auditor has already attested to, then grow.
	log.entries[1].IdentityKey = make([]byte, 32)
	for i := range log.entries[1].IdentityKey {
		log.entries[1].IdentityKey[i] = 0xEE
	}
	log.append("user4", "ACCOUNT", 4)

	findings, err := a.Audit(ctx())
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !hasKind(findings, auditor.KindInconsistent) {
		t.Fatalf("a rewritten log was not reported: %+v", findings)
	}
}

func TestDetectsAShrinkingLog(t *testing.T) {
	log := newFakeLog(t)
	a := auditor.New(log)
	for i := 0; i < 5; i++ {
		log.append(fmt.Sprintf("user%d", i), "ACCOUNT", byte(i))
	}
	if _, err := a.Audit(ctx()); err != nil {
		t.Fatalf("initial: %v", err)
	}

	log.entries = log.entries[:3]
	findings, _ := a.Audit(ctx())
	if !hasKind(findings, auditor.KindShrank) {
		t.Fatalf("a shrinking log was not reported: %+v", findings)
	}
}

func TestDetectsEntriesThatDoNotMatchTheSignedRoot(t *testing.T) {
	// The attack a consistency proof alone misses: the server signs a root for
	// a tree it will not show. Re-deriving the root from the served entries is
	// what catches it.
	log := newFakeLog(t)
	a := auditor.New(log)
	log.append("user0", "ACCOUNT", 0)
	log.append("user1", "ACCOUNT", 1)

	forged := make([]byte, 32)
	for i := range forged {
		forged[i] = 0x7F
	}
	log.forgeRoot = forged

	findings, err := a.Audit(ctx())
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !hasKind(findings, auditor.KindRootMismatch) {
		t.Fatalf("a forged root was not reported: %+v", findings)
	}
}

func TestDetectsALogKeyChange(t *testing.T) {
	log := newFakeLog(t)
	a := auditor.New(log)
	log.append("user0", "ACCOUNT", 0)
	if _, err := a.Audit(ctx()); err != nil {
		t.Fatalf("initial: %v", err)
	}

	_, other, _ := ed25519.GenerateKey(rand.Reader)
	log.overrideKey = other
	log.append("user1", "ACCOUNT", 1)

	findings, _ := a.Audit(ctx())
	if !hasKind(findings, auditor.KindLogKeyChanged) {
		t.Fatalf("a log key change was not reported: %+v", findings)
	}
}

func TestTreatsARefusedProofAsAnInconsistency(t *testing.T) {
	// A server that will not prove its own heads consistent has said enough.
	log := newFakeLog(t)
	a := auditor.New(log)
	log.append("user0", "ACCOUNT", 0)
	if _, err := a.Audit(ctx()); err != nil {
		t.Fatalf("initial: %v", err)
	}

	log.append("user1", "ACCOUNT", 1)
	log.refuseProofs = true

	findings, _ := a.Audit(ctx())
	if !hasKind(findings, auditor.KindInconsistent) {
		t.Fatalf("a refused proof was not reported: %+v", findings)
	}
}

func TestReportsRebindingsWithoutCallingThemAttacks(t *testing.T) {
	// A handle bound to a new key is what a reinstall looks like *and* what a
	// substitution looks like. The auditor cannot tell them apart, so it
	// surfaces the event rather than passing judgement — a non-critical finding
	// a human can look at.
	log := newFakeLog(t)
	a := auditor.New(log)
	log.append("ayse", "ACCOUNT1", 1)
	if _, err := a.Audit(ctx()); err != nil {
		t.Fatalf("initial: %v", err)
	}

	log.append("ayse", "ACCOUNT1", 2)
	findings, err := a.Audit(ctx())
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !hasKind(findings, auditor.KindRebinding) {
		t.Fatalf("a rebinding was not reported: %+v", findings)
	}
	if len(critical(findings)) != 0 {
		t.Errorf("a rebinding was reported as critical: %+v", critical(findings))
	}
}

func TestReportsWhenEntriesCannotBeRead(t *testing.T) {
	log := newFakeLog(t)
	a := auditor.New(log)
	log.append("user0", "ACCOUNT", 0)
	log.hideEntries = true

	findings, err := a.Audit(ctx())
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !hasKind(findings, auditor.KindRootMismatch) {
		t.Fatalf("an unreadable log was not reported: %+v", findings)
	}
}

func TestResumeRevalidatesRatherThanTrusting(t *testing.T) {
	log := newFakeLog(t)
	for i := 0; i < 6; i++ {
		log.append(fmt.Sprintf("user%d", i), "ACCOUNT", byte(i))
	}

	first := auditor.New(log)
	if _, err := first.Audit(ctx()); err != nil {
		t.Fatalf("audit: %v", err)
	}
	saved := first.Checkpoint()

	// A fresh auditor resuming from a published checkpoint must reach the same
	// root by re-reading the entries, not by believing the checkpoint.
	resumed := auditor.New(log)
	if err := resumed.Resume(ctx(), saved); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if resumed.Checkpoint().Size != saved.Size {
		t.Errorf("resumed size %d, want %d", resumed.Checkpoint().Size, saved.Size)
	}

	// A checkpoint that does not describe this log must be refused.
	bogus := saved
	bogus.RootHash = make([]byte, 32)
	if err := auditor.New(log).Resume(ctx(), bogus); err == nil {
		t.Error("a checkpoint that does not match the log was accepted")
	}
}

func TestCheckpointsRoundTripForPublication(t *testing.T) {
	log := newFakeLog(t)
	a := auditor.New(log)
	log.append("user0", "ACCOUNT", 0)
	if _, err := a.Audit(ctx()); err != nil {
		t.Fatalf("audit: %v", err)
	}

	data, err := auditor.MarshalCheckpoint(a.Checkpoint())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed, err := auditor.UnmarshalCheckpoint(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed.Size != a.Checkpoint().Size || string(parsed.RootHash) != string(a.Checkpoint().RootHash) {
		t.Error("checkpoint did not survive publication")
	}

	if _, err := auditor.UnmarshalCheckpoint([]byte(`{"size":5,"rootHash":"AAAA"}`)); err == nil {
		t.Error("a malformed checkpoint was accepted")
	}
}

func TestComparingAuditorsCatchesASplitView(t *testing.T) {
	// Two auditors, two logs, same key. Neither can tell alone; comparing
	// their checkpoints is what establishes the operator is forking.
	honest := newFakeLog(t)
	forked := &fakeLog{signKey: honest.signKey}

	for i := 0; i < 4; i++ {
		honest.append(fmt.Sprintf("user%d", i), "ACCOUNT", byte(i))
		forked.append(fmt.Sprintf("other%d", i), "ACCOUNT", byte(100+i))
	}

	a1, a2 := auditor.New(honest), auditor.New(forked)
	if _, err := a1.Audit(ctx()); err != nil {
		t.Fatalf("a1: %v", err)
	}
	if _, err := a2.Audit(ctx()); err != nil {
		t.Fatalf("a2: %v", err)
	}

	// Each log is internally consistent, so neither auditor found anything.
	err := auditor.CompareCheckpoints(ctx(), a1.Checkpoint(), a2.Checkpoint(),
		func(c context.Context, first, second int64) ([][]byte, error) {
			return honest.Consistency(c, first, second)
		})
	if err == nil {
		t.Fatal("comparing checkpoints from two different logs succeeded")
	}
}

func TestComparingAuditorsOnTheSameLogAgrees(t *testing.T) {
	log := newFakeLog(t)
	a1 := auditor.New(log)
	for i := 0; i < 3; i++ {
		log.append(fmt.Sprintf("user%d", i), "ACCOUNT", byte(i))
	}
	if _, err := a1.Audit(ctx()); err != nil {
		t.Fatalf("a1: %v", err)
	}

	// A second auditor that looked later must still be reconcilable.
	a2 := auditor.New(log)
	log.append("user3", "ACCOUNT", 3)
	if _, err := a2.Audit(ctx()); err != nil {
		t.Fatalf("a2: %v", err)
	}

	err := auditor.CompareCheckpoints(ctx(), a1.Checkpoint(), a2.Checkpoint(),
		func(c context.Context, first, second int64) ([][]byte, error) {
			return log.Consistency(c, first, second)
		})
	if err != nil {
		t.Fatalf("two auditors on one log disagreed: %v", err)
	}
}
