package auditor_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tildra/tildra/server/internal/auditor"
	"github.com/tildra/tildra/server/internal/transparency"
)

func testCheckpoint() auditor.Checkpoint {
	root := make([]byte, transparency.HashSize)
	for i := range root {
		root[i] = byte(i * 7)
	}
	logKey := make([]byte, ed25519.PublicKeySize)
	for i := range logKey {
		logKey[i] = byte(i * 3)
	}
	return auditor.Checkpoint{
		Size:      42,
		RootHash:  root,
		LogKey:    logKey,
		CheckedAt: time.Unix(1_770_000_000, 0).UTC(),
	}
}

func auditorKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return pub, priv
}

func TestSignedCheckpointVerifies(t *testing.T) {
	pub, priv := auditorKey(t)
	sc := auditor.SignCheckpoint(priv, testCheckpoint())

	if err := auditor.VerifyCheckpoint(pub, sc); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestSignatureSurvivesAJSONRoundTrip(t *testing.T) {
	// The document travels as JSON, and JSON has no canonical form. Signing
	// the framed encoding rather than the serialised bytes is what makes a
	// re-serialised document still verify.
	pubKey, privKey := auditorKey(t)
	sc := auditor.SignCheckpoint(privKey, testCheckpoint())

	data, err := auditor.MarshalSignedCheckpoint(sc)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := auditor.UnmarshalSignedCheckpoint(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := auditor.VerifyCheckpoint(pubKey, parsed); err != nil {
		t.Fatalf("verify after round trip: %v", err)
	}

	// Reordered and reformatted by a different encoder: still the same
	// document, so still the same signature.
	var loose map[string]any
	if err := json.Unmarshal(data, &loose); err != nil {
		t.Fatal(err)
	}
	compact, err := json.Marshal(loose)
	if err != nil {
		t.Fatal(err)
	}
	reparsed, err := auditor.UnmarshalSignedCheckpoint(compact)
	if err != nil {
		t.Fatal(err)
	}
	if err := auditor.VerifyCheckpoint(pubKey, reparsed); err != nil {
		t.Fatalf("verify after reserialisation: %v", err)
	}
}

func TestVerifyRejectsEveryFieldBeingMoved(t *testing.T) {
	pub, priv := auditorKey(t)
	base := testCheckpoint()
	signed := auditor.SignCheckpoint(priv, base)

	otherRoot := make([]byte, transparency.HashSize)
	copy(otherRoot, base.RootHash)
	otherRoot[0] ^= 0x01

	otherLogKey := make([]byte, len(base.LogKey))
	copy(otherLogKey, base.LogKey)
	otherLogKey[0] ^= 0x01

	cases := map[string]auditor.Checkpoint{
		"size":      {Size: 43, RootHash: base.RootHash, LogKey: base.LogKey, CheckedAt: base.CheckedAt},
		"rootHash":  {Size: base.Size, RootHash: otherRoot, LogKey: base.LogKey, CheckedAt: base.CheckedAt},
		"logKey":    {Size: base.Size, RootHash: base.RootHash, LogKey: otherLogKey, CheckedAt: base.CheckedAt},
		"checkedAt": {Size: base.Size, RootHash: base.RootHash, LogKey: base.LogKey, CheckedAt: base.CheckedAt.Add(time.Hour)},
	}
	for name, tampered := range cases {
		sc := signed
		sc.Checkpoint = tampered
		if err := auditor.VerifyCheckpoint(pub, sc); err == nil {
			t.Fatalf("a checkpoint with %s moved still verified", name)
		}
	}
}

func TestVerifyRefusesAnotherAuditorsKey(t *testing.T) {
	// The document carries the key it was signed with, which is useful and
	// proves nothing: anyone can generate a key, sign, and ship both.
	_, priv := auditorKey(t)
	pinned, _ := auditorKey(t)

	sc := auditor.SignCheckpoint(priv, testCheckpoint())
	if err := auditor.VerifyCheckpoint(pinned, sc); err != auditor.ErrWrongAuditor {
		t.Fatalf("err = %v, want ErrWrongAuditor", err)
	}

	// And with the embedded key stripped, so only the signature can speak: it
	// still must not verify against a key that did not make it.
	sc.AuditorKey = nil
	if err := auditor.VerifyCheckpoint(pinned, sc); err == nil {
		t.Fatal("a checkpoint verified against an auditor that did not sign it")
	}
}

func TestVerifyDistinguishesUnsignedFromTampered(t *testing.T) {
	// "This auditor does not sign" and "somebody edited this" are different
	// problems and lead to different responses.
	pub, _ := auditorKey(t)
	unsigned := auditor.SignedCheckpoint{Checkpoint: testCheckpoint()}
	if err := auditor.VerifyCheckpoint(pub, unsigned); err != auditor.ErrUnsigned {
		t.Fatalf("err = %v, want ErrUnsigned", err)
	}
}

func TestVerifyRequiresAPinnedKey(t *testing.T) {
	// Verifying against the key inside the document would be circular, so
	// there is no way to ask for it.
	_, priv := auditorKey(t)
	sc := auditor.SignCheckpoint(priv, testCheckpoint())
	if err := auditor.VerifyCheckpoint(nil, sc); err == nil {
		t.Fatal("verification succeeded with no pinned key")
	}
	if err := auditor.VerifyCheckpoint(make(ed25519.PublicKey, 31), sc); err == nil {
		t.Fatal("verification succeeded with a malformed pinned key")
	}
}

func TestSignatureDoesNotVerifyAsATreeHead(t *testing.T) {
	// Domain separation: the auditor's key must not be usable to make
	// something that passes for a different kind of attestation.
	_, priv := auditorKey(t)
	sc := auditor.SignCheckpoint(priv, testCheckpoint())

	head := transparency.SignedTreeHead{
		Size:     sc.Size,
		RootHash: sc.RootHash,
		LogKey:   priv.Public().(ed25519.PublicKey),
		// The auditor's checkpoint signature, offered as a tree-head signature.
		Signature: sc.Signature,
	}
	if err := head.Verify(priv.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("an auditor checkpoint signature verified as a signed tree head")
	}
}

func TestUnmarshalRefusesMalformedDocuments(t *testing.T) {
	for name, body := range map[string]string{
		"not json":      `{`,
		"negative size": `{"size":-1}`,
		"short root":    `{"size":4,"rootHash":"AAAA"}`,
		"short key":     `{"size":0,"auditorKey":"AAAA"}`,
	} {
		if _, err := auditor.UnmarshalSignedCheckpoint([]byte(body)); err == nil {
			t.Fatalf("%s parsed", name)
		}
	}
}

func TestPublishedFormIsReadable(t *testing.T) {
	// Operators paste this into a README or a status page; it should not be
	// one line of base64.
	_, priv := auditorKey(t)
	data, err := auditor.MarshalSignedCheckpoint(auditor.SignCheckpoint(priv, testCheckpoint()))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"size", "rootHash", "logKey", "auditorKey", "signature"} {
		if !strings.Contains(string(data), field) {
			t.Fatalf("published checkpoint has no %s field:\n%s", field, data)
		}
	}
}
