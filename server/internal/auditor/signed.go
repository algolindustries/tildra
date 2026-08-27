package auditor

// Signing a checkpoint, so it can reach somebody who was not handed it in
// person.
//
// An unsigned checkpoint works for the case the auditor was built for: two
// operators who know each other exchange files and compare. It does not work
// for the case that actually protects users — a phone fetching an auditor's
// view over the network and checking it against what the server showed *it*.
// There, an unsigned JSON blob is worth nothing: whoever serves it, including
// the operator being audited, can write whatever makes the two views agree.
//
// So an auditor has its own key, publishes its public half once, and signs
// every checkpoint. The client pins that key. This is deliberately the same
// shape as the log's own tree-head signature — the auditor is not more trusted
// than the log operator, it is a *second* party whose disagreement is the
// alarm.
//
// The signature covers a length-framed encoding rather than the JSON. JSON has
// no canonical form: field order, whitespace and integer formatting are all
// free, so signing the serialised bytes would mean a re-serialisation that is
// semantically identical fails to verify, and — worse — that two different
// JSON documents could carry one signature.

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/algolindustries/tildra/server/internal/transparency"
)

// CheckpointContext domain-separates the signature. A signature made over an
// auditor checkpoint must never verify as anything else.
const CheckpointContext = "tildra-auditor-checkpoint-v1:"

// ErrUnsigned is returned when a checkpoint carries no signature but one was
// required. Distinct from a bad signature: "this auditor does not sign" and
// "somebody tampered with this" call for different responses.
var ErrUnsigned = errors.New("auditor: checkpoint is not signed")

// ErrWrongAuditor is returned when a checkpoint is signed by a key other than
// the one that was pinned.
var ErrWrongAuditor = errors.New("auditor: checkpoint is signed by a different auditor")

// SignedCheckpoint is a checkpoint plus the auditor's attestation to it.
type SignedCheckpoint struct {
	Checkpoint
	// AuditorKey is the Ed25519 public key of the auditor. Present so the
	// document is self-describing; a verifier must still compare it against a
	// key it pinned out of band, and `VerifyCheckpoint` insists on that.
	AuditorKey []byte `json:"auditorKey,omitempty"`
	Signature  []byte `json:"signature,omitempty"`
}

// checkpointTranscript is the canonical byte encoding that gets signed.
//
// Length-framed rather than delimiter-joined, for the reason the rest of this
// codebase is: with delimiters, a value containing the delimiter can shift a
// field boundary and make one signature verify for different content.
func checkpointTranscript(c Checkpoint) []byte {
	out := []byte(CheckpointContext)
	out = appendFramed(out, int64Bytes(c.Size))
	out = appendFramed(out, c.RootHash)
	out = appendFramed(out, c.LogKey)
	// Second precision. Nanoseconds survive a Go round trip and do not survive
	// every JSON one, and a timestamp that changes shape between encoders is a
	// signature that stops verifying for no reason.
	out = appendFramed(out, int64Bytes(c.CheckedAt.UTC().Unix()))
	return out
}

func appendFramed(dst, field []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(field)))
	dst = append(dst, length[:]...)
	return append(dst, field...)
}

func int64Bytes(v int64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(v))
	return b[:]
}

// SignCheckpoint attests to a checkpoint with the auditor's key.
func SignCheckpoint(key ed25519.PrivateKey, c Checkpoint) SignedCheckpoint {
	// Truncated on the way in so the signed value and the published value are
	// the same thing. Signing c and publishing a rounded c is how a signature
	// that "sometimes fails" gets shipped.
	c.CheckedAt = c.CheckedAt.UTC().Truncate(time.Second)
	return SignedCheckpoint{
		Checkpoint: c,
		AuditorKey: key.Public().(ed25519.PublicKey),
		Signature:  ed25519.Sign(key, checkpointTranscript(c)),
	}
}

// VerifyCheckpoint checks a published checkpoint against a pinned auditor key.
//
// `pinned` is required. Verifying against the key inside the document would be
// circular — anyone can generate a key, sign a checkpoint, and put both in the
// same file.
func VerifyCheckpoint(pinned ed25519.PublicKey, sc SignedCheckpoint) error {
	if len(pinned) != ed25519.PublicKeySize {
		return fmt.Errorf("auditor: a pinned auditor key is required to verify a checkpoint")
	}
	if len(sc.Signature) == 0 {
		return ErrUnsigned
	}
	if len(sc.AuditorKey) != 0 && string(sc.AuditorKey) != string(pinned) {
		return ErrWrongAuditor
	}
	if !ed25519.Verify(pinned, checkpointTranscript(sc.Checkpoint), sc.Signature) {
		return fmt.Errorf("%w: checkpoint signature does not verify", transparency.ErrProofFailed)
	}
	return nil
}

// MarshalSignedCheckpoint renders a signed checkpoint for publication.
func MarshalSignedCheckpoint(sc SignedCheckpoint) ([]byte, error) {
	return json.MarshalIndent(sc, "", "  ")
}

// UnmarshalSignedCheckpoint parses a published checkpoint without verifying it.
//
// Verification is a separate call because it needs a pinned key the parser does
// not have, and because "this parsed" must never be mistaken for "this is
// trustworthy".
func UnmarshalSignedCheckpoint(data []byte) (SignedCheckpoint, error) {
	var sc SignedCheckpoint
	if err := json.Unmarshal(data, &sc); err != nil {
		return SignedCheckpoint{}, err
	}
	if sc.Size < 0 || (sc.Size > 0 && len(sc.RootHash) != transparency.HashSize) {
		return SignedCheckpoint{}, errors.New("malformed checkpoint")
	}
	if len(sc.AuditorKey) != 0 && len(sc.AuditorKey) != ed25519.PublicKeySize {
		return SignedCheckpoint{}, errors.New("malformed auditor key")
	}
	return sc, nil
}
