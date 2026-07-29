// Package model holds the wire and storage types shared across the server.
//
// A note that applies to this whole package: nothing here contains message
// plaintext, a phone number, or an email address. If a field is ever added that
// does, it is a protocol violation and docs/PROTOCOL.md §8 needs to change first.
package model

import "time"

// Account is an identity. Not a person, not a phone number — a key.
type Account struct {
	ID        string    `json:"id"`     // 26-char Crockford base32
	Handle    string    `json:"handle"` // optional, mutable, non-authoritative
	CreatedAt time.Time `json:"createdAt"`
}

// Device is one installation of a client. An account may have several; each
// has its own identity key and its own ratchet sessions.
type Device struct {
	AccountID   string    `json:"accountId"`
	DeviceID    string    `json:"deviceId"`
	Name        string    `json:"name"`        // user-visible, e.g. "Pixel 9"
	IdentityKey []byte    `json:"identityKey"` // Ed25519 public key, 32 bytes
	CreatedAt   time.Time `json:"createdAt"`
	LastSeen    time.Time `json:"lastSeen"`
}

// PreKey is one public key in a bundle. Signature is set only for signed
// prekeys (SPK, PQSPK); one-time prekeys are authenticated transitively by the
// bundle they arrive in.
type PreKey struct {
	ID        uint32 `json:"id"`
	PublicKey []byte `json:"publicKey"`
	Signature []byte `json:"signature,omitempty"`
}

// PreKeyBundle is what a client fetches to start a session with a device.
// The one-time keys are consumed — each bundle handed out removes them from
// the pool, so two senders never get the same one.
type PreKeyBundle struct {
	AccountID    string  `json:"accountId"`
	DeviceID     string  `json:"deviceId"`
	IdentityKey  []byte  `json:"identityKey"`
	SignedPreKey PreKey  `json:"signedPreKey"`
	SignedPQKey  PreKey  `json:"signedPqPreKey"`
	OneTimeKey   *PreKey `json:"oneTimePreKey,omitempty"`
	OneTimePQKey *PreKey `json:"oneTimePqPreKey,omitempty"`
}

// KeyUpload is the body a client PUTs to publish its keys.
type KeyUpload struct {
	IdentityKey  []byte   `json:"identityKey"`
	SignedPreKey PreKey   `json:"signedPreKey"`
	SignedPQKey  PreKey   `json:"signedPqPreKey"`
	OneTimeKeys  []PreKey `json:"oneTimePreKeys"`
	OneTimePQ    []PreKey `json:"oneTimePqPreKeys"`
}

// Envelope is a sealed-sender message. The server can see which mailbox it is
// destined for and how big it is (bucketed by the client). It cannot see the
// sender, the recipient's identity, or the content.
type Envelope struct {
	ID         string    `json:"id"`
	Mailbox    string    `json:"mailbox"`
	Ciphertext []byte    `json:"ciphertext"`
	ServerTS   time.Time `json:"serverTs"`
}

// Mailbox is a rotating drop point owned by a device. Clients register the
// mailboxes for today and tomorrow; older ones expire.
type Mailbox struct {
	ID        string    `json:"id"`
	AccountID string    `json:"accountId"`
	DeviceID  string    `json:"deviceId"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// Attachment is an encrypted blob held for retrieval.
//
// The server stores ciphertext and a size, and nothing else. It does not know
// the type of the file, its name, who uploaded it, or who will fetch it — the
// decryption key travels inside the message that references the attachment,
// so possession of the blob without that message is useless.
//
// Deliberately not linked to an account: an uploader-to-blob mapping would
// recreate exactly the metadata sealed sender exists to remove.
type Attachment struct {
	ID         string    `json:"id"`
	Ciphertext []byte    `json:"-"`
	Size       int64     `json:"size"`
	CreatedAt  time.Time `json:"createdAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
}
