// Package api is the HTTP surface of the Tildra server.
//
// Design rule for every handler here: if the handler needs to know something
// about the *content* of a conversation to do its job, the design is wrong.
// The server routes bytes and hands out public keys. That is the whole job.
package api

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/tildra/tildra/server/internal/auth"
	"github.com/tildra/tildra/server/internal/config"
	"github.com/tildra/tildra/server/internal/gateway"
	"github.com/tildra/tildra/server/internal/id"
	"github.com/tildra/tildra/server/internal/model"
	"github.com/tildra/tildra/server/internal/push"
	"github.com/tildra/tildra/server/internal/store"
	"github.com/tildra/tildra/server/internal/transparency"
	"github.com/tildra/tildra/server/internal/turn"
)

// Server wires the store, authenticator, hub, notifier and transparency log
// into an http.Handler.
type Server struct {
	cfg   *config.Config
	store store.Store
	auth  *auth.Authenticator
	hub   *gateway.Hub
	push  push.Notifier
	// tlog is nil when no signing key is configured. Handle lookups then carry
	// no proof, which the client is told rather than left to assume.
	tlog *transparency.Log
	log  *slog.Logger
}

func New(
	cfg *config.Config,
	s store.Store,
	a *auth.Authenticator,
	h *gateway.Hub,
	notifier push.Notifier,
	tlog *transparency.Log,
	log *slog.Logger,
) *Server {
	if notifier == nil {
		notifier = push.Nop{}
	}
	return &Server{cfg: cfg, store: s, auth: a, hub: h, push: notifier, tlog: tlog, log: log}
}

// Handler builds the route table.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Unauthenticated: registration and the login handshake.
	mux.HandleFunc("POST /v1/accounts", s.createAccount)
	mux.HandleFunc("GET /v1/auth/challenge", s.authChallenge)
	mux.HandleFunc("POST /v1/auth/token", s.authToken)
	mux.HandleFunc("GET /v1/handles/{handle}", s.resolveHandle)
	mux.HandleFunc("GET /v1/transparency/head", s.transparencyHead)
	mux.HandleFunc("GET /v1/transparency/consistency", s.transparencyConsistency)
	mux.HandleFunc("GET /v1/transparency/entries", s.transparencyEntries)
	mux.HandleFunc("GET /v1/recovery/{lookupId}", s.getRecoveryBlob)
	mux.HandleFunc("GET /healthz", s.health)

	// Device linking. The new device has no account yet, so the first two
	// steps cannot be authenticated — which is exactly why the security rests
	// on the identity-key commitment carried over a camera and the pairing
	// code the user compares, not on who is calling.
	mux.HandleFunc("POST /v1/provisioning", s.createProvisioning)
	mux.HandleFunc("GET /v1/provisioning/{id}", s.getProvisioning)

	// Authenticated.
	authed := http.NewServeMux()
	authed.HandleFunc("PUT /v1/keys", s.putKeys)
	authed.HandleFunc("GET /v1/keys/count", s.keyCount)
	authed.HandleFunc("GET /v1/keys/{accountId}/{deviceId}", s.getBundle)
	authed.HandleFunc("GET /v1/devices/{accountId}", s.listDevices)
	authed.HandleFunc("PUT /v1/handle", s.setHandle)
	authed.HandleFunc("POST /v1/mailboxes", s.registerMailboxes)
	authed.HandleFunc("POST /v1/messages", s.sendMessage)
	authed.HandleFunc("PUT /v1/backup", s.putBackup)
	authed.HandleFunc("GET /v1/backup", s.getBackup)
	authed.HandleFunc("PUT /v1/recovery/{lookupId}", s.putRecoveryBlob)
	authed.HandleFunc("PUT /v1/push", s.registerPushToken)
	authed.HandleFunc("DELETE /v1/push", s.deletePushToken)
	authed.HandleFunc("POST /v1/attachments", s.uploadAttachment)
	authed.HandleFunc("GET /v1/attachments/{id}", s.downloadAttachment)
	authed.HandleFunc("POST /v1/devices", s.addDevice)
	authed.HandleFunc("PUT /v1/provisioning/{id}/approval", s.approveProvisioning)
	authed.HandleFunc("GET /v1/turn", s.turnCredentials)
	authed.HandleFunc("POST /v1/auth/logout", s.logout)
	mux.Handle("/v1/", s.auth.Middleware(authed))

	// The WebSocket does its own auth: browsers and RN cannot set headers on
	// an upgrade, so the token arrives as a subprotocol.
	mux.HandleFunc("GET /v1/ws", s.websocket)

	return securityHeaders(logging(s.log, mux))
}

// ---------- accounts ----------

type createAccountReq struct {
	IdentityKey []byte `json:"identityKey"` // Ed25519 public key
	DeviceName  string `json:"deviceName"`
	ProofTS     string `json:"proofTs"` // RFC3339, signed
	Proof       []byte `json:"proof"`   // Ed25519 signature
}

type createAccountResp struct {
	AccountID string `json:"accountId"`
	DeviceID  string `json:"deviceId"`
}

func (s *Server) createAccount(w http.ResponseWriter, r *http.Request) {
	var req createAccountReq
	if !decode(w, r, &req) {
		return
	}
	ts, err := time.Parse(time.RFC3339, req.ProofTS)
	if err != nil {
		fail(w, http.StatusBadRequest, "proofTs must be RFC3339")
		return
	}
	if err := auth.VerifyRegistrationProof(req.IdentityKey, req.Proof, ts, time.Now()); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}

	acct := &model.Account{ID: id.New(), CreatedAt: time.Now().UTC()}
	if err := s.store.CreateAccount(r.Context(), acct); err != nil {
		s.fail500(w, "create account", err)
		return
	}
	dev := &model.Device{
		AccountID:   acct.ID,
		DeviceID:    id.New(),
		Name:        sanitizeName(req.DeviceName),
		IdentityKey: req.IdentityKey,
		CreatedAt:   time.Now().UTC(),
		LastSeen:    time.Now().UTC(),
	}
	if err := s.store.UpsertDevice(r.Context(), dev); err != nil {
		s.fail500(w, "create device", err)
		return
	}
	respond(w, http.StatusCreated, createAccountResp{AccountID: acct.ID, DeviceID: dev.DeviceID})
}

// ---------- auth ----------

func (s *Server) authChallenge(w http.ResponseWriter, r *http.Request) {
	accountID := r.URL.Query().Get("account")
	deviceID := r.URL.Query().Get("device")
	if accountID == "" || deviceID == "" {
		fail(w, http.StatusBadRequest, "account and device are required")
		return
	}
	// Issue a challenge even for unknown devices, and take the same code path.
	// Refusing early would turn this endpoint into an oracle for which account
	// IDs exist.
	c := s.auth.IssueChallenge(accountID, deviceID)
	respond(w, http.StatusOK, map[string]any{
		"challenge": c,
		"expiresAt": time.Now().Add(auth.ChallengeTTL).UTC(),
	})
}

type authTokenReq struct {
	AccountID string `json:"accountId"`
	DeviceID  string `json:"deviceId"`
	Challenge []byte `json:"challenge"`
	Signature []byte `json:"signature"`
}

func (s *Server) authToken(w http.ResponseWriter, r *http.Request) {
	var req authTokenReq
	if !decode(w, r, &req) {
		return
	}
	token, expires, err := s.auth.RedeemChallenge(r.Context(), req.AccountID, req.DeviceID, req.Challenge, req.Signature)
	if err != nil {
		// One generic message for every failure mode. Distinguishing "no such
		// device" from "bad signature" tells an attacker which half to work on.
		fail(w, http.StatusUnauthorized, "authentication failed")
		return
	}
	respond(w, http.StatusOK, map[string]any{"token": token, "expiresAt": expires.UTC()})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	token, _ := auth.BearerToken(r)
	sum := sha256Sum(token)
	if err := s.store.RevokeAuthToken(r.Context(), sum); err != nil {
		s.fail500(w, "revoke token", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------- calls ----------

// turnCredentials hands out a short-lived relay credential.
//
// Authenticated, because the relay is bandwidth this deployment pays for. But
// the credential itself is deliberately unlinkable to the caller — see
// internal/turn. The account that asked is checked here and then forgotten;
// nothing about it reaches the TURN server.
//
// A deployment with no relay answers 503 rather than pretending. The client
// needs to know, because "relay only until this call is answered" is a
// privacy guarantee it cannot keep without somewhere to relay through.
func (s *Server) turnCredentials(w http.ResponseWriter, r *http.Request) {
	cfg := turn.Config{Secret: s.cfg.TURNSecret, URLs: s.cfg.TURNURLs, TTL: s.cfg.TURNTTL}

	cred, err := cfg.Issue(time.Now())
	if errors.Is(err, turn.ErrNotConfigured) {
		fail(w, http.StatusServiceUnavailable, "this server has no TURN relay configured")
		return
	}
	if err != nil {
		s.fail500(w, "issue turn credential", err)
		return
	}

	// Not cacheable by anything in the middle: it is a bearer token.
	w.Header().Set("Cache-Control", "no-store")
	respond(w, http.StatusOK, cred)
}

// ---------- keys ----------

func (s *Server) putKeys(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	var up model.KeyUpload
	if !decode(w, r, &up) {
		return
	}
	if len(up.IdentityKey) != ed25519.PublicKeySize {
		fail(w, http.StatusBadRequest, "identityKey must be 32 bytes")
		return
	}
	// The signed prekeys must actually be signed by the identity key. The
	// server can't read messages, but it can refuse to hand out a bundle that
	// would fail verification on the client and confuse the user.
	if !ed25519.Verify(up.IdentityKey, up.SignedPreKey.PublicKey, up.SignedPreKey.Signature) {
		fail(w, http.StatusBadRequest, "signedPreKey signature invalid")
		return
	}
	if !ed25519.Verify(up.IdentityKey, up.SignedPQKey.PublicKey, up.SignedPQKey.Signature) {
		fail(w, http.StatusBadRequest, "signedPqPreKey signature invalid")
		return
	}
	if len(up.OneTimeKeys) > 200 || len(up.OneTimePQ) > 200 {
		fail(w, http.StatusBadRequest, "at most 200 one-time keys per upload")
		return
	}
	// A device rotating its identity key is a security event for everyone who
	// talks to it, not a routine update — it must re-register instead.
	dev, err := s.store.GetDevice(r.Context(), p.AccountID, p.DeviceID)
	if err != nil {
		s.fail500(w, "get device", err)
		return
	}
	if len(dev.IdentityKey) > 0 && !auth.ConstantTimeEqual(dev.IdentityKey, up.IdentityKey) {
		fail(w, http.StatusConflict, "identity key does not match the registered device key")
		return
	}
	if err := s.store.PutKeys(r.Context(), p.AccountID, p.DeviceID, &up); err != nil {
		s.fail500(w, "put keys", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) keyCount(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	ec, pq, err := s.store.PreKeyCount(r.Context(), p.AccountID, p.DeviceID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			respond(w, http.StatusOK, map[string]int{"oneTimePreKeys": 0, "oneTimePqPreKeys": 0})
			return
		}
		s.fail500(w, "prekey count", err)
		return
	}
	respond(w, http.StatusOK, map[string]int{"oneTimePreKeys": ec, "oneTimePqPreKeys": pq})
}

func (s *Server) getBundle(w http.ResponseWriter, r *http.Request) {
	accountID := r.PathValue("accountId")
	deviceID := r.PathValue("deviceId")
	b, err := s.store.TakeBundle(r.Context(), accountID, deviceID)
	if err != nil {
		if errors.Is(err, store.ErrNoPreKeys) || errors.Is(err, store.ErrNotFound) {
			fail(w, http.StatusNotFound, "no keys published for that device")
			return
		}
		s.fail500(w, "take bundle", err)
		return
	}
	respond(w, http.StatusOK, b)
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	devs, err := s.store.ListDevices(r.Context(), r.PathValue("accountId"))
	if err != nil {
		s.fail500(w, "list devices", err)
		return
	}
	// Strip LastSeen: when a contact was last online is metadata that no one
	// needs and that leaks a behavioural pattern.
	out := make([]map[string]any, 0, len(devs))
	for _, d := range devs {
		out = append(out, map[string]any{
			"deviceId":    d.DeviceID,
			"name":        d.Name,
			"identityKey": d.IdentityKey,
		})
	}
	respond(w, http.StatusOK, out)
}

// ---------- handles ----------

var handleRe = regexp.MustCompile(`^[a-z0-9_]{3,24}$`)

func (s *Server) setHandle(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	var req struct {
		Handle string `json:"handle"`
	}
	if !decode(w, r, &req) {
		return
	}
	h := strings.ToLower(strings.TrimSpace(req.Handle))
	if !handleRe.MatchString(h) {
		fail(w, http.StatusBadRequest, "handle must be 3-24 chars of a-z, 0-9, underscore")
		return
	}
	if err := s.store.SetHandle(r.Context(), p.AccountID, h); err != nil {
		if errors.Is(err, store.ErrHandleTaken) {
			fail(w, http.StatusConflict, "handle already taken")
			return
		}
		s.fail500(w, "set handle", err)
		return
	}

	// Record the binding in the log. A handle that resolves to a key nobody can
	// prove was published is a handle worth nothing, so a failure here fails
	// the request rather than being logged and ignored.
	if s.tlog != nil {
		device, err := s.store.GetDevice(r.Context(), p.AccountID, p.DeviceID)
		if err != nil {
			s.fail500(w, "get device for log entry", err)
			return
		}
		if _, err := s.tlog.Append(r.Context(), h, p.AccountID, device.IdentityKey); err != nil {
			s.fail500(w, "append log entry", err)
			return
		}
	}

	respond(w, http.StatusOK, map[string]string{"handle": h})
}

// resolveHandle answers with the binding *and* the proof it is in the log.
//
// `since` is the log size the caller last verified. Returning a consistency
// proof from there is what stops the server from quietly rewriting history:
// it must either show the same past, or fail.
func (s *Server) resolveHandle(w http.ResponseWriter, r *http.Request) {
	handle := r.PathValue("handle")
	a, err := s.store.GetAccountByHandle(r.Context(), handle)
	if err != nil {
		fail(w, http.StatusNotFound, "no such handle")
		return
	}

	response := map[string]any{"accountId": a.ID, "handle": a.Handle}

	if s.tlog != nil {
		since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
		if since < 0 {
			since = 0
		}
		entry, inclusion, consistency, head, err := s.tlog.Lookup(r.Context(), a.Handle, since)
		if err == nil {
			response["proof"] = map[string]any{
				"entry":       entry,
				"inclusion":   inclusion,
				"consistency": consistency,
				"head":        head,
			}
		} else {
			// A handle with no log entry is a server that has not caught up,
			// not a lie. The client decides whether to accept an unproven
			// binding; saying nothing would let it assume one was checked.
			s.log.Warn("no transparency proof for handle", "err", err)
		}
	}

	respond(w, http.StatusOK, response)
}

// transparencyHead publishes the current signed tree head.
//
// Unauthenticated on purpose: the log is only useful if anyone can watch it,
// including people who do not have an account.
func (s *Server) transparencyHead(w http.ResponseWriter, r *http.Request) {
	if s.tlog == nil {
		fail(w, http.StatusNotFound, "this server does not run a transparency log")
		return
	}
	respond(w, http.StatusOK, s.tlog.Head())
}

// ---------- mailboxes & messages ----------

func (s *Server) registerMailboxes(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	var req struct {
		Mailboxes []string `json:"mailboxes"`
		TTLHours  int      `json:"ttlHours"`
	}
	if !decode(w, r, &req) {
		return
	}
	// A device listens on one mailbox per active session per day, plus a
	// stable contact inbox. An account with many conversations legitimately
	// registers hundreds; the client batches, and this is the batch size.
	if len(req.Mailboxes) == 0 || len(req.Mailboxes) > 64 {
		fail(w, http.StatusBadRequest, "between 1 and 64 mailboxes per call")
		return
	}
	ttl := 48 * time.Hour
	if req.TTLHours > 0 && req.TTLHours <= 168 {
		ttl = time.Duration(req.TTLHours) * time.Hour
	}
	for _, mb := range req.Mailboxes {
		if len(mb) < 16 || len(mb) > 128 {
			fail(w, http.StatusBadRequest, "mailbox ids must be 16-128 chars")
			return
		}
		err := s.store.RegisterMailbox(r.Context(), &model.Mailbox{
			ID: mb, AccountID: p.AccountID, DeviceID: p.DeviceID,
			ExpiresAt: time.Now().Add(ttl).UTC(),
		})
		if err != nil {
			if errors.Is(err, store.ErrAlreadyExists) {
				fail(w, http.StatusConflict, "mailbox id collides with another account")
				return
			}
			s.fail500(w, "register mailbox", err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

type sendReq struct {
	Mailbox    string `json:"mailbox"`
	Ciphertext []byte `json:"ciphertext"`
}

func (s *Server) sendMessage(w http.ResponseWriter, r *http.Request) {
	var req sendReq
	if !decode(w, r, &req) {
		return
	}
	if req.Mailbox == "" || len(req.Ciphertext) == 0 {
		fail(w, http.StatusBadRequest, "mailbox and ciphertext are required")
		return
	}
	if int64(len(req.Ciphertext)) > s.cfg.MaxEnvelopeBytes {
		fail(w, http.StatusRequestEntityTooLarge, "envelope too large; use the attachment store")
		return
	}
	// Existence check only — we never tell the sender who owns the mailbox.
	if _, err := s.store.ResolveMailbox(r.Context(), req.Mailbox); err != nil {
		// Accepting silently would let a sender probe for live mailboxes; a
		// flat 404 for unknown ones is the lesser leak, and the client knows a
		// valid mailbox because the recipient told it one.
		fail(w, http.StatusNotFound, "unknown mailbox")
		return
	}
	e := &model.Envelope{
		ID:         id.New(),
		Mailbox:    req.Mailbox,
		Ciphertext: req.Ciphertext,
		ServerTS:   time.Now().UTC(),
	}
	if err := s.store.Enqueue(r.Context(), e); err != nil {
		s.fail500(w, "enqueue", err)
		return
	}
	// Deliver to any live socket. If nobody is listening the envelope waits in
	// the queue and the device is woken with a content-free notification.
	if !s.hub.Deliver(e) {
		s.wake(req.Mailbox)
	}
	respond(w, http.StatusAccepted, map[string]string{"id": e.ID})
}

// ---------- backup ----------

func (s *Server) putBackup(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	var req struct {
		Blob []byte `json:"blob"`
	}
	if !decode(w, r, &req) {
		return
	}
	if len(req.Blob) > 8<<20 {
		fail(w, http.StatusRequestEntityTooLarge, "backup blob exceeds 8 MiB")
		return
	}
	if err := s.store.PutBackup(r.Context(), p.AccountID, req.Blob); err != nil {
		s.fail500(w, "put backup", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getBackup(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	blob, err := s.store.GetBackup(r.Context(), p.AccountID)
	if err != nil {
		fail(w, http.StatusNotFound, "no backup stored")
		return
	}
	respond(w, http.StatusOK, map[string][]byte{"blob": blob})
}

// putRecoveryBlob publishes the blob a lost device is recovered from.
//
// Authenticated, because an account publishes its own. The lookup id comes
// from the client's recovery phrase and the server never learns the phrase;
// what it holds is a random-looking string and a ciphertext it cannot open.
func (s *Server) putRecoveryBlob(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	lookupID := r.PathValue("lookupId")
	if !validLookupID(lookupID) {
		fail(w, http.StatusBadRequest, "lookupId must be 32-64 hex characters")
		return
	}

	var req struct {
		Blob []byte `json:"blob"`
	}
	if !decode(w, r, &req) {
		return
	}
	// Smaller than the account backup on purpose: this one is readable without
	// authenticating, so it is the one worth keeping cheap to serve.
	if len(req.Blob) > 256<<10 {
		fail(w, http.StatusRequestEntityTooLarge, "recovery blob exceeds 256 KiB")
		return
	}

	err := s.store.PutRecoveryBlob(r.Context(), lookupID, p.AccountID, req.Blob)
	if errors.Is(err, store.ErrAlreadyExists) {
		fail(w, http.StatusConflict, "that recovery id belongs to another account")
		return
	}
	if err != nil {
		s.fail500(w, "put recovery blob", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// getRecoveryBlob serves it to anybody who knows the id.
//
// Unauthenticated, and it has to be: the caller is somebody who has lost the
// device that knew their account id, so there is nothing for them to
// authenticate with yet. What protects the blob is that the id is 128 bits
// derived from a phrase, and that the contents are encrypted under a
// different derivation of the same phrase. Guessing an id gets you ciphertext.
//
// It is a scraping surface and this deployment has no rate limiting — see
// docs/THREAT_MODEL.md.
func (s *Server) getRecoveryBlob(w http.ResponseWriter, r *http.Request) {
	lookupID := r.PathValue("lookupId")
	if !validLookupID(lookupID) {
		fail(w, http.StatusBadRequest, "lookupId must be 32-64 hex characters")
		return
	}

	blob, err := s.store.GetRecoveryBlob(r.Context(), lookupID)
	if err != nil {
		// Deliberately the same answer as a malformed id would get after
		// validation: whether an id exists is the one bit this endpoint has
		// to give up, and it should not give up more.
		fail(w, http.StatusNotFound, "no recovery blob stored")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	respond(w, http.StatusOK, map[string][]byte{"blob": blob})
}

var lookupIDPattern = regexp.MustCompile(`^[0-9a-f]{32,64}$`)

func validLookupID(id string) bool { return lookupIDPattern.MatchString(id) }

// ---------- device linking ----------

// createProvisioning opens a channel for a device that has no account yet.
func (s *Server) createProvisioning(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IdentityKey  []byte `json:"identityKey"`
		EphemeralKey []byte `json:"ephemeralKey"`
	}
	if !decode(w, r, &req) {
		return
	}
	if len(req.IdentityKey) != ed25519.PublicKeySize {
		fail(w, http.StatusBadRequest, "identityKey must be a 32-byte Ed25519 public key")
		return
	}
	if len(req.EphemeralKey) != 32 {
		fail(w, http.StatusBadRequest, "ephemeralKey must be 32 bytes")
		return
	}

	now := time.Now().UTC()
	p := &model.Provisioning{
		ID:           id.New(),
		IdentityKey:  req.IdentityKey,
		EphemeralKey: req.EphemeralKey,
		CreatedAt:    now,
		// Short: the window only has to last as long as it takes to point one
		// phone at another and compare six digits.
		ExpiresAt: now.Add(s.cfg.ProvisioningTTL),
	}
	if err := s.store.CreateProvisioning(r.Context(), p); err != nil {
		s.fail500(w, "create provisioning", err)
		return
	}
	respond(w, http.StatusCreated, map[string]any{"id": p.ID, "expiresAt": p.ExpiresAt})
}

// getProvisioning is polled by both sides: the approving device reads the new
// device's keys, and the new device waits for the approval to appear.
func (s *Server) getProvisioning(w http.ResponseWriter, r *http.Request) {
	p, err := s.store.GetProvisioning(r.Context(), r.PathValue("id"))
	if err != nil {
		fail(w, http.StatusNotFound, "no such provisioning channel")
		return
	}
	respond(w, http.StatusOK, p)
}

// addDevice registers a second device under the calling account.
//
// Authenticated as an existing device: adding a device to an account is
// something only that account's holder can do, and the identity key comes from
// the provisioning channel after the caller has checked it against the
// commitment it scanned.
func (s *Server) addDevice(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	var req struct {
		IdentityKey []byte `json:"identityKey"`
		Name        string `json:"name"`
	}
	if !decode(w, r, &req) {
		return
	}
	if len(req.IdentityKey) != ed25519.PublicKeySize {
		fail(w, http.StatusBadRequest, "identityKey must be a 32-byte Ed25519 public key")
		return
	}

	existing, err := s.store.ListDevices(r.Context(), p.AccountID)
	if err != nil {
		s.fail500(w, "list devices", err)
		return
	}
	// A cap, because every device multiplies the fanout of every message the
	// account receives, and an unbounded count is a way to make an account
	// expensive to talk to.
	if len(existing) >= 8 {
		fail(w, http.StatusConflict, "this account already has the maximum number of devices")
		return
	}
	for _, d := range existing {
		if auth.ConstantTimeEqual(d.IdentityKey, req.IdentityKey) {
			// Idempotent: a retried approval must not create a second device
			// for the same key.
			respond(w, http.StatusOK, map[string]string{"deviceId": d.DeviceID})
			return
		}
	}

	now := time.Now().UTC()
	device := &model.Device{
		AccountID:   p.AccountID,
		DeviceID:    id.New(),
		Name:        sanitizeName(req.Name),
		IdentityKey: req.IdentityKey,
		CreatedAt:   now,
		LastSeen:    now,
	}
	if err := s.store.UpsertDevice(r.Context(), device); err != nil {
		s.fail500(w, "add device", err)
		return
	}
	respond(w, http.StatusCreated, map[string]string{"deviceId": device.DeviceID})
}

// approveProvisioning stores the sealed approval for the new device to collect.
func (s *Server) approveProvisioning(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Approval []byte `json:"approval"`
	}
	if !decode(w, r, &req) {
		return
	}
	if len(req.Approval) == 0 || len(req.Approval) > 8192 {
		fail(w, http.StatusBadRequest, "approval must be between 1 and 8192 bytes")
		return
	}

	err := s.store.SetProvisioningApproval(r.Context(), r.PathValue("id"), req.Approval)
	if errors.Is(err, store.ErrAlreadyExists) {
		fail(w, http.StatusConflict, "this channel has already been approved")
		return
	}
	if err != nil {
		fail(w, http.StatusNotFound, "no such provisioning channel")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------- push ----------

func (s *Server) registerPushToken(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	var req struct {
		Platform string `json:"platform"`
		Token    string `json:"token"`
	}
	if !decode(w, r, &req) {
		return
	}
	switch req.Platform {
	case "expo", "apns", "fcm":
	default:
		fail(w, http.StatusBadRequest, "platform must be expo, apns or fcm")
		return
	}
	if len(req.Token) == 0 || len(req.Token) > 512 {
		fail(w, http.StatusBadRequest, "token must be between 1 and 512 characters")
		return
	}

	err := s.store.PutPushToken(r.Context(), &model.PushToken{
		AccountID: p.AccountID,
		DeviceID:  p.DeviceID,
		Platform:  req.Platform,
		Token:     req.Token,
		UpdatedAt: time.Now().UTC(),
	})
	if err != nil {
		s.fail500(w, "put push token", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// deletePushToken stops notifications for this device. Sign-out calls it, and
// so should any "mute this device" affordance — a user who turns off push
// should stop being a row in the table, not merely stop being notified.
func (s *Server) deletePushToken(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	if err := s.store.DeletePushToken(r.Context(), p.AccountID, p.DeviceID); err != nil {
		s.fail500(w, "delete push token", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// wake sends a content-free notification to the device that owns a mailbox.
//
// Runs detached from the request: a slow or unreachable push provider must not
// hold up the sender, who has already done their part. A failure here costs a
// delayed notification, not a lost message — the envelope is queued either way.
func (s *Server) wake(mailboxID string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		m, err := s.store.ResolveMailbox(ctx, mailboxID)
		if err != nil {
			return
		}
		token, err := s.store.GetPushToken(ctx, m.AccountID, m.DeviceID)
		if err != nil {
			// No token registered is the normal case for a desktop or a
			// device that declined notifications.
			return
		}
		if err := s.push.Notify(ctx, token); err != nil {
			s.log.Warn("push notify failed", "err", err)
		}
	}()
}

// transparencyConsistency proves that one tree size is a prefix of another.
//
// This is what makes gossip work: when two clients compare tree heads they
// have each verified, one of them asks for the proof that links the two. A
// server showing different logs to different people cannot produce it.
//
// Unauthenticated, like the rest of the log: cross-checking is most useful
// when anyone can do it.
func (s *Server) transparencyConsistency(w http.ResponseWriter, r *http.Request) {
	if s.tlog == nil {
		fail(w, http.StatusNotFound, "this server does not run a transparency log")
		return
	}
	first, err1 := strconv.ParseInt(r.URL.Query().Get("first"), 10, 64)
	second, err2 := strconv.ParseInt(r.URL.Query().Get("second"), 10, 64)
	if err1 != nil || err2 != nil || first < 0 || second < first {
		fail(w, http.StatusBadRequest, "first and second must be sizes with first <= second")
		return
	}

	proof, err := s.tlog.Consistency(int(first), int(second))
	if err != nil {
		fail(w, http.StatusBadRequest, "no such tree sizes in this log")
		return
	}
	respond(w, http.StatusOK, map[string]any{
		"first":  first,
		"second": second,
		"proof":  proof,
		"head":   s.tlog.Head(),
	})
}

// transparencyEntries lets an auditor read the log.
//
// A log nobody can enumerate is a log nobody can audit, and the entries are
// public bindings by design — this endpoint exposes nothing the lookup
// endpoint does not already.
func (s *Server) transparencyEntries(w http.ResponseWriter, r *http.Request) {
	if s.tlog == nil {
		fail(w, http.StatusNotFound, "this server does not run a transparency log")
		return
	}
	from, _ := strconv.ParseInt(r.URL.Query().Get("from"), 10, 64)
	to, err := strconv.ParseInt(r.URL.Query().Get("to"), 10, 64)
	if err != nil || from < 0 || to < from {
		fail(w, http.StatusBadRequest, "from and to must be indices with from <= to")
		return
	}
	// Bounded so one request cannot ask the server to serialise the whole log.
	if to-from > 1000 {
		to = from + 1000
	}
	// Clamp to what exists. An auditor walking the log does not know where it
	// ends, and answering "bad request" to a reasonable read is a good way to
	// make sure nobody audits anything.
	size := s.tlog.Size()
	if to > size {
		to = size
	}
	if from > size {
		from = size
	}

	entries, err := s.tlog.Entries(r.Context(), from, to)
	if err != nil {
		fail(w, http.StatusBadRequest, "no such range in this log")
		return
	}
	if entries == nil {
		entries = []*transparency.Entry{}
	}
	respond(w, http.StatusOK, map[string]any{"entries": entries, "head": s.tlog.Head()})
}

// ---------- attachments ----------

// uploadAttachment stores an encrypted blob and returns an ID.
//
// The body is raw ciphertext, not JSON: base64 would inflate a photo by a
// third for no benefit, since the server treats the bytes as opaque either
// way. No owner is recorded — see the note on model.Attachment.
func (s *Server) uploadAttachment(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxAttachmentBytes)
	ciphertext, err := io.ReadAll(r.Body)
	if err != nil {
		fail(w, http.StatusRequestEntityTooLarge, "attachment exceeds the size limit")
		return
	}
	if len(ciphertext) == 0 {
		fail(w, http.StatusBadRequest, "attachment is empty")
		return
	}

	now := time.Now().UTC()
	a := &model.Attachment{
		ID:         id.New(),
		Ciphertext: ciphertext,
		Size:       int64(len(ciphertext)),
		CreatedAt:  now,
		ExpiresAt:  now.Add(s.cfg.AttachmentTTL),
	}
	if err := s.store.PutAttachment(r.Context(), a); err != nil {
		s.fail500(w, "put attachment", err)
		return
	}
	respond(w, http.StatusCreated, map[string]any{
		"id":        a.ID,
		"size":      a.Size,
		"expiresAt": a.ExpiresAt,
	})
}

func (s *Server) downloadAttachment(w http.ResponseWriter, r *http.Request) {
	a, err := s.store.GetAttachment(r.Context(), r.PathValue("id"))
	if err != nil {
		// Expired and never-existed are the same answer on purpose: telling
		// them apart would confirm that a given ID was once real.
		fail(w, http.StatusNotFound, "no such attachment")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(a.Size, 10))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(a.Ciphertext)
}

// ---------- websocket ----------

func (s *Server) websocket(w http.ResponseWriter, r *http.Request) {
	// React Native's WebSocket cannot set an Authorization header, so the
	// token rides in the subprotocol slot: ["tildra.v1", "bearer.<token>"].
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols: []string{"tildra.v1"},
		// Same-origin checking is meaningless for a native client and this API
		// is not cookie-authenticated, so there is no CSRF surface to protect.
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}

	token := ""
	for _, p := range strings.Split(r.Header.Get("Sec-WebSocket-Protocol"), ",") {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, "bearer.") {
			token = strings.TrimPrefix(p, "bearer.")
		}
	}
	if token == "" {
		_ = ws.Close(websocket.StatusPolicyViolation, "missing token")
		return
	}
	principal, err := s.auth.Authenticate(r.Context(), token)
	if err != nil {
		_ = ws.Close(websocket.StatusPolicyViolation, "unauthorized")
		return
	}
	mailboxes, err := s.store.MailboxesFor(r.Context(), principal.AccountID, principal.DeviceID)
	if err != nil {
		_ = ws.Close(websocket.StatusInternalError, "")
		return
	}
	if len(mailboxes) == 0 {
		_ = ws.Close(websocket.StatusPolicyViolation, "no mailboxes registered")
		return
	}
	s.hub.Serve(r.Context(), ws, principal.AccountID, principal.DeviceID, mailboxes)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	respond(w, http.StatusOK, map[string]string{"status": "ok"})
}
