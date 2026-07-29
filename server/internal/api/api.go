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
)

// Server wires the store, authenticator, hub and notifier into an http.Handler.
type Server struct {
	cfg   *config.Config
	store store.Store
	auth  *auth.Authenticator
	hub   *gateway.Hub
	push  push.Notifier
	log   *slog.Logger
}

func New(
	cfg *config.Config,
	s store.Store,
	a *auth.Authenticator,
	h *gateway.Hub,
	notifier push.Notifier,
	log *slog.Logger,
) *Server {
	if notifier == nil {
		notifier = push.Nop{}
	}
	return &Server{cfg: cfg, store: s, auth: a, hub: h, push: notifier, log: log}
}

// Handler builds the route table.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Unauthenticated: registration and the login handshake.
	mux.HandleFunc("POST /v1/accounts", s.createAccount)
	mux.HandleFunc("GET /v1/auth/challenge", s.authChallenge)
	mux.HandleFunc("POST /v1/auth/token", s.authToken)
	mux.HandleFunc("GET /v1/handles/{handle}", s.resolveHandle)
	mux.HandleFunc("GET /healthz", s.health)

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
	authed.HandleFunc("PUT /v1/push", s.registerPushToken)
	authed.HandleFunc("DELETE /v1/push", s.deletePushToken)
	authed.HandleFunc("POST /v1/attachments", s.uploadAttachment)
	authed.HandleFunc("GET /v1/attachments/{id}", s.downloadAttachment)
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
	respond(w, http.StatusOK, map[string]string{"handle": h})
}

func (s *Server) resolveHandle(w http.ResponseWriter, r *http.Request) {
	a, err := s.store.GetAccountByHandle(r.Context(), r.PathValue("handle"))
	if err != nil {
		fail(w, http.StatusNotFound, "no such handle")
		return
	}
	// A handle resolves to an account ID and nothing else. Verifying that the
	// ID belongs to the human you meant is the safety-number check's job.
	respond(w, http.StatusOK, map[string]string{"accountId": a.ID, "handle": a.Handle})
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
