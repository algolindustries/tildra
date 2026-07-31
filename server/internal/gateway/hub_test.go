package gateway_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/tildra/tildra/server/internal/gateway"
	"github.com/tildra/tildra/server/internal/model"
	"github.com/tildra/tildra/server/internal/store/memory"
)

// The real-time delivery layer, which had no tests of its own — only whatever
// the client integration suites happened to exercise through it.
//
// Two of its rules are written into the code as warnings about what would
// happen without them, and both are about one authenticated account reaching
// another's mail: a subscribe is checked against the store rather than the
// client's claim, and an ack is refused for a mailbox the connection does not
// own, "without this check, any authenticated account could delete anyone
// else's undelivered mail". Neither had a test.
//
// The socket is a real one over httptest rather than a double. `Conn` is built
// inside `Serve` and closes the websocket on the slow-consumer path, so a nil
// double would only prove that a nil pointer panics.

const (
	accountID = "ACCT0123456789ABCDEFGHJKMN"
	deviceID  = "DEV0123456789ABCDEFGHJKMNP"

	otherAccount = "ACCTZZZZZZZZZZZZZZZZZZZZZZ"
	otherDevice  = "DEVZZZZZZZZZZZZZZZZZZZZZZZ"
)

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// mailbox registers one in the store, owned by the given device.
func mailbox(t *testing.T, s *memory.Store, id, account, device string) string {
	t.Helper()
	err := s.RegisterMailbox(context.Background(), &model.Mailbox{
		ID:        id,
		AccountID: account,
		DeviceID:  device,
		ExpiresAt: time.Now().Add(48 * time.Hour),
	})
	if err != nil {
		t.Fatalf("register mailbox %s: %v", id, err)
	}
	return id
}

func enqueue(t *testing.T, s *memory.Store, mailboxID, id string) {
	t.Helper()
	err := s.Enqueue(context.Background(), &model.Envelope{
		ID:         id,
		Mailbox:    mailboxID,
		Ciphertext: []byte("sealed-" + id),
		ServerTS:   time.Now(),
	})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
}

type session struct {
	hub  *gateway.Hub
	ws   *websocket.Conn
	stop func()
}

// connect runs one device's socket against a real server.
func connect(t *testing.T, s *memory.Store, mailboxes ...string) *session {
	t.Helper()
	hub := gateway.NewHub(s, quietLog())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		hub.Serve(r.Context(), ws, accountID, deviceID, mailboxes)
	}))

	ws, _, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		srv.Close()
		t.Fatalf("dial: %v", err)
	}

	return &session{hub: hub, ws: ws, stop: func() {
		_ = ws.Close(websocket.StatusNormalClosure, "")
		srv.Close()
	}}
}

// nextEnvelope reads frames until one carries an envelope, or the deadline
// passes. Frames that are not messages (pings, acks) are skipped rather than
// failing the read.
func (s *session) nextEnvelope(t *testing.T, within time.Duration) *model.Envelope {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), within)
	defer cancel()
	for {
		_, data, err := s.ws.Read(ctx)
		if err != nil {
			return nil
		}
		var f gateway.Frame
		if err := json.Unmarshal(data, &f); err != nil {
			continue
		}
		if f.Envelope != nil {
			return f.Envelope
		}
	}
}

// deliverWhenListening retries until the hub reports a listener.
//
// `connect` returns as soon as the client has dialled; the server's handler
// may not have reached `register` yet. Without this the negatives below are
// meaningless — "nobody is listening" is also what a socket that has not
// finished connecting looks like.
func deliverWhenListening(t *testing.T, s *session, e *model.Envelope) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s.hub.Deliver(e) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the hub never reported a listener for %s", e.Mailbox)
}

// silence asserts nothing arrives. Only meaningful after a positive event has
// already been observed on the same socket — see the call sites.
func (s *session) silence(t *testing.T, within time.Duration) {
	t.Helper()
	if e := s.nextEnvelope(t, within); e != nil {
		t.Fatalf("an envelope arrived that should not have: %s on %s", e.ID, e.Mailbox)
	}
}

// ---------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------

func TestBacklogIsDrainedOnConnect(t *testing.T) {
	// A device that was offline gets its mail by draining the queue, and the
	// hub holds no message state of its own.
	s := memory.New()
	mb := mailbox(t, s, "mb-own", accountID, deviceID)
	enqueue(t, s, mb, "e1")
	enqueue(t, s, mb, "e2")

	sess := connect(t, s, mb)
	defer sess.stop()

	for _, want := range []string{"e1", "e2"} {
		got := sess.nextEnvelope(t, 3*time.Second)
		if got == nil || got.ID != want {
			t.Fatalf("want %s, got %+v", want, got)
		}
	}
}

func TestDeliverReachesALiveListener(t *testing.T) {
	s := memory.New()
	mb := mailbox(t, s, "mb-own", accountID, deviceID)

	sess := connect(t, s, mb)
	defer sess.stop()

	// The hub reports whether anyone was listening; the caller uses that to
	// decide whether to fall back to a push notification.
	deliverWhenListening(t, sess, &model.Envelope{ID: "live", Mailbox: mb, ServerTS: time.Now()})
	if got := sess.nextEnvelope(t, 3*time.Second); got == nil || got.ID != "live" {
		t.Fatalf("want the live envelope, got %+v", got)
	}
}

func TestDeliverReportsNobodyForAMailboxNoOneHolds(t *testing.T) {
	// Saying yes here would drop the envelope on the floor: the caller leaves
	// it queued precisely because Deliver said no.
	s := memory.New()
	mb := mailbox(t, s, "mb-own", accountID, deviceID)
	sess := connect(t, s, mb)
	defer sess.stop()

	// Establish that the socket is registered first, or "false" below is just
	// a connection that had not finished.
	deliverWhenListening(t, sess, &model.Envelope{ID: "ready", Mailbox: mb, ServerTS: time.Now()})

	if sess.hub.Deliver(&model.Envelope{ID: "x", Mailbox: "mb-nobody", ServerTS: time.Now()}) {
		t.Fatal("Deliver claimed a listener for a mailbox nobody registered")
	}
}

func TestAClosedSocketStopsBeingAListener(t *testing.T) {
	s := memory.New()
	mb := mailbox(t, s, "mb-own", accountID, deviceID)
	sess := connect(t, s, mb)

	// Prove the socket is live first, so the negative below means something.
	deliverWhenListening(t, sess, &model.Envelope{ID: "before", Mailbox: mb, ServerTS: time.Now()})
	if got := sess.nextEnvelope(t, 3*time.Second); got == nil {
		t.Fatal("the live envelope never arrived")
	}

	sess.stop()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !sess.hub.Deliver(&model.Envelope{ID: "after", Mailbox: mb, ServerTS: time.Now()}) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the hub still claims a listener for a closed socket")
}

// ---------------------------------------------------------------------------
// Subscribe: ownership comes from the store, never from the client's claim
// ---------------------------------------------------------------------------

func TestSubscribeToAnOwnedMailboxStartsDelivery(t *testing.T) {
	// Every new conversation derives a mailbox, so a socket frozen to the ones
	// it opened with would silently stop receiving from anyone met since.
	s := memory.New()
	opened := mailbox(t, s, "mb-own", accountID, deviceID)
	later := mailbox(t, s, "mb-later", accountID, deviceID)
	enqueue(t, s, later, "waiting")

	sess := connect(t, s, opened)
	defer sess.stop()

	subscribe(t, sess, later)

	// The backlog of the newly subscribed mailbox comes too.
	if got := sess.nextEnvelope(t, 3*time.Second); got == nil || got.ID != "waiting" {
		t.Fatalf("want the queued envelope, got %+v", got)
	}
	deliverWhenListening(t, sess, &model.Envelope{ID: "fresh", Mailbox: later, ServerTS: time.Now()})
}

func TestSubscribeToSomeoneElsesMailboxIsRefused(t *testing.T) {
	// The client asks for a mailbox the store says belongs to another device.
	// Granting it would turn one authenticated account into a listener on
	// another's mail.
	s := memory.New()
	opened := mailbox(t, s, "mb-own", accountID, deviceID)
	theirs := mailbox(t, s, "mb-theirs", otherAccount, otherDevice)
	enqueue(t, s, theirs, "not-yours")

	// A second mailbox this device does own, subscribed after the refused one.
	// The read loop takes frames in order, so the moment delivery works here,
	// the refused subscribe has already been processed — which is what makes
	// the negative below a fact rather than a race with an unread frame.
	alsoMine := mailbox(t, s, "mb-mine-2", accountID, deviceID)

	sess := connect(t, s, opened)
	defer sess.stop()

	subscribe(t, sess, theirs)
	subscribe(t, sess, alsoMine)
	deliverWhenListening(t, sess, &model.Envelope{ID: "mine", Mailbox: alsoMine, ServerTS: time.Now()})
	if got := sess.nextEnvelope(t, 3*time.Second); got == nil || got.ID != "mine" {
		t.Fatalf("want the owned envelope, got %+v", got)
	}

	// The refused mailbox has no listener, and its backlog never came.
	if sess.hub.Deliver(&model.Envelope{ID: "theirs", Mailbox: theirs, ServerTS: time.Now()}) {
		t.Fatal("the hub registered a listener on someone else's mailbox")
	}
	sess.silence(t, 300*time.Millisecond)
}

func TestSubscribeToAMailboxNobodyRegisteredIsRefused(t *testing.T) {
	s := memory.New()
	opened := mailbox(t, s, "mb-own", accountID, deviceID)
	alsoMine := mailbox(t, s, "mb-mine-2", accountID, deviceID)
	sess := connect(t, s, opened)
	defer sess.stop()

	subscribe(t, sess, "mb-invented")
	subscribe(t, sess, alsoMine)
	deliverWhenListening(t, sess, &model.Envelope{ID: "ready", Mailbox: alsoMine, ServerTS: time.Now()})

	if sess.hub.Deliver(&model.Envelope{ID: "x", Mailbox: "mb-invented", ServerTS: time.Now()}) {
		t.Fatal("the hub registered a listener on an unregistered mailbox")
	}
}

// ---------------------------------------------------------------------------
// Ack
// ---------------------------------------------------------------------------

func TestAckDeletesOnlyFromAMailboxTheConnectionOwns(t *testing.T) {
	// The rule the code states: without the ownership check, any authenticated
	// account could delete anyone else's undelivered mail.
	s := memory.New()
	opened := mailbox(t, s, "mb-own", accountID, deviceID)
	theirs := mailbox(t, s, "mb-theirs", otherAccount, otherDevice)
	enqueue(t, s, opened, "mine")
	enqueue(t, s, theirs, "not-yours")

	sess := connect(t, s, opened)
	defer sess.stop()

	// Drain our own backlog so the ack below is the only thing in flight.
	if got := sess.nextEnvelope(t, 3*time.Second); got == nil || got.ID != "mine" {
		t.Fatalf("want our own backlog, got %+v", got)
	}

	ack(t, sess, theirs, "not-yours")
	ack(t, sess, opened, "mine")

	// The ack for our own mailbox is what tells us the server has processed
	// both frames, so the other one's survival is not a race.
	waitForQueue(t, s, opened, 0)

	left, err := s.Dequeue(context.Background(), theirs, 100)
	if err != nil {
		t.Fatalf("dequeue: %v", err)
	}
	if len(left) != 1 {
		t.Fatalf("someone else's mail was deleted by our ack: %d left", len(left))
	}
}

// ---------------------------------------------------------------------------
// Helpers that speak the client frame format
// ---------------------------------------------------------------------------

func subscribe(t *testing.T, s *session, mailboxes ...string) {
	t.Helper()
	send(t, s, map[string]any{"type": "subscribe", "mailboxes": mailboxes})
}

func ack(t *testing.T, s *session, mailboxID string, ids ...string) {
	t.Helper()
	send(t, s, map[string]any{"type": "ack", "mailbox": mailboxID, "ids": ids})
}

func send(t *testing.T, s *session, frame map[string]any) {
	t.Helper()
	data, err := json.Marshal(frame)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.ws.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func waitForQueue(t *testing.T, s *memory.Store, mailboxID string, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		left, err := s.Dequeue(context.Background(), mailboxID, 100)
		if err != nil {
			t.Fatalf("dequeue: %v", err)
		}
		if len(left) == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("mailbox %s never reached %d envelopes", mailboxID, want)
}
