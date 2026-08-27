// Package gateway is the real-time delivery layer.
//
// A device opens one WebSocket, tells the hub which mailboxes it owns, and
// receives envelopes as they arrive. The hub holds no message state — it is a
// notifier over the store's queue, so a device that was offline gets the same
// messages by draining the queue on reconnect.
package gateway

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/algolindustries/tildra/server/internal/model"
	"github.com/algolindustries/tildra/server/internal/store"
	"github.com/coder/websocket"
)

// Hub tracks which live connections are listening to which mailboxes.
type Hub struct {
	store store.Store
	log   *slog.Logger

	mu       sync.RWMutex
	byMailbx map[string]map[*Conn]struct{}
}

func NewHub(s store.Store, log *slog.Logger) *Hub {
	return &Hub{store: s, log: log, byMailbx: map[string]map[*Conn]struct{}{}}
}

// Conn is one authenticated device socket.
type Conn struct {
	ws        *websocket.Conn
	accountID string
	deviceID  string

	// mu guards mailboxes, which the read loop extends while Deliver reads it.
	mu        sync.RWMutex
	mailboxes map[string]struct{}

	send chan []byte
	once sync.Once
	done chan struct{}
}

func (c *Conn) owns(mailbox string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.mailboxes[mailbox]
	return ok
}

func (c *Conn) mailboxList() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]string, 0, len(c.mailboxes))
	for mb := range c.mailboxes {
		out = append(out, mb)
	}
	return out
}

// Frame is the envelope pushed down the socket. `type` discriminates:
// "message" carries an envelope, "ack" confirms a send, "error" explains a
// refusal, "ping" keeps middleboxes from reaping the connection.
type Frame struct {
	Type     string          `json:"type"`
	Envelope *model.Envelope `json:"envelope,omitempty"`
	Error    string          `json:"error,omitempty"`
	ID       string          `json:"id,omitempty"`
}

func (h *Hub) register(c *Conn, mailboxes []string) {
	c.mu.Lock()
	for _, mb := range mailboxes {
		c.mailboxes[mb] = struct{}{}
	}
	c.mu.Unlock()

	h.mu.Lock()
	defer h.mu.Unlock()
	for _, mb := range mailboxes {
		set := h.byMailbx[mb]
		if set == nil {
			set = map[*Conn]struct{}{}
			h.byMailbx[mb] = set
		}
		set[c] = struct{}{}
	}
}

func (h *Hub) unregister(c *Conn) {
	mailboxes := c.mailboxList()
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, mb := range mailboxes {
		if set := h.byMailbx[mb]; set != nil {
			delete(set, c)
			if len(set) == 0 {
				delete(h.byMailbx, mb)
			}
		}
	}
}

// Deliver pushes an envelope to every live listener on its mailbox. It
// reports whether anyone was listening; if nobody was, the caller leaves the
// envelope queued for the next connect (and may fire a push notification).
func (h *Hub) Deliver(e *model.Envelope) bool {
	h.mu.RLock()
	conns := make([]*Conn, 0, 2)
	for c := range h.byMailbx[e.Mailbox] {
		conns = append(conns, c)
	}
	h.mu.RUnlock()

	if len(conns) == 0 {
		return false
	}
	payload, err := json.Marshal(Frame{Type: "message", Envelope: e})
	if err != nil {
		h.log.Error("marshal envelope", "err", err)
		return false
	}
	delivered := false
	for _, c := range conns {
		select {
		case c.send <- payload:
			delivered = true
		default:
			// The client is not draining. Rather than buffer without bound —
			// which is how a messaging server turns into an OOM — we drop the
			// socket. The envelope stays in the queue and is picked up on
			// reconnect, so nothing is lost.
			h.log.Warn("slow consumer, closing socket", "account", c.accountID, "device", c.deviceID)
			c.close()
		}
	}
	return delivered
}

const (
	writeTimeout = 10 * time.Second
	pingInterval = 30 * time.Second
	sendBuffer   = 64
)

// Serve runs the read and write loops for one connection until it closes.
func (h *Hub) Serve(ctx context.Context, ws *websocket.Conn, accountID, deviceID string, mailboxes []string) {
	c := &Conn{
		ws:        ws,
		accountID: accountID,
		deviceID:  deviceID,
		mailboxes: map[string]struct{}{},
		send:      make(chan []byte, sendBuffer),
		done:      make(chan struct{}),
	}
	h.register(c, mailboxes)
	defer h.unregister(c)
	defer c.close()

	// Drain anything that arrived while this device was away, before going
	// live. Ordering matters: a client that sees a new message before its
	// backlog would ratchet out of order.
	h.drain(ctx, c, mailboxes)

	go c.writeLoop(ctx, h.log)
	c.readLoop(ctx, h)
}

func (h *Hub) drain(ctx context.Context, c *Conn, mailboxes []string) {
	for _, mb := range mailboxes {
		queued, err := h.store.Dequeue(ctx, mb, 500)
		if err != nil {
			h.log.Error("dequeue backlog", "mailbox", mb, "err", err)
			continue
		}
		for _, e := range queued {
			payload, err := json.Marshal(Frame{Type: "message", Envelope: e})
			if err != nil {
				continue
			}
			select {
			case c.send <- payload:
			default:
				h.log.Warn("backlog exceeds send buffer", "device", c.deviceID)
			}
		}
	}
}

// subscribe adds mailboxes to a live connection.
//
// Without this a socket is frozen to whatever mailboxes existed when it was
// opened. Since a mailbox is derived per session, every new conversation
// creates one — so a long-lived socket would silently stop receiving from
// anyone it met after connecting, and the messages would only surface on the
// next reconnect.
func (h *Hub) subscribe(ctx context.Context, c *Conn, mailboxes []string) {
	owned := make([]string, 0, len(mailboxes))
	for _, mb := range mailboxes {
		if c.owns(mb) {
			continue
		}
		// Ownership comes from the store, never from the client's claim.
		m, err := h.store.ResolveMailbox(ctx, mb)
		if err != nil {
			continue
		}
		if m.AccountID != c.accountID || m.DeviceID != c.deviceID {
			h.log.Warn("subscribe to unowned mailbox refused",
				"account", c.accountID, "device", c.deviceID)
			continue
		}
		owned = append(owned, mb)
	}
	if len(owned) == 0 {
		return
	}
	h.register(c, owned)
	h.drain(ctx, c, owned)
}

func (c *Conn) writeLoop(ctx context.Context, log *slog.Logger) {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		case msg := <-c.send:
			wctx, cancel := context.WithTimeout(ctx, writeTimeout)
			err := c.ws.Write(wctx, websocket.MessageText, msg)
			cancel()
			if err != nil {
				log.Debug("socket write failed", "err", err)
				c.close()
				return
			}
		case <-ticker.C:
			pctx, cancel := context.WithTimeout(ctx, writeTimeout)
			err := c.ws.Ping(pctx)
			cancel()
			if err != nil {
				c.close()
				return
			}
		}
	}
}

// clientFrame is what a device may send up the socket: acks, and subscriptions
// to mailboxes created after the socket opened. Sending messages goes over
// HTTP.
type clientFrame struct {
	Type      string   `json:"type"`
	Mailbox   string   `json:"mailbox"`
	IDs       []string `json:"ids"`
	Mailboxes []string `json:"mailboxes"`
}

func (c *Conn) readLoop(ctx context.Context, h *Hub) {
	for {
		_, data, err := c.ws.Read(ctx)
		if err != nil {
			return
		}
		var f clientFrame
		if err := json.Unmarshal(data, &f); err != nil {
			continue
		}

		switch f.Type {
		case "ack":
			if len(f.IDs) == 0 {
				continue
			}
			// A device may only ack mailboxes it owns. Without this check, any
			// authenticated account could delete anyone else's undelivered mail.
			if !c.owns(f.Mailbox) {
				h.log.Warn("ack for unowned mailbox", "account", c.accountID, "mailbox", f.Mailbox)
				continue
			}
			if err := h.store.Ack(ctx, f.Mailbox, f.IDs); err != nil {
				h.log.Error("ack failed", "err", err)
			}

		case "subscribe":
			if len(f.Mailboxes) == 0 || len(f.Mailboxes) > 256 {
				continue
			}
			h.subscribe(ctx, c, f.Mailboxes)
		}
	}
}

func (c *Conn) close() {
	c.once.Do(func() {
		close(c.done)
		_ = c.ws.Close(websocket.StatusNormalClosure, "")
	})
}
