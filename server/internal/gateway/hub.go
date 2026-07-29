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

	"github.com/coder/websocket"
	"github.com/tildra/tildra/server/internal/model"
	"github.com/tildra/tildra/server/internal/store"
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
	mailboxes []string

	send chan []byte
	once sync.Once
	done chan struct{}
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

func (h *Hub) register(c *Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, mb := range c.mailboxes {
		set := h.byMailbx[mb]
		if set == nil {
			set = map[*Conn]struct{}{}
			h.byMailbx[mb] = set
		}
		set[c] = struct{}{}
	}
}

func (h *Hub) unregister(c *Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, mb := range c.mailboxes {
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
		mailboxes: mailboxes,
		send:      make(chan []byte, sendBuffer),
		done:      make(chan struct{}),
	}
	h.register(c)
	defer h.unregister(c)
	defer c.close()

	// Drain anything that arrived while this device was away, before going
	// live. Ordering matters: a client that sees a new message before its
	// backlog would ratchet out of order.
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
				h.log.Warn("backlog exceeds send buffer", "device", deviceID)
			}
		}
	}

	go c.writeLoop(ctx, h.log)
	c.readLoop(ctx, h)
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

// clientFrame is what a device may send up the socket. Sending messages goes
// over HTTP; the socket is for acking delivery, which must be fast and
// frequent.
type clientFrame struct {
	Type    string   `json:"type"`
	Mailbox string   `json:"mailbox"`
	IDs     []string `json:"ids"`
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
		if f.Type != "ack" || len(f.IDs) == 0 {
			continue
		}
		// A device may only ack mailboxes it owns. Without this check, any
		// authenticated account could delete anyone else's undelivered mail.
		owned := false
		for _, mb := range c.mailboxes {
			if mb == f.Mailbox {
				owned = true
				break
			}
		}
		if !owned {
			h.log.Warn("ack for unowned mailbox", "account", c.accountID, "mailbox", f.Mailbox)
			continue
		}
		if err := h.store.Ack(ctx, f.Mailbox, f.IDs); err != nil {
			h.log.Error("ack failed", "err", err)
		}
	}
}

func (c *Conn) close() {
	c.once.Do(func() {
		close(c.done)
		_ = c.ws.Close(websocket.StatusNormalClosure, "")
	})
}
