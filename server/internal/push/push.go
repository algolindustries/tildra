// Package push wakes devices that are not connected.
//
// The single most important property here is what a notification does *not*
// contain. There is no sender, no conversation, no preview, and no count —
// only a signal that something arrived. Apple and Google necessarily learn
// that a device was woken and when; they must not also learn who is talking
// to whom, and a payload with a name in it would hand them exactly that.
//
// The client decrypts locally and replaces the placeholder with a real
// notification, so the user still sees who wrote to them. That work happens on
// the device, where the keys are.
package push

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/tildra/tildra/server/internal/model"
)

// Notifier delivers a content-free wake signal to one device.
type Notifier interface {
	Notify(ctx context.Context, token *model.PushToken) error
}

// Nop is the default. A server with no push provider configured still works —
// clients receive on reconnect — so this is a legitimate deployment, not a
// broken one.
type Nop struct{}

func (Nop) Notify(context.Context, *model.PushToken) error { return nil }

// Expo sends through Expo's push service, which fronts APNs and FCM.
//
// Chosen because the client is an Expo app and this avoids holding Apple and
// Google credentials on the server. A deployment that would rather talk to
// APNs and FCM directly implements Notifier and swaps it in.
type Expo struct {
	Endpoint string
	Client   *http.Client
	Log      *slog.Logger
}

func NewExpo(log *slog.Logger) *Expo {
	return &Expo{
		Endpoint: "https://exp.host/--/api/v2/push/send",
		Client:   &http.Client{Timeout: 10 * time.Second},
		Log:      log,
	}
}

type expoMessage struct {
	To       string         `json:"to"`
	Title    string         `json:"title"`
	Body     string         `json:"body"`
	Sound    string         `json:"sound"`
	Priority string         `json:"priority"`
	Data     map[string]any `json:"data"`
}

func (e *Expo) Notify(ctx context.Context, token *model.PushToken) error {
	// Deliberately generic. The client rewrites this once it has decrypted the
	// message; until then neither the push service nor a lock screen visible
	// across a room reveals anything.
	payload := []expoMessage{{
		To:       token.Token,
		Title:    "Tildra",
		Body:     "New message",
		Sound:    "default",
		Priority: "high",
		Data:     map[string]any{"type": "wake"},
	}}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := e.Client.Do(req)
	if err != nil {
		return fmt.Errorf("push send: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("push service returned %d", resp.StatusCode)
	}
	return nil
}

// Recording is a Notifier for tests: it remembers what it was asked to send
// and never touches the network.
type Recording struct {
	Sent []model.PushToken
	Err  error
}

func (r *Recording) Notify(_ context.Context, token *model.PushToken) error {
	if r.Err != nil {
		return r.Err
	}
	r.Sent = append(r.Sent, *token)
	return nil
}
