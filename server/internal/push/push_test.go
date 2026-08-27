package push_test

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

	"github.com/algolindustries/tildra/server/internal/model"
	"github.com/algolindustries/tildra/server/internal/push"
)

// token carries the identifiers a careless payload would leak. None of them
// belong in a notification.
func token() *model.PushToken {
	return &model.PushToken{
		AccountID: "ACCOUNTIDTHATMUSTNOTLEAK00",
		DeviceID:  "DEVICEIDTHATMUSTNOTLEAK",
		Platform:  "expo",
		Token:     "ExponentPushToken[abc123]",
		UpdatedAt: time.Unix(1_770_000_000, 0),
	}
}

// capture runs a notifier against a fake push service and returns the exact
// bytes it sent.
func capture(t *testing.T, status int) string {
	t.Helper()
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer server.Close()

	notifier := push.NewExpo(slog.New(slog.NewTextHandler(io.Discard, nil)))
	notifier.Endpoint = server.URL

	err := notifier.Notify(context.Background(), token())
	if status < 300 && err != nil {
		t.Fatalf("Notify: %v", err)
	}
	return body
}

func TestPayloadCarriesNothingAboutTheMessage(t *testing.T) {
	// The claim in the README and the threat model: Apple and Google learn
	// that a device was woken and when, and must not also learn who is talking
	// to whom. This is the test that stops somebody adding a preview "for UX"
	// and nothing noticing.
	body := capture(t, http.StatusOK)

	var sent []map[string]any
	if err := json.Unmarshal([]byte(body), &sent); err != nil {
		t.Fatalf("payload is not the array Expo expects: %v\n%s", err, body)
	}
	if len(sent) != 1 {
		t.Fatalf("sent %d messages, want 1", len(sent))
	}

	message := sent[0]
	if message["title"] != "Tildra" || message["body"] != "New message" {
		t.Fatalf("title/body are not the fixed placeholder: %v", message)
	}

	data, _ := message["data"].(map[string]any)
	if len(data) != 1 || data["type"] != "wake" {
		t.Fatalf("data carries something other than a wake signal: %v", data)
	}

	// Every field a notification could plausibly grow, named so a failure
	// says which one appeared.
	for _, forbidden := range []string{
		"sender", "senderAccountId", "from", "preview", "text", "conversation",
		"conversationId", "accountId", "deviceId", "count", "badge", "unread",
	} {
		if _, present := message[forbidden]; present {
			t.Fatalf("payload grew a %q field", forbidden)
		}
	}
}

func TestPayloadDoesNotEchoTheAccountOrDevice(t *testing.T) {
	// The notifier is handed a token that knows the account and the device.
	// Only the opaque push token may travel.
	body := capture(t, http.StatusOK)

	for _, secret := range []string{token().AccountID, token().DeviceID} {
		if strings.Contains(body, secret) {
			t.Fatalf("payload contains %q:\n%s", secret, body)
		}
	}
	if !strings.Contains(body, token().Token) {
		t.Fatalf("payload does not address the device it is for:\n%s", body)
	}
}

func TestARefusalIsAnError(t *testing.T) {
	// A push service that rejects the send must not look like a delivery. The
	// caller logs it; silently succeeding would hide a provider outage.
	notifier := push.NewExpo(slog.New(slog.NewTextHandler(io.Discard, nil)))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	notifier.Endpoint = server.URL

	if err := notifier.Notify(context.Background(), token()); err == nil {
		t.Fatal("a 500 from the push service was reported as success")
	}
}

func TestNopIsAWorkingDeployment(t *testing.T) {
	// A server with no push provider is a legitimate deployment — clients
	// receive on reconnect — so the default must not error.
	if err := (push.Nop{}).Notify(context.Background(), token()); err != nil {
		t.Fatalf("Nop.Notify: %v", err)
	}
}
