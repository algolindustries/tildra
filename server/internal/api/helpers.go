package api

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode"
)

const maxBodyBytes = 12 << 20 // 12 MiB — the backup blob is the largest legal body

func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		fail(w, http.StatusBadRequest, "malformed request body")
		return false
	}
	return true
}

func respond(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if body != nil {
		_ = json.NewEncoder(w).Encode(body)
	}
}

func fail(w http.ResponseWriter, code int, msg string) {
	respond(w, code, map[string]string{"error": msg})
}

// fail500 logs the real cause and tells the client nothing. Internal errors are
// exactly the messages most likely to leak a schema or a file path.
func (s *Server) fail500(w http.ResponseWriter, op string, err error) {
	s.log.Error("request failed", "op", op, "err", err)
	fail(w, http.StatusInternalServerError, "internal error")
}

func sha256Sum(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

// sanitizeName trims a user-supplied device name to something safe to show in
// another user's device list: printable, single-line, bounded.
func sanitizeName(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > 64 {
		s = s[:64]
	}
	if s == "" {
		s = "Unnamed device"
	}
	return s
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		next.ServeHTTP(w, r)
	})
}

// logging records the route, status and duration — deliberately not the
// client IP, per docs/PROTOCOL.md §8, and deliberately not the URL.
//
// The URL is the part that is easy to get wrong, and this did: it logged
// r.URL.Path, and the paths here carry account ids, device ids, handles,
// mailbox ids and — since recovery landed — the lookup id that addresses
// somebody's recovery blob. A log file is a place operators copy around,
// grep, and ship to a hosted collector; putting those in it undoes the
// property they were designed to have.
//
// What is logged is the matched route pattern, "GET /v1/keys/{accountId}/
// {deviceId}", which says what happened and names nobody. A request that
// matched nothing has no pattern and gets none: an unrouted path is
// attacker-chosen text and does not belong in a log either.
//
// If you add the IP or the URL here you have changed the product's privacy
// claims, so change the docs too — and the tests below will stop you first.
func logging(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		log.Info("http",
			"method", r.Method,
			"route", routeLabel(r.URL.Path),
			"status", rec.status,
			"dur", time.Since(start).Round(time.Millisecond),
		)
	})
}

// knownRoutes is every path prefix this server serves, to two segments.
//
// An allowlist rather than a redaction rule, because a redaction rule has to
// be right about every input and this only has to be right about a list that
// sits next to the route table. Anything not on it is somebody else's text.
var knownRoutes = map[string]bool{
	"/healthz":                     true,
	"/v1/accounts":                 true,
	"/v1/auth/challenge":           true,
	"/v1/auth/token":               true,
	"/v1/auth/logout":              true,
	"/v1/keys":                     true,
	"/v1/devices":                  true,
	"/v1/handle":                   true,
	"/v1/handles":                  true,
	"/v1/mailboxes":                true,
	"/v1/messages":                 true,
	"/v1/backup":                   true,
	"/v1/recovery":                 true,
	"/v1/push":                     true,
	"/v1/attachments":              true,
	"/v1/provisioning":             true,
	"/v1/transparency/head":        true,
	"/v1/transparency/consistency": true,
	"/v1/transparency/entries":     true,
	"/v1/turn":                     true,
	"/v1/ws":                       true,
}

// routeLabel turns a request path into something safe to write down.
//
// The longest known prefix wins, so "/v1/auth/challenge" keeps all three
// segments while "/v1/keys/ACCOUNT/DEVICE" keeps two. Everything past the
// prefix is an identifier — an account, a device, a handle, a mailbox, an
// attachment, a recovery lookup id — and none of them belong in a log. What
// is left says which endpoint was hit and names nobody.
func routeLabel(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 1 && parts[0] == "" {
		return "(unrecognised)"
	}

	for depth := min(len(parts), 3); depth >= 1; depth-- {
		prefix := "/" + strings.Join(parts[:depth], "/")
		if !knownRoutes[prefix] {
			continue
		}
		for range parts[depth:] {
			prefix += "/{}"
		}
		return prefix
	}
	return "(unrecognised)"
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach the underlying ResponseWriter.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// Hijack forwards the WebSocket upgrade to the real connection.
//
// Embedding http.ResponseWriter does not carry http.Hijacker through, so
// without this the upgrade fails with 501 and the gateway is unreachable —
// which is exactly as broken as it sounds, and exactly as silent.
func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("tildra: %T does not support hijacking", r.ResponseWriter)
	}
	return hijacker.Hijack()
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
