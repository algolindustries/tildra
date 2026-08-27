package auditor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/algolindustries/tildra/server/internal/transparency"
)

// HTTPSource reads a live server's transparency endpoints.
type HTTPSource struct {
	BaseURL string
	Client  *http.Client
}

func NewHTTPSource(baseURL string) *HTTPSource {
	return &HTTPSource{
		BaseURL: baseURL,
		// A generous timeout: an auditor downloading a large log is doing the
		// one thing it exists to do, and cutting it off mid-walk leaves it
		// unable to attest to anything.
		Client: &http.Client{Timeout: 60 * time.Second},
	}
}

func (h *HTTPSource) Head(ctx context.Context) (transparency.SignedTreeHead, error) {
	var head transparency.SignedTreeHead
	err := h.get(ctx, "/v1/transparency/head", nil, &head)
	return head, err
}

func (h *HTTPSource) Consistency(ctx context.Context, first, second int64) ([][]byte, error) {
	var body struct {
		Proof [][]byte `json:"proof"`
	}
	err := h.get(ctx, "/v1/transparency/consistency", url.Values{
		"first":  {strconv.FormatInt(first, 10)},
		"second": {strconv.FormatInt(second, 10)},
	}, &body)
	return body.Proof, err
}

func (h *HTTPSource) Entries(ctx context.Context, from, to int64) ([]*transparency.Entry, error) {
	var body struct {
		Entries []*transparency.Entry `json:"entries"`
	}
	err := h.get(ctx, "/v1/transparency/entries", url.Values{
		"from": {strconv.FormatInt(from, 10)},
		"to":   {strconv.FormatInt(to, 10)},
	}, &body)
	return body.Entries, err
}

func (h *HTTPSource) get(ctx context.Context, path string, query url.Values, out any) error {
	target := h.BaseURL + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := h.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
