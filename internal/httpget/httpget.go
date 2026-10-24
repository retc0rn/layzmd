// Package httpget provides a fake-able HTTP abstraction used by the enrichment
// engine. The HTTPGetter interface is the seam for testing; Client is the
// production implementation wrapping net/http.
package httpget

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// HTTPGetter is the interface all network callers depend on. Keeping it single-
// method (one Get with an optional headers map, instead of two overloads as in
// the C# IHttpGet) simplifies faking in tests.
type HTTPGetter interface {
	Get(ctx context.Context, url, userAgent string, headers map[string]string) (string, error)
}

// HTTPError is returned by Client.Get for any non-2xx response.
type HTTPError struct {
	StatusCode int
	Status     string
	RetryAfter time.Duration
}

// Error implements the error interface.
func (e *HTTPError) Error() string {
	return fmt.Sprintf("http %d: %s", e.StatusCode, e.Status)
}

// Client is a thin, production HTTPGetter wrapping a shared *http.Client.
// User-Agent and any per-request headers are set on the request, never on the
// shared client, so the client is safe for concurrent use.
type Client struct {
	hc *http.Client
}

// NewClient returns a Client with the given timeout. If timeout is zero the
// default of 30 seconds is used.
func NewClient(timeout time.Duration) *Client {
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &Client{hc: &http.Client{Timeout: timeout}}
}

// Get issues a GET request to url, sets the User-Agent header, applies any
// additional headers, reads the full response body, and returns it as a string.
//
// A non-2xx status code results in ("", *HTTPError) with StatusCode, Status,
// and any Retry-After value parsed from the response header.
// Transport and context errors are returned as-is.
func (c *Client) Get(ctx context.Context, url, userAgent string, headers map[string]string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", userAgent)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", &HTTPError{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
		}
	}

	return string(body), nil
}

// parseRetryAfter parses the value of a Retry-After header. It supports only
// the integer-seconds form (HTTP-date form is not needed for our sources and is
// ignored, returning 0). If s is empty or not a valid integer, 0 is returned.
func parseRetryAfter(s string) time.Duration {
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Second
}
