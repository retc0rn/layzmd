package httpget_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"layzmd/internal/httpget"
)

func TestHTTPError_Error(t *testing.T) {
	e := &httpget.HTTPError{StatusCode: 429, Status: "429 Too Many Requests"}
	msg := e.Error()
	if msg == "" {
		t.Fatal("Error() returned empty string")
	}
	// Must contain the status code.
	const want = "429"
	if !contains(msg, want) {
		t.Errorf("Error() = %q; want it to contain %q", msg, want)
	}
}

func TestClient_Get_OK(t *testing.T) {
	var gotUA, gotXTest string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotXTest = r.Header.Get("X-Test")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	}))
	defer ts.Close()

	c := httpget.NewClient(5 * time.Second)
	body, err := c.Get(context.Background(), ts.URL, "UA/1", map[string]string{"X-Test": "v"})
	if err != nil {
		t.Fatalf("Get returned unexpected error: %v", err)
	}
	if body != "hello" {
		t.Errorf("Get body = %q; want %q", body, "hello")
	}
	if gotUA != "UA/1" {
		t.Errorf("User-Agent = %q; want %q", gotUA, "UA/1")
	}
	if gotXTest != "v" {
		t.Errorf("X-Test = %q; want %q", gotXTest, "v")
	}
}

func TestClient_Get_Non2xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	c := httpget.NewClient(5 * time.Second)
	body, err := c.Get(context.Background(), ts.URL, "UA/1", nil)
	if err == nil {
		t.Fatalf("Get returned nil error for 404; body = %q", body)
	}
	if body != "" {
		t.Errorf("Get body = %q; want empty string on error", body)
	}
	var httpErr *httpget.HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("error is %T; want *httpget.HTTPError", err)
	}
	if httpErr.StatusCode != 404 {
		t.Errorf("HTTPError.StatusCode = %d; want 404", httpErr.StatusCode)
	}
}

func TestClient_Get_RetryAfter(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "2")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer ts.Close()

	c := httpget.NewClient(5 * time.Second)
	_, err := c.Get(context.Background(), ts.URL, "UA/1", nil)
	if err == nil {
		t.Fatal("Get returned nil error for 429")
	}
	var httpErr *httpget.HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("error is %T; want *httpget.HTTPError", err)
	}
	want := 2 * time.Second
	if httpErr.RetryAfter != want {
		t.Errorf("HTTPError.RetryAfter = %v; want %v", httpErr.RetryAfter, want)
	}
}

// contains is a simple substring check to avoid importing strings in test.
func contains(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
