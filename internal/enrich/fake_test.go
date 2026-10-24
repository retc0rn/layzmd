package enrich

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// fakeGetter is a test double for httpget.HTTPGetter. Routes are matched by
// substring on the request URL; the first match wins. It records every URL
// called (calls) and the headers of the last request (lastHeaders).
// It is safe for concurrent use.
type fakeGetter struct {
	mu  sync.Mutex
	routes []struct {
		match string
		body  string
		err   error
	}
	calls       []string
	lastHeaders map[string]string
}

func (f *fakeGetter) add(match, body string, err error) *fakeGetter {
	f.routes = append(f.routes, struct {
		match string
		body  string
		err   error
	}{match, body, err})
	return f
}

func (f *fakeGetter) Get(_ context.Context, url, _ string, headers map[string]string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls = append(f.calls, url)
	// Copy the headers so the caller's map cannot be mutated after the call.
	if headers != nil {
		cp := make(map[string]string, len(headers))
		for k, v := range headers {
			cp[k] = v
		}
		f.lastHeaders = cp
	} else {
		f.lastHeaders = nil
	}
	for _, r := range f.routes {
		if strings.Contains(url, r.match) {
			return r.body, r.err
		}
	}
	return "", fmt.Errorf("no route for %s", url)
}
