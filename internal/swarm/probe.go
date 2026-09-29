package swarm

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"
)

// ProbeHealth returns a readiness probe (for /readyz) that checks the Bee
// node's /health endpoint on baseURL with a SHORT dedicated per-request
// timeout, so readiness never inherits the longer dependency-client deadlines
// and never hangs on a stalled node. A 2xx response is healthy; anything else
// (non-2xx, timeout, transport failure) fails the probe. The returned error
// is a FIXED data-free classification — it never echoes the URL, status, or
// response detail — because probe errors are the only thing between an
// operator and the readiness summary an unauthenticated client can read.
//
// The probe uses a private bounded client (connect + response-header
// deadlines plus an overall timeout). When client is non-nil and carries a
// cloned standard transport, that transport's proxy/settings are preserved
// under the probe's own short deadlines.
func ProbeHealth(baseURL string, client *http.Client) func(ctx context.Context) error {
	origin := strings.TrimRight(baseURL, "/")
	return func(ctx context.Context) error {
		probeClient := &http.Client{
			Timeout: probeTimeout,
			Transport: &http.Transport{
				DialContext:           (&net.Dialer{Timeout: 2 * time.Second, KeepAlive: 0}).DialContext,
				TLSHandshakeTimeout:   2 * time.Second,
				ResponseHeaderTimeout: 2 * time.Second,
				IdleConnTimeout:       5 * time.Second,
			},
		}
		if client != nil {
			if t, ok := client.Transport.(*http.Transport); ok {
				cloned := t.Clone()
				cloned.ResponseHeaderTimeout = 2 * time.Second
				probeClient.Transport = cloned
			} else if client.Transport != nil {
				probeClient.Transport = client.Transport
			}
		}

		reqCtx, cancel := context.WithTimeout(ctx, probeTimeout)
		defer cancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, origin+"/health", nil)
		if err != nil {
			return errProbeFailed
		}
		resp, err := probeClient.Do(req)
		if err != nil {
			return errProbeFailed
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return errProbeFailed
		}
		return nil
	}
}

// probeTimeout bounds the whole Bee readiness probe (connect through
// response). Readiness must never wait longer than this for a node.
const probeTimeout = 2 * time.Second

// errProbeFailed is the fixed data-free readiness failure classification:
// the node is down, unresponsive, or unhealthy. It never carries the URL,
// status, or response detail.
var errProbeFailed = errors.New("bee readiness probe failed")
