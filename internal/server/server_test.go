package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// okHandler answers every request with 200 so lifecycle tests can distinguish
// a fully served request from a dropped connection.
func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// serveTestServer starts the bounded lifecycle over a LIVE listener bound to
// port 0 (never a close-then-rebind sequence, so parallel tests cannot steal
// the port) and returns the bound address and the channel Run will report its
// result on. The returned address is substituted into cfg.Address.
func serveTestServer(t *testing.T, ctx context.Context, cfg Config, handler http.Handler, opts ...Option) (string, chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	cfg.Address = ln.Addr().String()
	o := options{}
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	done := make(chan error, 1)
	go func() { done <- serveListener(ctx, cfg, handler, ln, o) }()
	return cfg.Address, done
}

func testConfig(addr string) Config {
	return Config{
		Address:           addr,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ShutdownTimeout:   2 * time.Second,
	}
}

// waitReady polls the server until it answers 200, proving Run has opened the
// listener before the test drives it.
func waitReady(t *testing.T, addr string) {
	t.Helper()
	client := &http.Client{Timeout: 500 * time.Millisecond}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get("http://" + addr + "/")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server on %s never became ready", addr)
}

// TestServerRunAppliesConfiguredTimeouts asserts the wrapper builds the
// http.Server with every configured timeout verbatim.
func TestServerRunAppliesConfiguredTimeouts(t *testing.T) {
	cfg := Config{
		Address:           ":8080",
		ReadHeaderTimeout: 7 * time.Second,
		ReadTimeout:       8 * time.Second,
		WriteTimeout:      9 * time.Second,
		IdleTimeout:       10 * time.Second,
		ShutdownTimeout:   11 * time.Second,
		MaxHeaderBytes:    4096,
	}
	srv := newHTTPServer(cfg, okHandler())
	if srv.Addr != cfg.Address {
		t.Fatalf("addr: got %q want %q", srv.Addr, cfg.Address)
	}
	if srv.ReadHeaderTimeout != cfg.ReadHeaderTimeout {
		t.Fatalf("ReadHeaderTimeout: got %v want %v", srv.ReadHeaderTimeout, cfg.ReadHeaderTimeout)
	}
	if srv.ReadTimeout != cfg.ReadTimeout {
		t.Fatalf("ReadTimeout: got %v want %v", srv.ReadTimeout, cfg.ReadTimeout)
	}
	if srv.WriteTimeout != cfg.WriteTimeout {
		t.Fatalf("WriteTimeout: got %v want %v", srv.WriteTimeout, cfg.WriteTimeout)
	}
	if srv.IdleTimeout != cfg.IdleTimeout {
		t.Fatalf("IdleTimeout: got %v want %v", srv.IdleTimeout, cfg.IdleTimeout)
	}
	if srv.MaxHeaderBytes != cfg.MaxHeaderBytes {
		t.Fatalf("MaxHeaderBytes: got %d want %d", srv.MaxHeaderBytes, cfg.MaxHeaderBytes)
	}
}

// TestServerRunGracefulShutdownDrainsInflightRequests proves that cancelling
// ctx does not return Run while a request is still being handled, and that the
// in-flight request completes normally before Run returns nil.
func TestServerRunGracefulShutdownDrainsInflightRequests(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-entered:
		default:
			close(entered)
		}
		<-release
		w.WriteHeader(http.StatusOK)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr, done := serveTestServer(t, ctx, testConfig("127.0.0.1:0"), handler)

	client := &http.Client{}
	type result struct {
		resp *http.Response
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		resp, err := client.Get("http://" + addr + "/")
		resCh <- result{resp: resp, err: err}
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request never reached the handler")
	}

	cancel()

	select {
	case err := <-done:
		t.Fatalf("Run returned before the in-flight request drained: %v", err)
	case <-time.After(150 * time.Millisecond):
	}

	close(release)

	select {
	case res := <-resCh:
		if res.err != nil {
			t.Fatalf("in-flight request failed: %v", res.err)
		}
		if res.resp.StatusCode != http.StatusOK {
			t.Fatalf("in-flight request status: got %d want 200", res.resp.StatusCode)
		}
		res.resp.Body.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight request never completed")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error after graceful drain: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the request drained")
	}
}

// TestServerRunForcesCloseAfterShutdownDeadline proves that a request which
// never completes is force-closed once the ShutdownTimeout deadline passes,
// and that Run returns an error wrapping ErrShutdownDeadline.
func TestServerRunForcesCloseAfterShutdownDeadline(t *testing.T) {
	entered := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-entered:
		default:
			close(entered)
		}
		select {} // never completes
	})

	cfg := testConfig("127.0.0.1:0")
	cfg.ShutdownTimeout = 100 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr, done := serveTestServer(t, ctx, cfg, handler)

	client := &http.Client{}
	errCh := make(chan error, 1)
	go func() {
		_, err := client.Get("http://" + addr + "/")
		errCh <- err
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request never reached the handler")
	}

	cancel()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("force-closed request returned no error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("force-closed request never failed")
	}

	select {
	case err := <-done:
		if !errors.Is(err, ErrShutdownDeadline) {
			t.Fatalf("Run error: got %v want ErrShutdownDeadline", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the forced close")
	}
}

// TestServerRunCleanupCallbacksRunOnGracefulShutdown asserts every registered
// cleanup callback runs, in registration order, after a graceful shutdown.
func TestServerRunCleanupCallbacksRunOnGracefulShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	calls := []string{}
	cb := func(name string) func() error {
		return func() error {
			mu.Lock()
			defer mu.Unlock()
			calls = append(calls, name)
			return nil
		}
	}

	addr, done := serveTestServer(t, ctx, testConfig("127.0.0.1:0"), okHandler(),
		WithCleanup(cb("first")), WithCleanup(cb("second")))
	waitReady(t, addr)

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after shutdown")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 2 || calls[0] != "first" || calls[1] != "second" {
		t.Fatalf("cleanup callbacks: got %v want [first second]", calls)
	}
}

// TestServerRunRunsCleanupCallbacksOnServeError proves cleanup callbacks still
// run when the server fails before or during serving (e.g. a bind conflict),
// so durable resources are never leaked on a failed startup.
func TestServerRunRunsCleanupCallbacksOnServeError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String() // keep the port occupied so Run cannot bind it

	cleanupRan := false
	err = Run(context.Background(), testConfig(addr), okHandler(),
		WithCleanup(func() error { cleanupRan = true; return nil }))
	if err == nil {
		t.Fatal("Run succeeded on an occupied address")
	}
	if !strings.Contains(err.Error(), "server:") {
		t.Fatalf("serve error not wrapped with the server prefix: %v", err)
	}
	if !cleanupRan {
		t.Fatal("cleanup callback did not run on serve error")
	}
}

// TestServerRunPropagatesCleanupError asserts a failing cleanup callback is
// surfaced as a wrapped error from Run.
func TestServerRunPropagatesCleanupError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cleanupErr := errors.New("cleanup failed")
	addr, done := serveTestServer(t, ctx, testConfig("127.0.0.1:0"), okHandler(),
		WithCleanup(func() error { return cleanupErr }))
	waitReady(t, addr)

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, cleanupErr) {
			t.Fatalf("Run error: got %v want cleanup error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after shutdown")
	}
}

// TestServerRunRejectsInvalidConfig asserts the wrapper fails closed before
// opening any listener when the configuration is invalid.
func TestServerRunRejectsInvalidConfig(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		handler http.Handler
	}{
		{name: "blank address", cfg: Config{Address: " ", ShutdownTimeout: time.Second}, handler: okHandler()},
		{name: "nil handler", cfg: Config{Address: ":8080", ShutdownTimeout: time.Second}, handler: nil},
		{name: "zero shutdown timeout", cfg: Config{Address: ":8080"}, handler: okHandler()},
		{name: "negative shutdown timeout", cfg: Config{Address: ":8080", ShutdownTimeout: -time.Second}, handler: okHandler()},
		{name: "negative read header timeout", cfg: Config{Address: ":8080", ShutdownTimeout: time.Second, ReadHeaderTimeout: -time.Second}, handler: okHandler()},
		{name: "negative read timeout", cfg: Config{Address: ":8080", ShutdownTimeout: time.Second, ReadTimeout: -time.Second}, handler: okHandler()},
		{name: "negative write timeout", cfg: Config{Address: ":8080", ShutdownTimeout: time.Second, WriteTimeout: -time.Second}, handler: okHandler()},
		{name: "negative idle timeout", cfg: Config{Address: ":8080", ShutdownTimeout: time.Second, IdleTimeout: -time.Second}, handler: okHandler()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := Run(context.Background(), tc.cfg, tc.handler); err == nil {
				t.Fatal("Run accepted an invalid configuration")
			}
		})
	}
}
