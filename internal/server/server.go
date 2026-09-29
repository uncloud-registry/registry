// Package server provides the bounded HTTP server lifecycle used by both
// binaries. Run owns the listener, applies every configured timeout to the
// http.Server, serves until the caller's context is canceled, then drains
// in-flight requests gracefully before returning. A request that cannot
// finish within ShutdownTimeout is force-closed, and cleanup callbacks (e.g.
// releasing a durable staging store or joining a worker loop) always run
// before Run returns, on every path.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// ErrShutdownDeadline is returned (wrapped) by Run when graceful shutdown
// could not drain in-flight requests before ShutdownTimeout elapsed and the
// remaining connections were force-closed. It is a fixed sentinel: the error
// carries no request, connection, or configuration data.
var ErrShutdownDeadline = errors.New("graceful shutdown deadline exceeded; in-flight connections force-closed")

// Config carries every bounded-server knob. Zero durations keep Go's
// net/http zero-value semantics (no wall-clock deadline) for the field in
// question, so operators may disable a deadline explicitly; negative
// durations and a non-positive ShutdownTimeout are rejected by Run.
type Config struct {
	Address           string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
	MaxHeaderBytes    int
}

// Option configures Run. Always use the exported constructors; the raw
// options type is unexported so the option surface stays closed.
type Option func(*options)

type options struct {
	tlsConfig *tls.Config
	cleanups  []func() error
}

// WithTLSConfig makes Run terminate TLS directly: the listener accepts
// plaintext TCP and is wrapped with tls.NewListener using the supplied
// configuration. A nil config is ignored (plaintext serving).
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(o *options) {
		o.tlsConfig = tlsConfig
	}
}

// WithCleanup registers a callback Run invokes before returning, on every
// exit path (graceful shutdown, forced close, and serve/listen failure), in
// registration order. Callbacks are the hook for durable-resource teardown:
// the staging cleanup worker join and the spool/SQLite close must happen
// only after in-flight requests have drained, and a forced close must never
// skip them. A failing callback aborts the remaining sequence and surfaces
// as a wrapped error from Run.
func WithCleanup(fn func() error) Option {
	return func(o *options) {
		if fn != nil {
			o.cleanups = append(o.cleanups, fn)
		}
	}
}

// newHTTPServer builds the http.Server exactly from the configured values so
// the configured timeouts are applied verbatim (asserted by tests).
func newHTTPServer(cfg Config, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              cfg.Address,
		Handler:           handler,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
	}
}

// validate rejects every configuration shape that cannot produce a bounded,
// well-defined lifecycle. A blank address, a nil handler, negative timeouts,
// and a non-positive shutdown timeout all fail closed BEFORE any listener is
// opened, so a bad config can never touch a socket.
func validate(cfg Config, handler http.Handler) error {
	if handler == nil {
		return errors.New("server: handler is required")
	}
	if strings.TrimSpace(cfg.Address) == "" {
		return errors.New("server: listen address is required")
	}
	if cfg.ShutdownTimeout <= 0 {
		return errors.New("server: shutdown timeout must be positive")
	}
	for _, pair := range []struct {
		name string
		d    time.Duration
	}{
		{"read header", cfg.ReadHeaderTimeout},
		{"read", cfg.ReadTimeout},
		{"write", cfg.WriteTimeout},
		{"idle", cfg.IdleTimeout},
	} {
		if pair.d < 0 {
			return fmt.Errorf("server: %s timeout must not be negative", pair.name)
		}
	}
	return nil
}

// Run serves handler on cfg.Address with every configured timeout applied,
// until ctx is canceled or the server fails. On context cancellation it
// drains in-flight requests with a fresh ShutdownTimeout-bounded context; if
// the deadline passes while requests are still active, the remaining
// connections are force-closed and Run returns a wrapped ErrShutdownDeadline.
// Cleanup callbacks run before Run returns on every path, and a serve/listen
// failure is returned wrapped. All errors carry only fixed text plus the
// underlying non-secret cause; no configuration values are echoed.
func Run(ctx context.Context, cfg Config, handler http.Handler, opts ...Option) error {
	if err := validate(cfg, handler); err != nil {
		return err
	}
	o := options{}
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}

	ln, err := net.Listen("tcp", cfg.Address)
	if err != nil {
		// The listener never opened, but durable resources may already have
		// been constructed by the caller (the handler may own a staging
		// store): cleanups must still run so a failed startup never leaks
		// them.
		if cerr := runCleanups(o); cerr != nil {
			return cerr
		}
		return fmt.Errorf("server: listen: %w", err)
	}
	return serveListener(ctx, cfg, handler, ln, o)
}

// serveListener runs the bounded lifecycle over an ALREADY-OPEN listener. It
// exists so tests can hand in a listener bound to port 0 (eliminating any
// close-then-rebind race); Run is serveListener plus its own net.Listen.
func serveListener(ctx context.Context, cfg Config, handler http.Handler, ln net.Listener, o options) error {
	srv := newHTTPServer(cfg, handler)
	if o.tlsConfig != nil {
		ln = tls.NewListener(ln, o.tlsConfig)
	}

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(ln)
	}()

	select {
	case err := <-serveErr:
		// The server stopped on its own: a real failure, or a normal close
		// that was not initiated by us. Force-close any leftovers and always
		// run the cleanups so durable resources are never leaked on a failed
		// startup or an unexpected exit.
		_ = srv.Close()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			if cerr := runCleanups(o); cerr != nil {
				return cerr
			}
			return fmt.Errorf("server: serve: %w", err)
		}
		if cerr := runCleanups(o); cerr != nil {
			return cerr
		}
		return nil

	case <-ctx.Done():
		// Graceful shutdown on a FRESH timeout context: the caller's ctx is
		// already done, so it cannot bound the drain.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()

		shutdownErr := srv.Shutdown(shutdownCtx)
		// Join the serve goroutine so the listener is fully closed and no
		// request handler is still running before any cleanup touches the
		// resources the handlers may use.
		<-serveErr

		if shutdownErr != nil {
			// The graceful window expired with requests still in flight:
			// force-close the remaining connections. Cleanup callbacks still
			// run — a forced close must never skip durable-resource teardown.
			_ = srv.Close()
			if cerr := runCleanups(o); cerr != nil {
				return cerr
			}
			return fmt.Errorf("server: %w", ErrShutdownDeadline)
		}

		if cerr := runCleanups(o); cerr != nil {
			return cerr
		}
		return nil
	}
}

// runCleanups invokes every registered cleanup callback in order; the first
// failure aborts the sequence and is surfaced wrapped. It runs on every exit
// path (graceful, forced, serve failure, and listen failure).
func runCleanups(o options) error {
	for _, fn := range o.cleanups {
		if err := fn(); err != nil {
			return fmt.Errorf("server: cleanup: %w", err)
		}
	}
	return nil
}
