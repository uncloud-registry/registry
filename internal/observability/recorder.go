package observability

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ResultClass maps a response status to the fixed request error class.
// 2xx is success, 4xx is a client error (rejected before server work), and
// every 5xx is a server error (including the dependency and integrity
// surfaces, which carry their own dedicated failure counters).
func ResultClass(status int) string {
	switch {
	case status >= 200 && status < 300:
		return ResultSuccess
	case status >= 400 && status < 500:
		return ResultClientError
	default:
		return ResultServerError
	}
}

// ResponseRecorder wraps an http.ResponseWriter to capture the FIRST status
// code written (or the implicit 200 of a bare Write), so request telemetry
// and the structured request log can classify a request after dispatch
// without buffering any response body.
type ResponseRecorder struct {
	http.ResponseWriter
	status int
}

// NewResponseRecorder wraps w for status capture. All reads/writes pass
// through unchanged.
func NewResponseRecorder(w http.ResponseWriter) *ResponseRecorder {
	return &ResponseRecorder{ResponseWriter: w}
}

// WriteHeader records the FIRST status and forwards it. Later WriteHeader
// calls (invalid per net/http) are ignored by the recorder.
func (r *ResponseRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

// Write records the implicit 200 and forwards the body write.
func (r *ResponseRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

// Status returns the captured status, defaulting to 200 when the handler
// never wrote a header (success paths write the body after recording state).
func (r *ResponseRecorder) Status() int {
	if r.status == 0 {
		return http.StatusOK
	}
	return r.status
}

// RequestID returns the bounded correlation identity for request logs: a
// caller-supplied X-Request-ID reduced to the safe alphabet (log-injection
// proof, at most 64 bytes), or a fresh random 32-hex ID when absent. The
// generated form is a random correlation identity — never secret material,
// never an echo of request data.
func RequestID(r *http.Request) string {
	const maxLen = 64
	if raw := r.Header.Get("X-Request-ID"); raw != "" {
		var b strings.Builder
		for _, c := range raw {
			if b.Len() >= maxLen {
				break
			}
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
				b.WriteRune(c)
			}
		}
		if s := b.String(); s != "" {
			return s
		}
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err == nil {
		return hex.EncodeToString(raw[:])
	}
	return fmt.Sprintf("req-%d", time.Now().UnixNano())
}
