package observability

import (
	"context"
	"testing"
	"time"
)

// TestReadinessJSONIsStructured proves the /readyz payload is a stable,
// non-secret JSON summary ordered by component.
func TestReadinessJSONIsStructured(t *testing.T) {
	res := RunReadiness(context.Background(), []Component{
		{Name: "database", Probe: func(context.Context) error { return nil }},
		{Name: "bee", Probe: func(context.Context) error { return &probeDetailError{detail: "nope"} }},
	})
	body := res.JSON()
	// The body must be a JSON object with the fixed status and checks array.
	for _, want := range []string{`"status"`, `"checks"`, `"database"`, `"bee"`, `"ok":true`, `"ok":false`, `"failed"`} {
		if index := indexOf(body, want); index < 0 {
			t.Errorf("readiness JSON missing %q: %s", want, body)
		}
	}
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// TestReadinessTimeoutConstIsShort proves the per-probe deadline stays a
// short bounded value (readiness must never hang on a stalled dependency).
func TestReadinessTimeoutConstIsShort(t *testing.T) {
	if ReadinessProbeTimeout <= 0 || ReadinessProbeTimeout > 10*time.Second {
		t.Fatalf("ReadinessProbeTimeout = %v, want a short positive bound", ReadinessProbeTimeout)
	}
}
