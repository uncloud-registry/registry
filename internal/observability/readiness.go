package observability

import (
	"context"
	"encoding/json"
	"time"
)

// Probe performs ONE bounded readiness check. It returns nil when the
// component is healthy. Probe implementations MUST be data-free: their error
// text (paths, hosts, refs, key material) is never surfaced — the readiness
// runner reports only the fixed classification "failed".
type Probe func(ctx context.Context) error

// Component names every registry/control-plane readiness component. Fixed
// vocabulary — never derived from request data.
const (
	ComponentStaging        = "staging"
	ComponentVerification   = "verification-keys"
	ComponentBee            = "bee"
	ComponentDatabase       = "database"
	ComponentMasterKey      = "master-key"
	ComponentSigningKey     = "signing-key"
	ComponentBeePublication = "bee-publication"
)

// Ready/not-ready status values of the /readyz summary.
const (
	StatusReady    = "ready"
	StatusNotReady = "not_ready"
)

// checkFailedClass is the ONLY error classification ever surfaced for a down
// component. Probe error text — which may legitimately carry paths, hosts,
// refs, or key material — never crosses the readiness boundary.
const checkFailedClass = "failed"

// Component pairs a fixed component name with its probe. A nil probe means
// the component is NOT APPLICABLE to this process (e.g. Bee in in-memory
// mode) and the component is omitted entirely from the readiness summary.
type Component struct {
	Name  string
	Probe Probe
}

// Check is one component's structured, non-secret readiness outcome.
type Check struct {
	Name  string `json:"name"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// Readiness is the full structured /readyz summary: fixed status plus one
// Check per applicable component. It carries no secrets, paths, hosts, refs,
// or identifiers — only fixed component names and the fixed failure class.
type Readiness struct {
	Status string  `json:"status"`
	Checks []Check `json:"checks"`
}

// JSON renders the readiness summary for the /readyz response body. Because
// Check.Error is always the fixed classification, the JSON never carries
// probe detail.
func (r Readiness) JSON() string {
	data, err := json.Marshal(r)
	if err != nil {
		return `{"status":"not_ready","checks":[]}`
	}
	return string(data)
}

// ReadinessProbeTimeout bounds EACH component probe. Readiness must never
// hang on a stalled dependency, so every probe runs under this short
// deadline. Declared as a var so tests may shrink it.
var ReadinessProbeTimeout = 2 * time.Second

// RunReadiness runs every applicable component probe under the short
// per-probe deadline and assembles the structured, non-secret summary.
// Components whose probe is nil are skipped (not applicable). Probe errors
// are observed only as ok=false with the fixed "failed" classification —
// their text never reaches the summary.
func RunReadiness(ctx context.Context, components []Component) Readiness {
	res := Readiness{Status: StatusReady, Checks: []Check{}}
	for _, c := range components {
		if c.Probe == nil {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, ReadinessProbeTimeout)
		err := c.Probe(cctx)
		cancel()
		if err != nil {
			res.Checks = append(res.Checks, Check{Name: c.Name, OK: false, Error: checkFailedClass})
			res.Status = StatusNotReady
			continue
		}
		res.Checks = append(res.Checks, Check{Name: c.Name, OK: true})
	}
	return res
}
