package publish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/uncloud-registry/registry/internal/spec"
)

// InternalFeedUpdatePath is the RETIRED legacy (pre-round-3) internal
// feed-update endpoint path. It is EXPLICITLY DISABLED on the internal
// server (a request to it is an ordinary unrecognized-route 404, exactly
// like any other unknown path — see InternalFeedServer.ServeHTTP): the
// PublicationID/attempt-identity split (round 2) and the durable
// publication_states terminal-success gate (round 3 / Finding 1) are both
// meaningless without a stable PublicationID, and this repository has no
// production caller that ever omits one (the registry data plane's handler
// always supplies a non-empty stable identity — see
// registry.Handler.handleManifestPut). Rather than maintain a second active
// identity mode whose durable rows could be mistaken for — or used to
// bypass — the current protocol's, the legacy shape is retired outright.
// This constant is retained ONLY so tests can positively assert the route is
// gone (never 200, never routed to the signer).
const InternalFeedUpdatePath = "/internal/v1/feed-updates"

// InternalFeedUpdatePathV2 is the CURRENT internal feed-update endpoint path
// and the ONLY one ControlPlaneCommitter (the production data-plane client)
// ever sends to. Every request accepted here MUST carry a non-empty
// PublicationID (the stable logical-publication identity) and an OperationID
// that is exactly ComputeCommitAttemptID(PublicationID, ...) — the current
// protocol never falls back to treating OperationID as its own stable
// identity, and never infers a "legacy mode" from a missing field. This is
// the explicit, bounded protocol-version marker Task 17 round 3 requires:
// a new registry binary and an old (pre-round-3) control plane can never
// silently miscommunicate, because the old control plane simply does not
// serve this path (it 404s) and the new registry never speaks the old one.
// Deployment ordering: this repository ships in lockstep, but a rolling
// upgrade MUST still bring the control plane up on the version that serves
// this path BEFORE any registry process using it is started; a registry
// pointed at a not-yet-upgraded control plane fails every commit closed
// (ErrCommitBackend, from the 404) rather than silently degrading to a
// weaker identity contract.
const InternalFeedUpdatePathV2 = "/internal/v2/feed-updates"

// InternalAuthHeader is the dedicated credential header the registry data
// plane sends on every internal feed-commit request. It is distinct from the
// public Authorization header so an internal request can never be confused
// with (or benefit from) a browser/session credential, and it never carries a
// user session, registry token, or feed-owner key.
const InternalAuthHeader = "X-Uncloud-Internal-Auth"

// InternalResolvePath is the exact internal endpoint prefix for dynamic
// registry-identity resolution. A resolve request is GET
// InternalResolvePath + <canonical-hostname> (the data plane strips any port
// before sending; the control plane stores hosts WITHOUT a port). It shares
// the internal credential header with feed commits and operation bindings, so
// dynamic resolution rides the SAME internal listener and trust boundary —
// never the public router.
const InternalResolvePath = "/internal/v1/resolve/"

// ResolveResponse is the exact response a successful registry-identity
// resolution returns: the registry's feed-owner address and its unambiguous
// control-plane RegistryID (the data plane routes internal feed commits by
// this ID). JSON names are the fixed contract.
type ResolveResponse struct {
	Owner      string `json:"owner"`
	RegistryID int64  `json:"registryID"`
}

// FeedCommitRequest is the exact request the registry data plane sends to the
// control-plane internal feed signer. Field/JSON names are the fixed contract
// from the Task 10 interface. Topic is the FULL deterministic repository-state
// feed reference (feed://<owner>/<topichex>).
//
// OperationID and PublicationID are DELIBERATELY DISTINCT identities:
//
//   - PublicationID is the STABLE logical publication identity — the exact
//     identity recorded as durable per-tag provenance (spec.TagPublication),
//     echoed to the caller, and durably bound by the preflight operation-key
//     reservation. It NEVER changes across a one-time authoritative
//     generation-conflict rebuild or a lost-response retry of the SAME
//     logical publication.
//   - OperationID is the identity of ONE COMMIT ATTEMPT: it is deterministically
//     derived from PublicationID plus the attempt's own ExpectedGeneration and
//     target Reference (see ComputeCommitAttemptID), so it is durably reserved
//     and hashed at the control plane (feed_signer_operations) PER ATTEMPT. A
//     rebuilt attempt (fresh generation/reference) always derives a FRESH
//     OperationID, so its durable reservation can never collide with the
//     conflicted attempt's permanently-fixed request hash.
//
// On the current versioned wire route PublicationID is REQUIRED. The v2
// client rejects an empty value before network I/O, and the v2 server rejects
// omission before invoking the signer. The omitempty tag exists only because
// this typed value is also used by isolated Go-level legacy migration tests;
// it does not make omission a supported wire mode.
type FeedCommitRequest struct {
	OperationID        string `json:"operationID"`
	PublicationID      string `json:"publicationID,omitempty"`
	RegistryID         int64  `json:"registryID"`
	Owner              string `json:"owner"`
	Topic              string `json:"topic"`
	Reference          string `json:"reference"`
	BatchID            string `json:"batchID"`
	ExpectedGeneration int64  `json:"expectedGeneration"`
}

// FeedCommitResult is the exact response a successful feed commit returns.
type FeedCommitResult struct {
	OperationID string `json:"operationID"`
	Feed        string `json:"feed"`
	Reference   string `json:"reference"`
}

// Stable sentinel errors mapping the internal service's coarse statuses. They
// carry no internal error text, secrets, or topology, and every raw transport/
// decode/build detail is REDUCED to one of them before it can cross a caller
// boundary.
var (
	// ErrCommitUnauthorized is returned when the control plane rejects the
	// internal credential (401).
	ErrCommitUnauthorized = errors.New("internal feed signing rejected the credential")
	// ErrCommitMalformed is returned when the control plane rejects the
	// request as malformed (400) or when the client cannot build/send a valid
	// request.
	ErrCommitMalformed = errors.New("invalid feed commit request rejected")
	// ErrCommitUnknownRegistry is returned when the registry ID does not exist
	// or the caller's owner does not belong to it (404).
	ErrCommitUnknownRegistry = errors.New("registry is unknown to the feed signing service")
	// ErrCommitConflict is the PERMANENT conflict class: reusing an operation
	// or publication identity with different input (409). It is NEVER safe to
	// rebuild or retry — a distinct logical operation must never inherit
	// another operation's outcome.
	ErrCommitConflict = errors.New("feed commit operation conflict")
	// ErrCommitGenerationConflict is the RECOVERABLE conflict class: the
	// repository generation did not match (advanced elsewhere, or a
	// concurrent creation raced) (412). It is the ONLY conflict class
	// IsGenerationConflict recognizes as safe for the one-time authoritative
	// re-resolution and rebuild.
	ErrCommitGenerationConflict = errors.New("feed commit generation conflict")
	// ErrCommitBackend is a retryable control-plane/Bee/dependency failure (503).
	// It is also the class to which every raw network, dial, timeout, URL,
	// TLS, decode, and validation-of-response failure collapses, so no host/
	// port/path/topology or response body ever reaches err.Error().
	ErrCommitBackend = errors.New("feed signing service is temporarily unavailable")
)

// CommitResponseMaxBody bounds the internal feed-commit response body.
const CommitResponseMaxBody = 4096

// CommitRequestMaxBody bounds the internal feed-commit request body.
const CommitRequestMaxBody = 16384

// OperationIDMaxLen is the documented upper bound on an operation identifier
// (bytes), enforced by ValidateOperationID and mirrored byte-for-byte by the
// control-plane database operation-ID grammar.
const (
	OperationIDMaxLen = 128
	ownerMaxLen       = 128
	batchIDMaxLen     = 128
)

// commitRequestTimeout is the per-request deadline applied via the request
// context even when the supplied HTTP client has no Timeout configured.
const commitRequestTimeout = 30 * time.Second

// ControlPlaneCommitter commits an immutable repository-state reference through
// the control plane's internal feed-signing service. It carries NO key
// material. The internal credential (Secret) authenticates the registry data
// plane and is mounted from a secret file.
type ControlPlaneCommitter struct {
	// BaseURL is the control-plane internal feed-signing origin, validated and
	// canonicalized by Commit: absolute http(s), host required, no userinfo,
	// path (beyond empty or "/"), query, or fragment. Plaintext http is
	// accepted ONLY for a loopback host; any non-loopback origin must use
	// https.
	BaseURL string
	// Secret is the internal service credential bytes loaded from a secret
	// file. It is never echoed.
	Secret []byte
	// HTTPClient is the transport; a nil client uses http.DefaultClient.
	HTTPClient *http.Client
	// Logger, when set, records the raw transport/diagnostic detail that is
	// deliberately NOT propagated in returned errors (data-free to callers).
	Logger *slog.Logger
}

func (c ControlPlaneCommitter) logf(msg string, args ...any) {
	if c.Logger != nil {
		c.Logger.Warn(msg, args...)
	}
}

// Commit sends one authenticated, bounded feed-commit request, strictly decodes
// and canonically VERIFIES the result against the request, and returns only a
// fixed sentinel class on any failure. A successful result is never returned
// unless its OperationID/Feed/Reference EXACTLY match the (canonicalized)
// request; a mismatched, malformed, or duplicated response is a fail-closed
// backend error, never an accepted success. Every raw network/URL/decode error
// collapses to ErrCommitBackend so no URL/host/port/dial/body leaks through
// err.Error(). There is no retry loop here: safe retries use the same
// OperationID idempotency contract the caller owns.
func (c ControlPlaneCommitter) Commit(ctx context.Context, req FeedCommitRequest) (FeedCommitResult, error) {
	baseURL, err := parseCommitBaseURL(c.BaseURL)
	if err != nil {
		c.logf("internal commit: invalid base URL", "err", err.Error())
		return FeedCommitResult{}, ErrCommitBackend
	}
	if len(c.Secret) == 0 {
		return FeedCommitResult{}, ErrCommitBackend
	}
	if err := validateCommitRequestShape(req); err != nil {
		return FeedCommitResult{}, ErrCommitMalformed
	}
	// The CURRENT protocol (round 3 / Finding 2) mandates the stable/attempt
	// identity split unconditionally: this production client never sends the
	// legacy (PublicationID-omitted) shape, and never silently infers one
	// from a missing field. A caller that leaves PublicationID empty fails
	// closed here, before any network attempt.
	if req.PublicationID == "" {
		return FeedCommitResult{}, ErrCommitMalformed
	}

	body, err := json.Marshal(req)
	if err != nil {
		return FeedCommitResult{}, ErrCommitMalformed
	}
	if len(body) > CommitRequestMaxBody {
		return FeedCommitResult{}, ErrCommitMalformed
	}

	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	reqCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		reqCtx, cancel = context.WithTimeout(ctx, commitRequestTimeout)
		defer cancel()
	}

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, baseURL+InternalFeedUpdatePathV2, bytes.NewReader(body))
	if err != nil {
		return FeedCommitResult{}, ErrCommitMalformed
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(InternalAuthHeader, string(c.Secret))

	resp, err := client.Do(httpReq)
	if err != nil {
		// Raw dial/TLS/timeout detail is correlated locally, never returned.
		c.logf("internal commit: transport failure")
		return FeedCommitResult{}, ErrCommitBackend
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, CommitResponseMaxBody+1))
	if err != nil {
		return FeedCommitResult{}, ErrCommitBackend
	}
	if len(respBody) > CommitResponseMaxBody {
		return FeedCommitResult{}, ErrCommitBackend
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return decodeCommitResult(respBody, req)
	case http.StatusUnauthorized:
		return FeedCommitResult{}, ErrCommitUnauthorized
	case http.StatusBadRequest:
		return FeedCommitResult{}, ErrCommitMalformed
	case http.StatusNotFound:
		return FeedCommitResult{}, ErrCommitUnknownRegistry
	case http.StatusConflict:
		return FeedCommitResult{}, ErrCommitConflict
	case http.StatusPreconditionFailed:
		return FeedCommitResult{}, ErrCommitGenerationConflict
	default:
		// 503 and anything else on the backend side is retryable/dependency.
		return FeedCommitResult{}, ErrCommitBackend
	}
}

// ControlPlaneOrigin is a validated, canonical control-plane internal
// feed-signing origin. It is shared by the request-time committer
// (parseCommitBaseURL → NewControlPlaneCommitter) and the registry's STARTUP
// client builder (cmd/registry buildControlPlaneHTTPClient) so the two can
// never drift: the same scheme, host, userinfo/path/query/fragment and loopback
// rules apply at both call sites. The precedence-of-http-over-loopback rule is
// enforced once here; the TLS trust mode decision is deliberately NOT here
// (trust is an operational concern layered above the origin).
type ControlPlaneOrigin struct {
	scheme   string // "http" or "https"
	host     string // canonical "host[:port]"
	hostname string // host without any port or IPv6 brackets
}

// Scheme returns "http" or "https".
func (o ControlPlaneOrigin) Scheme() string { return o.scheme }

// Host returns the canonical "host[:port]" origin host.
func (o ControlPlaneOrigin) Host() string { return o.host }

// Hostname returns the origin host without any port or IPv6 brackets — the
// correct TLS ServerName (for an https origin) and the loopback test subject.
func (o ControlPlaneOrigin) Hostname() string { return o.hostname }

// IsHTTPS reports whether the origin uses plaintext http=false / https=true.
func (o ControlPlaneOrigin) IsHTTPS() bool { return o.scheme == "https" }

// IsLoopback reports whether the origin host is a loopback address/localhost.
func (o ControlPlaneOrigin) IsLoopback() bool { return isLoopbackHost(o.hostname) }

// String returns the canonical scheme://host[:port] origin.
func (o ControlPlaneOrigin) String() string { return o.scheme + "://" + o.host }

// ParseControlPlaneOrigin validates and canonicalizes an internal feed-signing
// origin: absolute http(s), host required, no userinfo, no path beyond empty
// or "/", no query, no fragment. Plaintext http is allowed ONLY for a loopback
// host (127.0.0.0/8, ::1, or localhost); any other host must use https. Malformed
// and scoped (userinfo/path/query/fragment) forms are rejected. It returns the
// canonical scheme://host[:port] origin. This is the SINGLE origin validator for
// both request-time and startup control-plane wiring, so their policies cannot
// drift. Errors carry no URL data.
func ParseControlPlaneOrigin(raw string) (ControlPlaneOrigin, error) {
	raw = strings.TrimRight(raw, "/")
	if raw == "" {
		return ControlPlaneOrigin{}, errors.New("control plane URL is not configured")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ControlPlaneOrigin{}, errors.New("control plane URL is not an absolute origin")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ControlPlaneOrigin{}, errors.New("control plane URL must be http or https")
	}
	if u.User != nil {
		return ControlPlaneOrigin{}, errors.New("control plane URL must not contain userinfo")
	}
	if u.RawQuery != "" {
		return ControlPlaneOrigin{}, errors.New("control plane URL must not contain a query")
	}
	if u.Fragment != "" {
		return ControlPlaneOrigin{}, errors.New("control plane URL must not contain a fragment")
	}
	if p := u.EscapedPath(); p != "" && p != "/" {
		return ControlPlaneOrigin{}, errors.New("control plane URL must be an origin with no path")
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return ControlPlaneOrigin{}, errors.New("control plane URL uses plaintext http for a non-loopback host")
	}
	return ControlPlaneOrigin{scheme: u.Scheme, host: u.Host, hostname: u.Hostname()}, nil
}

// parseCommitBaseURL is the request-time wrapper over the shared origin
// validator, returning the canonical origin string used by the current commit
// client. Both it and cmd/registry's startup builder call
// ParseControlPlaneOrigin, so the policies are structurally identical.
func parseCommitBaseURL(raw string) (string, error) {
	o, err := ParseControlPlaneOrigin(raw)
	if err != nil {
		return "", err
	}
	return o.String(), nil
}

func isLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	// Strip IPv6 brackets before parsing.
	h := host
	if len(h) > 1 && h[0] == '[' && h[len(h)-1] == ']' {
		h = h[1 : len(h)-1]
	}
	addr, err := netip.ParseAddr(h)
	if err != nil {
		return false // a DNS name is not provably loopback
	}
	return addr.IsLoopback()
}

// decodeCommitResult STRICTLY decodes a bounded successful response: duplicate
// members anywhere, unknown top-level fields, trailing content, malformed or
// unbounded field values, and a result that does not canonically match the
// request are all rejected. Only a fully validated, request-equal result is
// returned as success.
func decodeCommitResult(data []byte, req FeedCommitRequest) (FeedCommitResult, error) {
	if err := rejectDuplicateJSONMembers(data); err != nil {
		return FeedCommitResult{}, ErrCommitBackend
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var result FeedCommitResult
	if err := dec.Decode(&result); err != nil {
		return FeedCommitResult{}, ErrCommitBackend
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return FeedCommitResult{}, ErrCommitBackend
	}
	if err := ValidateCommitResult(result); err != nil {
		return FeedCommitResult{}, ErrCommitBackend
	}
	// Canonical constant/normal comparison of every result field to the
	// request before success; the publisher must never accept an unrelated
	// result.
	if result.OperationID != req.OperationID {
		return FeedCommitResult{}, ErrCommitBackend
	}
	if result.Feed != CanonicalTopic(req.Topic) {
		return FeedCommitResult{}, ErrCommitBackend
	}
	if result.Reference != CanonicalReference(req.Reference) {
		return FeedCommitResult{}, ErrCommitBackend
	}
	return result, nil
}

// validateCommitRequestShape applies the client-side bounded syntax contract.
func validateCommitRequestShape(req FeedCommitRequest) error {
	if err := ValidateOperationID(req.OperationID); err != nil {
		return fmt.Errorf("%w: operationID must be non-empty, bounded, and a JSON-safe printable-ASCII identifier", err)
	}
	if req.PublicationID != "" {
		if err := ValidateOperationID(req.PublicationID); err != nil {
			return fmt.Errorf("%w: publicationID must be bounded and a JSON-safe printable-ASCII identifier", err)
		}
	}
	if req.RegistryID <= 0 {
		return errors.New("registryID must be positive")
	}
	if req.Owner == "" || len(req.Owner) > ownerMaxLen {
		return errors.New("owner must be non-empty and bounded")
	}
	// Topic must be EXACTLY the canonical full-feed wire form
	// (feed://<40 lowercase hex owner>/<64 lowercase hex topic>). This runs
	// BEFORE hashing or reservation so an invalid or non-canonical topic can
	// never collapse into a valid request hash.
	if _, _, err := ParseCanonicalFeed(req.Topic); err != nil {
		return errors.New("topic must be a canonical full feed reference (feed://<40 lowercase hex owner>/<64 lowercase hex topic>)")
	}
	if !IsHexReference(req.Reference) {
		return errors.New("reference must be a 64-hex immutable object reference")
	}
	if req.BatchID == "" || len(req.BatchID) > batchIDMaxLen {
		return errors.New("batchID must be non-empty and bounded")
	}
	if req.ExpectedGeneration < 0 {
		return errors.New("expectedGeneration must be non-negative")
	}
	return nil
}

// ValidateCommitRequest applies the bounded client-side syntax contract so the
// control-plane feed signer and the data-plane client share exactly the same
// acceptance rules.
func ValidateCommitRequest(req FeedCommitRequest) error {
	return validateCommitRequestShape(req)
}

// IsHexReference reports whether s is a 64-character lowercase or uppercase
// hexadecimal immutable object reference.
func IsHexReference(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// ValidateCommitResult enforces the bounded, canonical field contract on a
// FeedCommitResult (used on both the wire response and the stored result).
// Feed must be EXACTLY the canonical full-feed wire form and Reference the
// canonical 64-lowercase-hex form — an invalid or non-canonical value is
// rejected so a mismatched feed/reference can never be accepted as success.
func ValidateCommitResult(result FeedCommitResult) error {
	if err := ValidateOperationID(result.OperationID); err != nil {
		return errors.New("result operationID must be non-empty, bounded, and a JSON-safe printable-ASCII identifier")
	}
	// Feed must be EXACTLY the canonical full-feed wire form, not merely a
	// lowercased string.
	if _, _, err := ParseCanonicalFeed(result.Feed); err != nil {
		return errors.New("result feed must be a canonical full feed reference (feed://<40 lowercase hex owner>/<64 lowercase hex topic>)")
	}
	if !IsHexReference(result.Reference) || result.Reference != CanonicalReference(result.Reference) {
		return errors.New("result reference must be a canonical 64-hex value")
	}
	return nil
}

// isJSONSafeOperationID reports whether s is a JSON-safe printable-ASCII
// operation identifier: every byte is ASCII printable 0x20..0x7e EXCEPT the
// five bytes Go's default JSON encoder escapes (\", \\, <, >, &). Such a string
// is emitted VERBATIM by json.Marshal — no \uXXXX, \n, \", or <>& escapes — so
// the canonical succeeded result can be reconstructed byte-for-byte as a plain
// SQLite concatenation, exactly what the DB result-integrity trigger requires.
// It doubles as the stable OperationID alphabet Task 10's durable idempotency
// accepts (a result's operationID must equal its request's, so constraining it
// at the request ALSO keeps the stored result byte-exact).
func isJSONSafeOperationID(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e ||
			c == '"' || c == '\\' || c == '<' || c == '>' || c == '&' {
			return false
		}
	}
	return true
}

// ValidateOperationID enforces the application operation-ID grammar on a
// single candidate operation identifier. It is the single Go authority for
// Task 10's operation-ID alphabet and is applied to BOTH the request's
// OperationID (via ValidateCommitRequest) and the result's OperationID (via
// ValidateCommitResult). A valid operation ID is:
//
//   - non-empty and at most OperationIDMaxLen (128) bytes;
//   - every byte an ASCII printable 0x20..0x7e except the five Go-JSON-escaped
//     bytes `"`, `\`, `<`, `>`, `&`; and therefore
//   - free of controls (0x00..0x1f), DEL (0x7f), and any non-ASCII byte
//     (>= 0x80, including the JSON-escaping code points U+2028 / U+2029).
//
// The database operation-ID grammar (migration 13's identity triggers) is a
// byte-parity mirror of THIS function — the two MUST agree on the same valid
// set, which the parity tests prove exhaustively — so a persisted operation ID
// can never be a value Go would reject, and json.Marshal always emits it
// verbatim (the premise of the canonical-result byte-exact invariant).
func ValidateOperationID(opID string) error {
	if opID == "" || len(opID) > OperationIDMaxLen {
		return errors.New("operationID must be non-empty and bounded")
	}
	if !isJSONSafeOperationID(opID) {
		return errors.New("operationID must be a bounded JSON-safe printable-ASCII identifier (no \", \\, <, >, &, controls, DEL, or non-ASCII)")
	}
	return nil
}

// CanonicalFeedCommitResultJSON returns the EXACT canonical byte form of a
// validated FeedCommitResult: the fixed Go struct field order (operationID,
// feed, reference) with every value emitted as a JSON-safe literal. Because
// operationID is constrained to a JSON-safe printable-ASCII alphabet and
// feed/reference are lowercase-hex wire forms (no <, >, &, ", \, control, or
// non-ASCII bytes), Go's json.Marshal would emit them VERBATIM with no
// escaping — so this fixed concatenation IS byte-for-byte the canonical layout
// every persisted result must match, and it is the exact string the DB
// result-integrity trigger reconstructs in SQLite with plain concatenation.
// Callers MUST have validated the result with ValidateCommitResult first.
func CanonicalFeedCommitResultJSON(result FeedCommitResult) []byte {
	return []byte(`{"operationID":"` + result.OperationID + `","feed":"` + result.Feed + `","reference":"` + result.Reference + `"}`)
}

// rejectDuplicateJSONMembers rejects duplicate member names anywhere in a JSON
// object so encoding/json's last-wins behavior cannot silently accept a
// duplicated control-plane result field.
func rejectDuplicateJSONMembers(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return walkJSON(dec)
}

func walkJSON(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			members := make(map[string]struct{})
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyTok.(string)
				if !ok {
					return errors.New("invalid object key")
				}
				if _, dup := members[key]; dup {
					return fmt.Errorf("duplicate object member %q", key)
				}
				members[key] = struct{}{}
				if err := walkJSON(dec); err != nil {
					return err
				}
			}
			_, err := dec.Token()
			return err
		case '[':
			for dec.More() {
				if err := walkJSON(dec); err != nil {
					return err
				}
			}
			_, err := dec.Token()
			return err
		default:
			return errors.New("unexpected delimiter")
		}
	case string, json.Number, bool, nil:
		return nil
	default:
		return errors.New("unexpected token")
	}
}

// ComputeOperationID derives a stable, deterministic, PROVISIONAL operation ID
// for a logical repository publication from its immutable identity: registry,
// owner, repository, tag, the manifest content digest, and the expected
// (current) generation. It canonicalizes the owner (via NormalizeOwner) and
// encodes every typed field with binary fixed-width (int64) or length-prefixed
// (string) framing so no NUL/separator byte inside a value can create a field
// boundary collision. Because it is a pure function of the immutable logical
// publication, retrying the SAME publication computes the same OperationID.
//
// NOTE: Task 14 owns the FINAL stable-operation-ID and read-after-write retry
// semantics at the manifest-PUT caller boundary. This provisional form keeps
// the current caller wiring buildable and durable-idempotent for a supplied
// OperationID, but does NOT itself solve Task 14's public retry contract.
func ComputeOperationID(registryID int64, owner string, repo string, tag string, manifestDigest string, expectedGeneration int64) string {
	h := sha256.New()
	h.Write([]byte("uncloud-registry-feed-commit-op:v1\x00"))
	writeInt64Field(h, registryID)
	writeStringField(h, spec.NormalizeOwner(owner))
	writeStringField(h, repo)
	writeStringField(h, tag)
	writeStringField(h, manifestDigest)
	writeInt64Field(h, expectedGeneration)
	return hex.EncodeToString(h.Sum(nil))
}

// DeterministicUpdatedAt derives the repo-state UpdatedAt timestamp for a
// logical publication as a PURE function of its operation identity. A retry of
// the same publication (the same client request or an identical lost-response
// retry, which compute the same operation ID) therefore rebuilds
// BYTE-IDENTICAL repo-state bytes — the precondition for the control plane's
// durable request-hash idempotency and for restart-safe read-after-write
// retries. It intentionally NEVER consults the wall clock: time-varying state
// would make every rebuilt document differ and defeat byte-stable rebuilds.
// The value is a deterministic RFC3339 UTC timestamp seeded by the operation
// ID's digest, inside a fixed anchored window.
func DeterministicUpdatedAt(operationID string) string {
	sum := sha256.Sum256([]byte("uncloud-registry-updated-at:v1\x00" + operationID))
	// Map the digest onto a fixed one-year window anchored in the past so the
	// timestamp is always parseable, deterministic, and never wall-clock.
	anchor := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	seconds := int64(binary.BigEndian.Uint64(sum[:8]))
	offset := seconds % (366 * 24 * 3600)
	return anchor.Add(time.Duration(offset) * time.Second).UTC().Format(time.RFC3339)
}

// ComputeCommitAttemptID derives the deterministic identity of ONE feed-commit
// ATTEMPT from its stable logical publicationID plus the exact fields that
// distinguish one attempt from another: the registry, owner, topic, the
// immutable reference the attempt targets, and its expected generation. Two
// attempts of the SAME logical publication (a conflict rebuild, or a crash
// retry) derive the SAME attempt id iff they target the IDENTICAL
// generation and reference; a rebuilt attempt at a fresh generation/reference
// always derives a FRESH attempt id, so the durable FeedSigner operation row
// it reserves can never collide with a prior attempt's permanently-fixed
// request hash. Topic and Reference are canonicalized first so an equivalent
// non-canonical spelling derives the identical attempt id.
func ComputeCommitAttemptID(publicationID string, registryID int64, owner string, topic string, reference string, expectedGeneration int64) string {
	h := sha256.New()
	h.Write([]byte("uncloud-registry-feed-commit-attempt:v1\x00"))
	writeStringField(h, publicationID)
	writeInt64Field(h, registryID)
	writeStringField(h, spec.NormalizeOwner(owner))
	writeStringField(h, CanonicalTopic(topic))
	writeStringField(h, CanonicalReference(reference))
	writeInt64Field(h, expectedGeneration)
	return hex.EncodeToString(h.Sum(nil))
}

func writeStringField(h io.Writer, s string) {
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(s)))
	h.Write(lb[:])
	h.Write([]byte(s))
}

func writeInt64Field(h io.Writer, v int64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(v))
	h.Write(b[:])
}
