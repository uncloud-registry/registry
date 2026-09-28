package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/config"
	"github.com/uncloud-registry/registry/internal/credential"
	"github.com/uncloud-registry/registry/internal/policy"
	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/registry"
	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/staging"
	"github.com/uncloud-registry/registry/internal/swarm"
)

func main() {
	addr := envOrDefault("REGISTRY_ADDR", ":8080")
	handler, err := buildHandler()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("registry listening on %s", addr)
	serveErr := http.ListenAndServe(addr, handler)
	// Close durable staging (spool root + SQLite) on shutdown; never leak the
	// handle. Drivers that didn't open real state (in-memory) close as a no-op.
	if c, ok := handler.(io.Closer); ok {
		if closeErr := c.Close(); closeErr != nil {
			log.Printf("registry close: %v", closeErr)
		}
	}
	if serveErr != nil {
		log.Fatal(serveErr)
	}
}

func buildHandler() (http.Handler, error) {
	switch envOrDefault("REGISTRY_BACKEND", "memory") {
	case "memory":
		return buildMemoryHandler()
	case "bee":
		return buildBeeHandler()
	default:
		return nil, fmt.Errorf("unsupported REGISTRY_BACKEND %q", os.Getenv("REGISTRY_BACKEND"))
	}
}

func buildMemoryHandler() (http.Handler, error) {
	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	authRealm := envOrDefault("REGISTRY_AUTH_REALM", "https://auth.uncloud-registry.com/token")
	authenticator, err := buildAuthenticator()
	if err != nil {
		return nil, err
	}

	return registry.NewHandler(
		resolve.RegistryResolver{
			Registries: resolve.StaticRegistryIdentityResolver{Hosts: map[string]resolve.RegistryIdentity{}},
			Docs:       docs,
			Feeds:      feeds,
		},
		docs,
		docs,
		policy.PullAuthorizer{Policies: policy.AuthPolicyResolver{Docs: docs, Feeds: feeds}},
		policy.PushAuthorizer{
			AuthPolicies:  policy.AuthPolicyResolver{Docs: docs, Feeds: feeds},
			StampPolicies: policy.StampPolicyResolver{Docs: docs, Feeds: feeds},
		},
		authenticator,
		staging.NewMemoryStore(),
		publish.Publisher{
			Builder: publish.DefaultBuilder{},
			Objects: docs,
			Feeds:   feeds,
		},
		nil,
		authRealm,
	), nil
}

// buildStagingService constructs the durable Task 15 staging service from a
// fully validated RegistryConfig, applies the atomic quota + stream buffer,
// and returns it as the registry-facing RegistryStore. It is only called
// AFTER every security-sensitive configuration and credential has validated,
// so an invalid config can never open a database or sidecar.
func buildStagingService(rc config.RegistryConfig) (staging.RegistryStore, error) {
	svc, err := staging.NewService(context.Background(), rc.StagingRoot, rc.StagingDB)
	if err != nil {
		return nil, err
	}
	svc.SetLimits(staging.Limits{
		MaxUploadBytes:       rc.MaxUploadBytes,
		MaxRepositoryBytes:   rc.MaxRepositoryBytes,
		MaxTotalStagingBytes: rc.MaxTotalStagingBytes,
	})
	svc.SetStreamBuffer(rc.StreamBufferBytes)
	return svc, nil
}

func buildBeeHandler() (http.Handler, error) {
	beeURL := strings.TrimSpace(os.Getenv("BEE_API_URL"))
	if beeURL == "" {
		return nil, fmt.Errorf("BEE_API_URL is required when REGISTRY_BACKEND=bee")
	}
	// Fail closed BEFORE any listener/client: the Bee base URL must be an
	// absolute http(s) ORIGIN (no userinfo/path/query/fragment).
	if err := validateBeeBaseURL(beeURL); err != nil {
		return nil, fmt.Errorf("BEE_API_URL: %w", err)
	}
	docs := swarm.NewBeeDocumentStore(beeURL, http.DefaultClient)
	objects := swarm.NewBeeObjectStore(beeURL, http.DefaultClient)
	// Production Bee read layering (Task 13): repository/auth/stamp feeds are
	// resolved through the BeeFeedResolver — GET /feeds/{owner}/{topic}
	// returns the 32 RAW BINARY payload bytes (with the required index
	// headers), which it decodes to the canonical immutable 64-hex reference.
	// The BeeDocumentStore serves ONLY immutable /bzz/{ref} document reads,
	// and BeeObjectStore serves objects. IdentityFeedResolver is NEVER used in
	// Bee mode: its in-memory identity pairing exists for identity mode and
	// would mis-decode binary feed payloads.
	feeds := swarm.NewBeeFeedResolver(beeURL, http.DefaultClient)
	authRealm := envOrDefault("REGISTRY_AUTH_REALM", "https://auth.uncloud-registry.com/token")
	authenticator, err := buildAuthenticator()
	if err != nil {
		return nil, err
	}
	registryResolver, err := buildRegistryIdentityResolver()
	if err != nil {
		return nil, err
	}

	// Bee-mode repository-state commits go exclusively through the control
	// plane's internal feed signer. The registry process NEVER holds or accepts
	// the feed-owner signing key: BEE_FEED_SIGNER_PRIVATE_KEY is not read in
	// Bee mode, and there is no local signer. Fail closed if the control-plane
	// URL or the shared internal credential is not configured, and require an
	// unambiguous control-plane RegistryID for every resolved host.
	cpURL := strings.TrimSpace(os.Getenv("CONTROLPLANE_URL"))
	if cpURL == "" {
		return nil, fmt.Errorf("CONTROLPLANE_URL is required when REGISTRY_BACKEND=bee (repository feed commits are signed by the control plane)")
	}
	secretPath, err := envRequired("CONTROLPLANE_INTERNAL_SECRET_FILE")
	if err != nil {
		return nil, fmt.Errorf("registry-to-control-plane credential: %w", err)
	}
	internalSecret, err := credential.LoadSecretFile(secretPath)
	if err != nil {
		return nil, err
	}
	if err := credential.ValidateSecret(internalSecret); err != nil {
		return nil, err
	}
	cpHTTPClient, err := buildControlPlaneHTTPClient(cpURL)
	if err != nil {
		return nil, err
	}
	if err := requireRegistryIDs(registryResolver); err != nil {
		return nil, err
	}

	committer := &publish.ControlPlaneCommitter{
		BaseURL:    cpURL,
		Secret:     internalSecret,
		HTTPClient: cpHTTPClient,
	}
	binder := &publish.ControlPlaneOperationBinder{
		BaseURL:    cpURL,
		Secret:     internalSecret,
		HTTPClient: cpHTTPClient,
	}

	// Durable bounded uploads (Task 16): the staging config is validated
	// BEFORE any database is opened or any listener exposed, and the durable
	// Task 15 service enforces the atomic per-upload/repo/total quotas inside
	// BEGIN IMMEDIATE transactions.
	stageCfg, err := config.LoadRegistryConfig()
	if err != nil {
		return nil, fmt.Errorf("registry staging config: %w", err)
	}
	stageStore, err := buildStagingService(stageCfg)
	if err != nil {
		return nil, fmt.Errorf("staging service: %w", err)
	}

	// Shared production resolver used by both the handler and the cleanup's
	// committed-repository-state provider (so cleanup never unpins a blob a
	// committed publication still references).
	resolver := resolve.RegistryResolver{
		Registries: registryResolver,
		Docs:       docs,
		Feeds:      feeds,
	}

	// Task 18: bounded periodic cleanup of expired staging. The cleanup unpins
	// an expired finalized blob's Bee content and removes it, but refuses to
	// unpin or remove any blob still referenced by committed repository state.
	// The loop honors context cancellation. The staging store handed to the
	// handler is wrapped so that closing the handler cancels the loop BEFORE
	// the underlying staging service (spool + SQLite) is released.
	cleanup, err := buildCleanup(stageStore, objects, resolver)
	if err != nil {
		return nil, fmt.Errorf("staging cleanup: %w", err)
	}
	interval, err := cleanupIntervalFromEnv()
	if err != nil {
		return nil, err
	}
	batch, err := cleanupBatchFromEnv()
	if err != nil {
		return nil, err
	}
	cleanupCtx, cancelCleanup := context.WithCancel(context.Background())
	cleanupDone := runCleanupLoop(cleanupCtx, cleanup, interval, batch)
	closeSvc := func() error { return nil }
	if ic, ok := stageStore.(io.Closer); ok {
		closeSvc = ic.Close
	}
	stageStore = &cancelOnCloseStore{RegistryStore: stageStore, cancel: cancelCleanup, done: cleanupDone, close: closeSvc}

	handler := registry.NewHandler(
		resolver,
		objects,
		objects,
		policy.PullAuthorizer{Policies: policy.AuthPolicyResolver{Docs: docs, Feeds: feeds}},
		policy.PushAuthorizer{
			AuthPolicies:  policy.AuthPolicyResolver{Docs: docs, Feeds: feeds},
			StampPolicies: policy.StampPolicyResolver{Docs: docs, Feeds: feeds},
		},
		authenticator,
		stageStore,
		publish.Publisher{
			Builder: publish.DefaultBuilder{},
			Objects: objects,
			Commits: committer,
		},
		binder,
		authRealm,
	)
	if rh, ok := handler.(*registry.Handler); ok {
		rh.MaxUploadBytes = stageCfg.MaxUploadBytes
		rh.SessionTTL = stageCfg.UploadTTL
	}
	return handler, nil
}

// ---------------------------------------------------------------------------
// Task 18: periodic staging cleanup wiring.
// ---------------------------------------------------------------------------

// committedRefProvider resolves the Bee refs currently referenced by committed
// repository state for a repo, across every registry identity the resolver
// serves. A repo's committed state document's Blobs are the contents a live
// publication references; their refs must never be unpinned. A conclusive
// absent feed yields no refs; any resolution error FAILS CLOSED so the cleanup
// refuses to unpin without authoritative committed-state knowledge. No
// configured identity also fails closed (an empty committed set would silently
// permit unpinning published blobs).
type committedRefProvider struct {
	resolver   resolve.RegistryResolver
	identities []resolve.RegistryIdentity
}

func (p *committedRefProvider) CommittedRefs(ctx context.Context, repo string) (map[string]struct{}, error) {
	if len(p.identities) == 0 {
		return nil, errors.New("cleanup committed-state provider has no registry identity")
	}
	refs := make(map[string]struct{})
	for _, id := range p.identities {
		doc, found, err := p.resolver.ResolveRepoStateOptional(ctx, id, repo)
		if err != nil {
			// Fail closed: without authoritative committed-state knowledge we
			// must not unpin anything this pass.
			return nil, err
		}
		if !found {
			continue
		}
		for _, blob := range doc.Blobs {
			if blob.SwarmRef != "" {
				refs[swarm.CanonicalObjectRef(blob.SwarmRef)] = struct{}{}
			}
		}
	}
	return refs, nil
}

// registryIdentities extracts the static host -> RegistryIdentity map as a
// slice. Bee-mode requires exactly such a static map (see requireRegistryIDs);
// anything else cannot scope a repo to a feed owner and fails closed.
func registryIdentities(r resolve.RegistryIdentityResolver) ([]resolve.RegistryIdentity, error) {
	static, ok := r.(resolve.StaticRegistryIdentityResolver)
	if !ok {
		return nil, errors.New("Bee-mode staging cleanup requires a static registry identity map")
	}
	ids := make([]resolve.RegistryIdentity, 0, len(static.Hosts))
	for _, id := range static.Hosts {
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil, errors.New("Bee-mode staging cleanup requires at least one mapped registry identity")
	}
	return ids, nil
}

// buildCleanup constructs the staging Cleanup over the durable service held by
// stageStore, unpinning through the Bee object store and gating eligibility on
// the committed repository state so a published blob is never unpinned.
func buildCleanup(stageStore staging.RegistryStore, unpin staging.Unpinner, resolver resolve.RegistryResolver) (*staging.Cleanup, error) {
	identities, err := registryIdentities(resolver.Registries)
	if err != nil {
		return nil, err
	}
	committed := &committedRefProvider{resolver: resolver, identities: identities}
	return staging.NewCleanup(stageStore, unpin, committed)
}

// Env knobs for the periodic cleanup loop.
const (
	envCleanupInterval      = "REGISTRY_CLEANUP_INTERVAL"
	envCleanupBatch         = "REGISTRY_CLEANUP_BATCH"
	defaultCleanupInterval  = 5 * time.Minute
	defaultCleanupBatchSize = 100
	// maxCleanupBatchSize is the documented finite upper bound on a per-pass
	// cleanup batch. A single pass is a tightly-bounded, non-overlapping unit
	// of work and the periodic loop is the only writer, so unbounded values
	// serve no purpose and would only enlarge the shutdown-join window (and the
	// per-pass committed-state revalidation cost). Any configured batch above
	// this fails closed rather than being silently clamped.
	maxCleanupBatchSize = 10000
	// cleanupShutdownTimeout bounds the graceful shutdown join: after
	// cancelling the loop, the handler Close waits up to this long for an
	// in-flight cleanup pass to finish before releasing the staging store, so
	// the SQLite/spool close can never race a pass that is mid-transaction.
	// A pathological pass that exceeds the bound is conceded (the store is
	// closed anyway) rather than hanging shutdown indefinitely.
	cleanupShutdownTimeout = 5 * time.Second
)

// cleanupIntervalFromEnv reads the cleanup loop interval (a positive duration)
// strictly; an unset value uses the default and a malformed value fails closed.
func cleanupIntervalFromEnv() (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(envCleanupInterval))
	if raw == "" {
		return defaultCleanupInterval, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", envCleanupInterval)
	}
	return d, nil
}

// cleanupBatchFromEnv reads the per-pass candidate batch bound strictly: an
// unset value uses the default, a positive value within the documented finite
// maximum is honored, and a non-positive or over-the-maximum value FAILS
// CLOSED (never silently clamped, never read as a default).
func cleanupBatchFromEnv() (int, error) {
	raw := strings.TrimSpace(os.Getenv(envCleanupBatch))
	if raw == "" {
		return defaultCleanupBatchSize, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", envCleanupBatch)
	}
	if n > maxCleanupBatchSize {
		return 0, fmt.Errorf("%s must not exceed %d", envCleanupBatch, maxCleanupBatchSize)
	}
	return n, nil
}

// runCleanupLoop runs one bounded cleanup pass per interval until ctx is
// canceled, logging the per-class counts only when work was examined. It is
// safe to call once per process. It returns a channel closed exactly when the
// loop goroutine has fully exited (no pass is still in flight), so a caller
// can cancel and JOIN the loop before releasing the underlying staging store.
func runCleanupLoop(ctx context.Context, cleanup *staging.Cleanup, interval time.Duration, batch int) <-chan struct{} {
	done := make(chan struct{})
	if cleanup == nil {
		close(done)
		return done
	}
	if interval <= 0 {
		interval = defaultCleanupInterval
	}
	if batch <= 0 {
		batch = defaultCleanupBatchSize
	}
	if batch > maxCleanupBatchSize {
		batch = maxCleanupBatchSize
	}
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				res, err := cleanup.RunOnce(ctx, time.Now(), batch)
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					log.Printf("staging cleanup: %v", err)
					continue
				}
				if res.Examined > 0 {
					log.Printf("staging cleanup: examined=%d expired=%d removed=%d unpinned=%d failed=%d",
						res.Examined, res.Expired, res.Removed, res.Unpinned, res.Failed)
				}
			}
		}
	}()
	return done
}

// cancelOnCloseStore wraps the durable staging store so that closing the
// handler (registry.Handler.Close closes h.Staging when it is an io.Closer)
// cancels the periodic cleanup loop and then JOINS it (bounded) BEFORE the
// underlying staging service (spool + database) is released. Cancellation
// alone is not a work-completion signal: a pass already mid-transaction keeps
// running until it observes ctx — so the close waits on the loop's done
// channel (up to cleanupShutdownTimeout) to ensure no in-flight pass races the
// SQLite/spool teardown. The registry-facing RegistryStore contract is
// otherwise unchanged.
type cancelOnCloseStore struct {
	staging.RegistryStore
	cancel func()
	done   <-chan struct{}
	close  func() error
}

func (s *cancelOnCloseStore) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	// Join the cleanup loop: a canceled context does not mean a pass has
	// finished, and releasing the store while one is mid-SQL would be unsafe.
	if s.done != nil {
		timer := time.NewTimer(cleanupShutdownTimeout)
		defer timer.Stop()
		select {
		case <-s.done:
		case <-timer.C:
			// A pathological pass exceeded the bound: concede and close anyway
			// rather than hang shutdown (documented in cleanupShutdownTimeout).
		}
	}
	if s.close != nil {
		return s.close()
	}
	return nil
}

// validateBeeBaseURL rejects anything but an absolute http/https ORIGIN with
// no userinfo, query, fragment, or non-root path — enforced BEFORE the
// registry listener or any Bee client is built (task-13 config fail-closed).
// The error is data-free (never echoes the offending URL).
func validateBeeBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("BEE_API_URL is not a valid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("BEE_API_URL must be an absolute http or https URL")
	}
	if u.Host == "" {
		return errors.New("BEE_API_URL must include a host")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("BEE_API_URL must be an origin with no userinfo, query, or fragment")
	}
	if p := u.EscapedPath(); p != "" && p != "/" {
		return errors.New("BEE_API_URL must be an origin with no path")
	}
	return nil
}

// buildControlPlaneHTTPClient builds the DEDICATED HTTP client the registry
// uses to reach the control-plane internal feed-signing listener. It NEVER
// mutates the process-global http.DefaultTransport: a private self-hosted
// control plane is reached over an https URL authenticated by a PRIVATE CA
// bundle, loaded and validated BEFORE the registry listener starts.
//
// The origin itself is validated by publish.ParseControlPlaneOrigin — the SAME
// validator the request-time committer uses — so the two call sites cannot
// drift: plaintext http is allowed only for a loopback host, and userinfo, path
// (beyond "/"), query, fragment, and malformed/scoped forms are all rejected.
//
// TLS trust is strictly controlled:
//   - Plaintext http (provably loopback after origin validation) requires NO
//     trust mode; if either CONTROLPLANE_CA_BUNDLE_FILE or
//     CONTROLPLANE_USE_SYSTEM_ROOTS is set, startup FAILS rather than
//     silently ignoring an HTTPS-only trust setting on a plaintext origin.
//   - An https control-plane URL requires EXACTLY ONE explicit trust mode: a
//     non-empty CONTROLPLANE_CA_BUNDLE_FILE, XOR CONTROLPLANE_USE_SYSTEM_ROOTS=1.
//     Missing BOTH fails startup (never silently falling back to the process
//     root pool); having BOTH fails startup (never silently preferring one).
//     CONTROLPLANE_USE_SYSTEM_ROOTS accepts only "1", "0", or unset — any other
//     value (e.g. "true", "yes") fails startup rather than being read as false.
//
// For an https origin the TLS config carries a dedicated transport clone, the
// chosen root pool, MinVersion TLS1.2, and ServerName pinned from the exact
// origin host (defeats host spoofing). Errors carry no URL/data/path content.
func buildControlPlaneHTTPClient(cpURL string) (*http.Client, error) {
	origin, err := publish.ParseControlPlaneOrigin(cpURL)
	if err != nil {
		return nil, fmt.Errorf("CONTROLPLANE_URL: %w", err)
	}

	base := http.DefaultTransport.(*http.Transport).Clone()

	caBundle := strings.TrimSpace(os.Getenv("CONTROLPLANE_CA_BUNDLE_FILE"))
	useSystemRoots, boolErr := parseSystemRootsEnv()
	if boolErr != nil {
		return nil, boolErr
	}

	if !origin.IsHTTPS() {
		// Provably loopback after origin validation. A CA bundle or system-roots
		// trust setting is MEANINGLESS on plaintext http: fail startup rather
		// than silently ignore an operator's HTTPS-only trust configuration.
		if caBundle != "" || useSystemRoots {
			return nil, errors.New("CONTROLPLANE_CA_BUNDLE_FILE and CONTROLPLANE_USE_SYSTEM_ROOTS are HTTPS-only settings and are rejected on a plaintext http control-plane URL")
		}
		return &http.Client{Transport: base}, nil
	}

	// An https origin requires EXACTLY ONE explicit trust mode.
	if caBundle != "" && useSystemRoots {
		return nil, errors.New("CONTROLPLANE_CA_BUNDLE_FILE and CONTROLPLANE_USE_SYSTEM_ROOTS are mutually exclusive: an https control-plane URL requires exactly one explicit trust mode")
	}
	if caBundle == "" && !useSystemRoots {
		return nil, errors.New("the https control-plane URL requires exactly one explicit trust mode: set CONTROLPLANE_CA_BUNDLE_FILE or CONTROLPLANE_USE_SYSTEM_ROOTS=1")
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: origin.Hostname(), // from the EXACT origin host, never from SNI spoofing
	}
	switch {
	case caBundle != "":
		pool, err := credential.LoadCACertPool(caBundle)
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = pool
	default:
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			return nil, errors.New("failed to load the system root CA pool")
		}
		tlsConfig.RootCAs = pool
	}
	base.TLSClientConfig = tlsConfig
	return &http.Client{Transport: base}, nil
}

// parseSystemRootsEnv reads CONTROLPLANE_USE_SYSTEM_ROOTS into a strict boolean.
// Only "1", "0", or an unset value are accepted; any other form (e.g. "true",
// "yes", "on") fails closed rather than being silently read as false, so an
// operator typo can never silently disable explicit system-roots trust.
func parseSystemRootsEnv() (bool, error) {
	switch strings.TrimSpace(os.Getenv("CONTROLPLANE_USE_SYSTEM_ROOTS")) {
	case "", "0":
		return false, nil
	case "1":
		return true, nil
	default:
		return false, errors.New("CONTROLPLANE_USE_SYSTEM_ROOTS must be 1, 0, or unset")
	}
}

// requireRegistryIDs fails closed unless every host the registry resolver can
// serve resolves to an unambiguous positive control-plane RegistryID. Bee-mode
// feed commits are routed by RegistryID; silently assigning or defaulting an ID
// would route a commit to the wrong registry. Multi-host static mappings remain
// supported (each host carries its own ID); ENS resolution (which yields only a
// feed-owner, never a control-plane RegistryID) is therefore rejected in Bee
// mode.
func requireRegistryIDs(resolver resolve.RegistryIdentityResolver) error {
	static, ok := resolver.(resolve.StaticRegistryIdentityResolver)
	if !ok {
		return fmt.Errorf("Bee-mode repository feed commits require an explicit host→registryID map (REGISTRY_ID_MAP); resolution mode must be static")
	}
	for host, identity := range static.Hosts {
		if identity.RegistryID <= 0 {
			return fmt.Errorf("Bee-mode repository feed commands require a positive registryID for host %q; configure REGISTRY_ID_MAP", host)
		}
	}
	if len(static.Hosts) == 0 {
		return fmt.Errorf("Bee-mode repository feed commits require at least one host mapped to a registryID (REGISTRY_ID_MAP)")
	}
	return nil
}

func envOrDefault(name string, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

// envRequired returns a nonblank env value or an error. It is used for
// settings whose absence must fail startup: fail-closed registry
// authentication never falls back to an optional or shared-secret mode.
func envRequired(name string) (string, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return "", fmt.Errorf("%s must be set", name)
	}
	return value, nil
}

// buildAuthenticator constructs the fail-closed registry token verifier from
// REQUIRED production configuration:
//
//   - REGISTRY_TOKEN_PUBLIC_KEYS_FILE: strict JWKS file (Ed25519 OKP keys
//     only; see auth.LoadJWKSFromFile). Startup fails when absent, unreadable,
//     malformed, empty, or containing anything but Ed25519 public keys.
//   - REGISTRY_TOKEN_ISSUER: the exact issuer every registry token must carry.
//   - REGISTRY_TOKEN_AUDIENCE: a STRICT comma-separated allowlist of exact
//     registry hosts (auth.ParseAudienceAllowlist). Blank elements, surrounding
//     or interior whitespace, duplicates, wildcards, and malformed hosts fail
//     startup, as does an empty list. Each allowed host gets exact
//     singleton-audience verification via auth.MultiServiceVerifier: the
//     resolved request service must be in the allowlist (hosts outside it fail
//     before any token verification), and a token must carry exactly that
//     service in its service claim and single audience. This supports at least
//     two owner-map hosts in one process with host-specific tokens.
//
// Supported production platforms for keys-file loading: macOS and Linux. On
// every other platform auth.LoadJWKSFromFile fails closed with
// auth.ErrJWKSFileLoadingUnsupported (it never opens or reads the keys file
// through a weaker fallback), so startup aborts here — the registry does not
// silently run with a racy Lstat-then-open load on any GOOS.
//
// The three settings are consumed by the verifier — they are not parsed and
// ignored. Key material is never logged or included in errors.
func buildAuthenticator() (registry.Authenticator, error) {
	jwksPath, err := envRequired("REGISTRY_TOKEN_PUBLIC_KEYS_FILE")
	if err != nil {
		return nil, fmt.Errorf("registry token verification configuration: %w", err)
	}
	issuer, err := envRequired("REGISTRY_TOKEN_ISSUER")
	if err != nil {
		return nil, fmt.Errorf("registry token verification configuration: %w", err)
	}
	// Read the RAW value: envRequired would trim surrounding whitespace, which
	// must instead reach ParseAudienceAllowlist so it can be rejected (the
	// strict list contract also covers the empty/blank cases).
	audiences, err := auth.ParseAudienceAllowlist(os.Getenv("REGISTRY_TOKEN_AUDIENCE"))
	if err != nil {
		return nil, fmt.Errorf("registry token verification configuration: %w", err)
	}
	keys, err := auth.LoadJWKSFromFile(jwksPath)
	if err != nil {
		return nil, err
	}
	verifier, err := auth.NewMultiServiceVerifier(keys, issuer, audiences)
	if err != nil {
		return nil, fmt.Errorf("registry token verification configuration: %w", err)
	}
	return registry.BearerAuthenticator{Tokens: verifier}, nil
}

func parseRegistryOwners(raw string) map[string]string {
	owners := map[string]string{}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.SplitN(item, "=", 2)
		if len(parts) != 2 {
			continue
		}
		host := strings.TrimSpace(parts[0])
		owner := strings.TrimSpace(parts[1])
		if host == "" || owner == "" {
			continue
		}
		owners[host] = owner
	}
	return owners
}

func buildRegistryIdentityResolver() (resolve.RegistryIdentityResolver, error) {
	switch envOrDefault("REGISTRY_RESOLUTION_MODE", "static") {
	case "static":
		return staticRegistryIdentityResolverFromEnv(), nil
	case "ens":
		rpcURL := strings.TrimSpace(os.Getenv("ETH_RPC_URL"))
		if rpcURL == "" {
			return nil, fmt.Errorf("ETH_RPC_URL is required when REGISTRY_RESOLUTION_MODE=ens")
		}
		suffix := strings.TrimSpace(os.Getenv("REGISTRY_ENS_SUFFIX"))
		if suffix == "" {
			return nil, fmt.Errorf("REGISTRY_ENS_SUFFIX is required when REGISTRY_RESOLUTION_MODE=ens")
		}
		resolver := resolve.ENSRegistryIdentityResolver{
			DomainSuffix: suffix,
			RPCURL:       rpcURL,
			HTTPClient:   http.DefaultClient,
		}
		if addr := strings.TrimSpace(os.Getenv("ENS_REGISTRY_ADDRESS")); addr != "" {
			resolver.ENSRegistryAddr = common.HexToAddress(addr)
		}
		return resolver, nil
	default:
		return nil, fmt.Errorf("unsupported REGISTRY_RESOLUTION_MODE %q", os.Getenv("REGISTRY_RESOLUTION_MODE"))
	}
}

func staticRegistryIdentityResolverFromEnv() resolve.RegistryIdentityResolver {
	owners := parseRegistryOwners(os.Getenv("REGISTRY_OWNER_MAP"))
	ids := parseRegistryIDs(os.Getenv("REGISTRY_ID_MAP"))
	hosts := make(map[string]resolve.RegistryIdentity, len(owners))
	for host, owner := range owners {
		regID := ids[host]
		hosts[host] = resolve.RegistryIdentity{
			Host:       host,
			Owner:      owner,
			RegistryID: regID,
		}
	}
	return resolve.StaticRegistryIdentityResolver{Hosts: hosts}
}

// parseRegistryIDs parses a CSV "host=id" map naming each host's unambiguous
// control-plane RegistryID. Every value must be canonical positive decimal text
// so a malformed or non-positive value cannot silently become a zero/assigned
// ID; the caller (Bee mode) then fails closed unless every served host has one.
func parseRegistryIDs(raw string) map[string]int64 {
	ids := map[string]int64{}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.SplitN(item, "=", 2)
		if len(parts) != 2 {
			continue
		}
		host := strings.TrimSpace(parts[0])
		if host == "" {
			continue
		}
		idText := strings.TrimSpace(parts[1])
		id, err := strconv.ParseInt(idText, 10, 64)
		if err != nil || id <= 0 {
			// A malformed or non-positive id can never be used as a registry ID;
			// leave the host unmapped so fail-closed validation catches it.
			continue
		}
		ids[host] = id
	}
	return ids
}
