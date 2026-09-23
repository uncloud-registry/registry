package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/uncloud-registry/registry/internal/auth"
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
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatal(err)
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
		authRealm,
	), nil
}

func buildBeeHandler() (http.Handler, error) {
	beeURL := strings.TrimSpace(os.Getenv("BEE_API_URL"))
	if beeURL == "" {
		return nil, fmt.Errorf("BEE_API_URL is required when REGISTRY_BACKEND=bee")
	}
	docs := swarm.NewBeeDocumentStore(beeURL, http.DefaultClient)
	objects := swarm.NewBeeObjectStore(beeURL, http.DefaultClient)
	feeds := swarm.IdentityFeedResolver{}
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

	return registry.NewHandler(
		resolve.RegistryResolver{
			Registries: registryResolver,
			Docs:       docs,
			Feeds:      feeds,
		},
		objects,
		objects,
		policy.PullAuthorizer{Policies: policy.AuthPolicyResolver{Docs: docs, Feeds: feeds}},
		policy.PushAuthorizer{
			AuthPolicies:  policy.AuthPolicyResolver{Docs: docs, Feeds: feeds},
			StampPolicies: policy.StampPolicyResolver{Docs: docs, Feeds: feeds},
		},
		authenticator,
		staging.NewMemoryStore(),
		publish.Publisher{
			Builder: publish.DefaultBuilder{},
			Objects: objects,
			Commits: committer,
		},
		authRealm,
	), nil
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
