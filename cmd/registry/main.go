package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/uncloud-registry/registry/internal/auth"
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

	var feedUpdater publish.FeedUpdater = swarm.DisabledFeedUpdater{
		Reason: "real feed updates require BEE_FEED_SIGNER_PRIVATE_KEY; use REGISTRY_BACKEND=memory for end-to-end local testing or configure a signer key for Bee mode",
	}
	if signerKey := strings.TrimSpace(os.Getenv("BEE_FEED_SIGNER_PRIVATE_KEY")); signerKey != "" {
		updater, err := swarm.NewBeeSequenceFeedUpdater(beeURL, http.DefaultClient, signerKey)
		if err != nil {
			return nil, err
		}
		feedUpdater = updater
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
			Feeds:   feedUpdater,
		},
		authRealm,
	), nil
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
	hosts := make(map[string]resolve.RegistryIdentity, len(owners))
	for host, owner := range owners {
		hosts[host] = resolve.RegistryIdentity{
			Host:  host,
			Owner: owner,
		}
	}
	return resolve.StaticRegistryIdentityResolver{Hosts: hosts}
}
