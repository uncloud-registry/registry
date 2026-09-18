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
		return buildMemoryHandler(), nil
	case "bee":
		return buildBeeHandler()
	default:
		return nil, fmt.Errorf("unsupported REGISTRY_BACKEND %q", os.Getenv("REGISTRY_BACKEND"))
	}
}

func buildMemoryHandler() http.Handler {
	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	subjects := auth.SubjectResolver{}
	authRealm := envOrDefault("REGISTRY_AUTH_REALM", "https://auth.uncloud-registry.com/token")
	if manager, err := tokenManagerFromEnv(); err == nil {
		subjects = auth.SubjectResolver{Tokens: manager}
	}

	return registry.NewHandler(
		resolve.RegistryResolver{
			Registries: resolve.StaticRegistryIdentityResolver{Hosts: map[string]resolve.RegistryIdentity{}},
			Docs:       docs,
			Feeds:      feeds,
		},
		docs,
		docs,
		policy.PullAuthorizer{Policies: policy.AuthPolicyResolver{Docs: docs, Feeds: feeds}, Subjects: subjects},
		policy.PushAuthorizer{
			AuthPolicies:  policy.AuthPolicyResolver{Docs: docs, Feeds: feeds},
			StampPolicies: policy.StampPolicyResolver{Docs: docs, Feeds: feeds},
			Subjects:      subjects,
		},
		subjects,
		staging.NewMemoryStore(),
		publish.Publisher{
			Builder: publish.DefaultBuilder{},
			Objects: docs,
			Feeds:   feeds,
		},
		authRealm,
	)
}

func buildBeeHandler() (http.Handler, error) {
	beeURL := strings.TrimSpace(os.Getenv("BEE_API_URL"))
	if beeURL == "" {
		return nil, fmt.Errorf("BEE_API_URL is required when REGISTRY_BACKEND=bee")
	}
	docs := swarm.NewBeeDocumentStore(beeURL, http.DefaultClient)
	objects := swarm.NewBeeObjectStore(beeURL, http.DefaultClient)
	feeds := swarm.IdentityFeedResolver{}
	subjects := auth.SubjectResolver{}
	authRealm := envOrDefault("REGISTRY_AUTH_REALM", "https://auth.uncloud-registry.com/token")
	registryResolver, err := buildRegistryIdentityResolver()
	if err != nil {
		return nil, err
	}
	if manager, err := tokenManagerFromEnv(); err == nil {
		subjects = auth.SubjectResolver{Tokens: manager}
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
		policy.PullAuthorizer{Policies: policy.AuthPolicyResolver{Docs: docs, Feeds: feeds}, Subjects: subjects},
		policy.PushAuthorizer{
			AuthPolicies:  policy.AuthPolicyResolver{Docs: docs, Feeds: feeds},
			StampPolicies: policy.StampPolicyResolver{Docs: docs, Feeds: feeds},
			Subjects:      subjects,
		},
		subjects,
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

func tokenManagerFromEnv() (*auth.TokenManager, error) {
	secret := strings.TrimSpace(os.Getenv("REGISTRY_TOKEN_SECRET"))
	if secret == "" {
		return nil, nil
	}
	return auth.NewTokenManager(secret)
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
