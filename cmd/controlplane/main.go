package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/controlplane"
	"github.com/uncloud-registry/registry/internal/swarm"
)

func main() {
	addr := envOrDefault("CONTROLPLANE_ADDR", ":8081")
	dbPath := envOrDefault("CONTROLPLANE_DB_PATH", "file:controlplane.db?_pragma=foreign_keys(1)")
	tokenSecret := envOrDefault("CONTROLPLANE_TOKEN_SECRET", "dev-secret-change-me")
	registryDomain := envOrDefault("CONTROLPLANE_REGISTRY_DOMAIN", "uncloud-registry.com")
	beeAPIURL := strings.TrimSpace(os.Getenv("CONTROLPLANE_BEE_API_URL"))

	store, err := controlplane.OpenSQLite(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	tokens, err := auth.NewSessionTokenManager(tokenSecret, auth.DefaultSessionIssuer, auth.DefaultSessionAudience)
	if err != nil {
		log.Fatal(err)
	}
	registryTokens, err := newRegistryTokenIssuerFromEnv()
	if err != nil {
		log.Fatal(err)
	}

	var publisher *controlplane.Publisher
	if beeAPIURL != "" {
		publisher = &controlplane.Publisher{
			Documents: swarm.NewBeeObjectStore(beeAPIURL, nil),
			Feeds: controlplane.BeeRegistryFeedUpdater{
				BaseURL: beeAPIURL,
			},
		}
	}

	handler := controlplane.NewHTTPServer(&controlplane.Service{
		Store:          store,
		Tokens:         tokens,
		RegistryTokens: registryTokens,
		RegistryDomain: registryDomain,
		Publisher:      publisher,
	}, auth.SubjectResolver{Tokens: tokens})

	log.Printf("control plane listening on %s", addr)
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatal(err)
	}
}

func envOrDefault(name string, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

// newRegistryTokenIssuerFromEnv builds the Ed25519 registry token signing key.
// It reads a 64-char hex seed from CONTROLPLANE_REGISTRY_ED25519_KEY; when unset
// a random key is generated so a fresh local deployment still signs valid
// registry tokens (verification keys must then be distributed to registries).
func newRegistryTokenIssuerFromEnv() (*auth.RegistryTokenIssuer, error) {
	seedHex := strings.TrimSpace(os.Getenv("CONTROLPLANE_REGISTRY_ED25519_KEY"))
	var priv ed25519.PrivateKey
	if seedHex == "" {
		log.Printf("CONTROLPLANE_REGISTRY_ED25519_KEY not set: generating an ephemeral Ed25519 registry signing key")
		_, priv, _ = ed25519.GenerateKey(rand.Reader)
	} else {
		seed, err := hex.DecodeString(seedHex)
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("CONTROLPLANE_REGISTRY_ED25519_KEY must be %d hex characters", ed25519.SeedSize*2)
		}
		priv = ed25519.NewKeyFromSeed(seed)
	}
	return auth.NewRegistryTokenIssuer(priv, auth.RegistryIssuer, "cp-ed25519-1")
}
