package main

import (
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
	tokens, err := auth.NewTokenManager(tokenSecret)
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
