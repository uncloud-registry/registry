package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/config"
	"github.com/uncloud-registry/registry/internal/controlplane"
	"github.com/uncloud-registry/registry/internal/swarm"
)

func main() {
	// The whole configuration matrix is loaded and validated ONCE, before any
	// side effect (database, secret files, or listening). No parallel env
	// path exists to disagree with it.
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		log.Fatal(err)
	}

	// Final cryptographic validation still happens before any persistent side
	// effect, using exactly the validated config values. Errors never contain
	// secret material.
	tokens, err := auth.NewSessionTokenManager(cfg.SessionSecret, auth.DefaultSessionIssuer, auth.DefaultSessionAudience)
	if err != nil {
		log.Fatal(err)
	}

	var feedKeyCipher *controlplane.FeedKeyCipher
	if cfg.MasterKeyFile != "" {
		feedKeyCipher, err = controlplane.LoadMasterKeyFile(cfg.MasterKeyFile)
		if err != nil {
			log.Fatal(err)
		}
	}

	registryPriv, err := parseRegistrySeedHex(cfg.RegistryEd25519Key)
	if err != nil {
		log.Fatal(err)
	}
	registryTokens, err := auth.NewRegistryTokenIssuer(registryPriv, auth.RegistryIssuer, cfg.RegistryKeyID)
	if err != nil {
		log.Fatal(err)
	}

	store, err := controlplane.OpenSQLite(cfg.DBPath)
	if err != nil {
		log.Fatal(err)
	}

	service := &controlplane.Service{
		Store:          store,
		Tokens:         tokens,
		RegistryTokens: registryTokens,
		RegistryDomain: cfg.RegistryDomain,
		FeedKeys:       feedKeyCipher,
	}

	// Legacy plaintext feed keys are read and encrypted ONLY under an explicit
	// opt-in; the schema migration itself never touches them. Because the
	// migrated ciphertext and the cleared legacy column are written in the
	// same per-row transaction, an interrupted or failed migration never leaves
	// a partially migrated row.
	legacyMigration, err := legacyKeyMigrationEnabled()
	if err != nil {
		log.Fatal(err)
	}
	if legacyMigration {
		if _, err := service.MigrateLegacyFeedKeys(context.Background()); err != nil {
			log.Fatal(err)
		}
	}

	var publisher *controlplane.Publisher
	if cfg.BeeAPIURL != nil {
		publisher = &controlplane.Publisher{
			Documents: swarm.NewBeeObjectStore(cfg.BeeAPIURL.String(), nil),
			Feeds: controlplane.BeeRegistryFeedUpdater{
				BaseURL: cfg.BeeAPIURL.String(),
				Keys:    service,
			},
		}
	}
	service.Publisher = publisher

	handler := controlplane.NewHTTPServerWithConfig(service, auth.SubjectResolver{Tokens: tokens}, cfg)

	log.Printf("control plane listening on %s", cfg.ListenAddr)
	if err := http.ListenAndServe(cfg.ListenAddr, handler); err != nil {
		log.Fatal(err)
	}
}

func envOrDefault(name string, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

// envRequiredSecret returns the value of a required environment variable,
// failing loudly if it is missing or empty. Used for secrets that must never
// have a default.
func envRequiredSecret(name string) (string, error) {
	value := os.Getenv(name)
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("%s is required and must not be empty", name)
	}
	return value, nil
}

// masterKeyFileFromEnv resolves the required CONTROLPLANE_MASTER_KEY_FILE
// path. The value is preserved byte-for-byte (whitespace is a legitimate part
// of a path); only blank values are rejected, and the error names the variable
// never its value, so no path material reaches logs.
func masterKeyFileFromEnv() (string, error) {
	return envRequiredSecret("CONTROLPLANE_MASTER_KEY_FILE")
}

// legacyKeyMigrationEnabled implements the explicit opt-in gate for reading
// legacy plaintext feed keys: only the literal value "true" (after trimming)
// enables migration before serving. Any other non-blank value fails startup —
// a typo must neither silently skip the migration (leaving plaintext at rest)
// nor silently run it. Unset means no migration.
func legacyKeyMigrationEnabled() (bool, error) {
	value := strings.TrimSpace(os.Getenv("CONTROLPLANE_MIGRATE_LEGACY_KEYS"))
	switch value {
	case "":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, fmt.Errorf("CONTROLPLANE_MIGRATE_LEGACY_KEYS must be exactly \"true\" to enable legacy feed-key migration, or unset to skip it")
	}
}

// parseRegistrySeedHex decodes an Ed25519 signing seed from a 64-char hex
// string into a private key. It fails closed on missing, malformed, or
// wrong-length input and never returns or logs the seed value itself.
func parseRegistrySeedHex(seedHex string) (ed25519.PrivateKey, error) {
	seedHex = strings.TrimSpace(seedHex)
	if seedHex == "" {
		return nil, errors.New("CONTROLPLANE_REGISTRY_ED25519_KEY is required: set a stable 64-character hex Ed25519 seed")
	}
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("CONTROLPLANE_REGISTRY_ED25519_KEY must be exactly %d hex characters", ed25519.SeedSize*2)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
