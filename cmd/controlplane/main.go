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
	"github.com/uncloud-registry/registry/internal/controlplane"
	"github.com/uncloud-registry/registry/internal/swarm"
)

// registrySigningKeyID is the explicit kid stamped on every registry token the
// control plane signs. Operators distribute the matching public key under this
// exact kid to registries (Task 5).
const registrySigningKeyID = "cp-ed25519-1"

func main() {
	addr := envOrDefault("CONTROLPLANE_ADDR", ":8081")
	dbPath := envOrDefault("CONTROLPLANE_DB_PATH", "file:controlplane.db?_pragma=foreign_keys(1)")
	// No default secret: missing/weak configuration must fail startup rather
	// than serve HMAC-signed sessions with a public key.
	tokenSecret, err := envRequiredSecret("CONTROLPLANE_TOKEN_SECRET")
	if err != nil {
		log.Fatal(err)
	}
	registryDomain := envOrDefault("CONTROLPLANE_REGISTRY_DOMAIN", "uncloud-registry.com")
	beeAPIURL := strings.TrimSpace(os.Getenv("CONTROLPLANE_BEE_API_URL"))

	// The master-key file is REQUIRED: without the current AES-256 master key
	// no registry feed key can be stored encrypted (or decrypted for signing),
	// so startup fails rather than running with plaintext-adjacent gaps. The
	// path is an env value, never a command-line secret; loader errors contain
	// no path or key material.
	masterKeyPath, err := envRequiredSecret("CONTROLPLANE_MASTER_KEY_FILE")
	if err != nil {
		log.Fatal(err)
	}
	feedKeyCipher, err := controlplane.LoadMasterKeyFile(masterKeyPath)
	if err != nil {
		log.Fatal(err)
	}

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

	service := &controlplane.Service{
		Store:          store,
		Tokens:         tokens,
		RegistryTokens: registryTokens,
		RegistryDomain: registryDomain,
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
	if beeAPIURL != "" {
		publisher = &controlplane.Publisher{
			Documents: swarm.NewBeeObjectStore(beeAPIURL, nil),
			Feeds: controlplane.BeeRegistryFeedUpdater{
				BaseURL: beeAPIURL,
				Keys:    service,
			},
		}
	}
	service.Publisher = publisher

	handler := controlplane.NewHTTPServer(service, auth.SubjectResolver{Tokens: tokens})

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

// newRegistryTokenIssuerFromEnv builds the Ed25519 registry token signing key
// from a required, stable CONTROLPLANE_REGISTRY_ED25519_KEY hex seed. It never
// generates an ephemeral key: a control plane without a stable signing seed
// cannot start, because ephemeral tokens would not survive a restart. Errors
// describe the failure without echoing the key material.
func newRegistryTokenIssuerFromEnv() (*auth.RegistryTokenIssuer, error) {
	priv, err := parseRegistrySeedHex(os.Getenv("CONTROLPLANE_REGISTRY_ED25519_KEY"))
	if err != nil {
		return nil, err
	}
	return auth.NewRegistryTokenIssuer(priv, auth.RegistryIssuer, registrySigningKeyID)
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
