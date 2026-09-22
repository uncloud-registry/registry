package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/config"
	"github.com/uncloud-registry/registry/internal/controlplane"
	"github.com/uncloud-registry/registry/internal/swarm"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		log.Fatal(err)
	}

	comps, err := prepareControlPlane(cfg, defaultDeps())
	if err != nil {
		log.Fatal(err)
	}

	srv := &http.Server{Handler: comps.handler}
	if comps.tlsCert != nil {
		// Direct termination: serve TLS with the already-parsed certificate,
		// never plaintext, never a deferred file read.
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{*comps.tlsCert},
			MinVersion:   tls.VersionTLS12,
		}
		ln, err := net.Listen("tcp", cfg.ListenAddr)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("control plane serving TLS (direct) on %s", cfg.ListenAddr)
		if err := srv.Serve(tls.NewListener(ln, tlsConfig)); err != nil {
			log.Fatal(err)
		}
		return
	}

	// Trusted-proxy termination: a trusted reverse proxy terminates TLS and
	// forwards to this internal plaintext listener.
	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("control plane serving internal HTTP behind trusted proxy on %s", cfg.ListenAddr)
	if err := srv.Serve(ln); err != nil {
		log.Fatal(err)
	}
}

// controlPlaneDeps captures every external side-effect the startup assembler
// performs, so tests can inject spies that prove invalid values cause zero
// file, DB, or listening side effects before startup fails.
type controlPlaneDeps struct {
	newSessionManager func(secret, issuer, audience string) (*auth.SessionTokenManager, error)
	loadMasterKey     func(path string) (*controlplane.FeedKeyCipher, error)
	parseRegistrySeed func(seedHex string) (ed25519.PrivateKey, error)
	newRegistryIssuer func(priv ed25519.PrivateKey, issuer, keyID string) (*auth.RegistryTokenIssuer, error)
	loadTLSKeyPair    func(certFile, keyFile string) (tls.Certificate, error)
	openStore         func(dbPath string) (*controlplane.Store, error)
}

func defaultDeps() controlPlaneDeps {
	return controlPlaneDeps{
		newSessionManager: auth.NewSessionTokenManager,
		loadMasterKey:     controlplane.LoadMasterKeyFile,
		parseRegistrySeed: parseRegistrySeedHex,
		newRegistryIssuer: func(priv ed25519.PrivateKey, issuer, keyID string) (*auth.RegistryTokenIssuer, error) {
			return auth.NewRegistryTokenIssuer(priv, issuer, keyID)
		},
		loadTLSKeyPair: tls.LoadX509KeyPair,
		openStore:      controlplane.OpenSQLite,
	}
}

// controlPlaneComponents is the fully assembled, validated control plane.
type controlPlaneComponents struct {
	handler http.Handler
	// tlsCert is non-nil exactly when termination is direct and TLS must be
	// served with this preloaded certificate. It is parsed before the DB opens.
	tlsCert *tls.Certificate
}

// prepareControlPlane assembles every component strictly in dependency order:
// session manager → master-key file → registry seed → TLS keypair (direct) →
// database → service → optional legacy migration → publisher → HTTP handler.
// Every invalid value returns an error BEFORE the database is opened (the only
// persistent side effect), so a misconfiguration never touches storage or
// listens. Errors contain no secret material and no file paths.
func prepareControlPlane(cfg *config.ControlPlaneConfig, deps controlPlaneDeps) (*controlPlaneComponents, error) {
	if deps.newSessionManager == nil || deps.loadMasterKey == nil || deps.parseRegistrySeed == nil ||
		deps.newRegistryIssuer == nil || deps.loadTLSKeyPair == nil || deps.openStore == nil {
		return nil, errors.New("startup dependencies must be fully supplied")
	}

	tokens, err := deps.newSessionManager(cfg.SessionSecret, auth.DefaultSessionIssuer, auth.DefaultSessionAudience)
	if err != nil {
		return nil, err
	}

	// The master-key file is required in every mode and always loaded before
	// the database — there is no development-only plaintext feed-key path.
	feedKeyCipher, err := deps.loadMasterKey(cfg.MasterKeyFile)
	if err != nil {
		return nil, err
	}

	registryPriv, err := deps.parseRegistrySeed(cfg.RegistryEd25519Key)
	if err != nil {
		return nil, err
	}
	registryTokens, err := deps.newRegistryIssuer(registryPriv, auth.RegistryIssuer, cfg.RegistryKeyID)
	if err != nil {
		return nil, err
	}

	// Direct termination: parse the TLS keypair now, before any DB side
	// effect. trusted-proxy termination does not need a local certificate.
	var tlsCert *tls.Certificate
	if cfg.TLSTermination == config.TLSTermDirect {
		cert, err := deps.loadTLSKeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			// Data-free: never leak the certificate/key file paths.
			return nil, errors.New("failed to load the TLS certificate and private key pair")
		}
		tlsCert = &cert
	}

	store, err := deps.openStore(cfg.DBPath)
	if err != nil {
		return nil, err
	}

	service := &controlplane.Service{
		Store:          store,
		Tokens:         tokens,
		RegistryTokens: registryTokens,
		RegistryDomain: cfg.RegistryDomain,
		FeedKeys:       feedKeyCipher,
		SessionTTL:     cfg.SessionTTL,
	}

	// Legacy plaintext feed keys are read and encrypted ONLY under the
	// validated explicit opt-in (CONTROLPLANE_MIGRATE_LEGACY_KEYS=true, already
	// parsed into the config before any file or DB work).
	if cfg.LegacyKeyMigration {
		if _, err := service.MigrateLegacyFeedKeys(context.Background()); err != nil {
			return nil, err
		}
	}

	if cfg.BeeAPIURL != nil {
		service.Publisher = &controlplane.Publisher{
			Documents: swarm.NewBeeObjectStore(cfg.BeeAPIURL.String(), nil),
			Feeds: controlplane.BeeRegistryFeedUpdater{
				BaseURL: cfg.BeeAPIURL.String(),
				Keys:    service,
			},
		}
	}

	handler := controlplane.NewHTTPServerWithConfig(service, auth.SubjectResolver{Tokens: tokens}, cfg)
	return &controlPlaneComponents{handler: handler, tlsCert: tlsCert}, nil
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
