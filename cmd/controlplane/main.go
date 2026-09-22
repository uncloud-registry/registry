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
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/config"
	"github.com/uncloud-registry/registry/internal/controlplane"
	"github.com/uncloud-registry/registry/internal/credential"
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Run the provisioning outbox reconciler for the process lifetime. It is
	// joined before exit so no worker goroutine leaks and its DB transactions
	// finish before the process dies.
	var wg sync.WaitGroup
	if comps.reconciler != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := comps.reconciler.Run(ctx); err != nil && ctx.Err() == nil {
				log.Printf("control plane reconciler: %v", err)
			}
		}()
	}

	srv := &http.Server{Handler: comps.handler}
	var listener net.Listener
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
		listener = tls.NewListener(ln, tlsConfig)
		log.Printf("control plane serving TLS (direct) on %s", cfg.ListenAddr)
	} else {
		// Trusted-proxy termination: a trusted reverse proxy terminates TLS
		// and forwards to this internal plaintext listener.
		ln, err := net.Listen("tcp", cfg.ListenAddr)
		if err != nil {
			log.Fatal(err)
		}
		listener = ln
		log.Printf("control plane serving internal HTTP behind trusted proxy on %s", cfg.ListenAddr)
	}

	// The internal feed-signing listener is served on its own dedicated
	// socket, separate from the public router, so it can never inherit the
	// public browser CSRF/session assumptions. It is stopped with the process,
	// and a Serve error here enters the main select and aborts the whole
	// process with a nonzero exit (never log-and-continue).
	var internalSrv *http.Server
	var serveErr chan error
	if comps.internalHandler != nil && comps.internalAddr != "" {
		internalLn, err := net.Listen("tcp", comps.internalAddr)
		if err != nil {
			log.Fatal(err)
		}
		internalSrv = &http.Server{
			Handler:           comps.internalHandler,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    64 * 1024,
		}
		serveErr = make(chan error, 2)
		go func() {
			var serr error
			if comps.internalTLS != nil {
				tlsConfig := &tls.Config{
					Certificates: []tls.Certificate{*comps.internalTLS},
					MinVersion:   tls.VersionTLS12,
				}
				serr = internalSrv.Serve(tls.NewListener(internalLn, tlsConfig))
			} else {
				serr = internalSrv.Serve(internalLn)
			}
			if serr != nil && !errors.Is(serr, http.ErrServerClosed) {
				serveErr <- serr
			}
		}()
		mode := "plaintext"
		if comps.internalTLS != nil {
			mode = "TLS"
		}
		log.Printf("control plane internal feed signer (%s) listening on %s", mode, comps.internalAddr)
	}
	if serveErr == nil {
		serveErr = make(chan error, 1)
	}
	go func() { serveErr <- srv.Serve(listener) }()

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = srv.Shutdown(shutdownCtx)
		if internalSrv != nil {
			_ = internalSrv.Shutdown(shutdownCtx)
		}
		cancel()
		<-serveErr
	}

	// Graceful join: stop the reconciler loop and wait for it to exit.
	stop()
	wg.Wait()
}

// controlPlaneDeps captures every external side-effect the startup assembler
// performs, so tests can inject spies that prove invalid values cause zero
// file, DB, or listening side effects before startup fails.
type controlPlaneDeps struct {
	newSessionManager      func(secret, issuer, audience string) (*auth.SessionTokenManager, error)
	loadMasterKey          func(path string) (*controlplane.FeedKeyCipher, error)
	parseRegistrySeed      func(seedHex string) (ed25519.PrivateKey, error)
	newRegistryIssuer      func(priv ed25519.PrivateKey, issuer, keyID string) (*auth.RegistryTokenIssuer, error)
	loadTLSKeyPair         func(certFile, keyFile string) (tls.Certificate, error)
	loadInternalTLSKeyPair func(certFile, keyFile string) (tls.Certificate, error)
	openStore              func(dbPath string) (*controlplane.Store, error)
	loadInternalSecret     func(path string) ([]byte, error)
}

func defaultDeps() controlPlaneDeps {
	return controlPlaneDeps{
		newSessionManager: auth.NewSessionTokenManager,
		loadMasterKey:     controlplane.LoadMasterKeyFile,
		parseRegistrySeed: parseRegistrySeedHex,
		newRegistryIssuer: func(priv ed25519.PrivateKey, issuer, keyID string) (*auth.RegistryTokenIssuer, error) {
			return auth.NewRegistryTokenIssuer(priv, issuer, keyID)
		},
		loadTLSKeyPair:         tls.LoadX509KeyPair,
		loadInternalTLSKeyPair: tls.LoadX509KeyPair,
		openStore:              controlplane.OpenSQLite,
		loadInternalSecret:     credential.LoadSecretFile,
	}
}

// controlPlaneComponents is the fully assembled, validated control plane.
type controlPlaneComponents struct {
	handler http.Handler
	// tlsCert is non-nil exactly when termination is direct and TLS must be
	// served with this preloaded certificate. It is parsed before the DB opens.
	tlsCert *tls.Certificate
	// reconciler, when non-nil, owns the provisioning outbox worker loop. It
	// is created only when a Bee endpoint is configured (documents+feeds).
	// Nil means no external publication is wired and no reconciler runs.
	reconciler *controlplane.Reconciler
	// internalHandler, when non-nil, is the constrained internal feed-signing
	// server served on its own dedicated listener (internalAddr), so it can
	// never inherit the public router's browser CSRF/session assumptions.
	internalHandler http.Handler
	internalAddr    string
	// internalTLS, when non-nil, is the already-parsed certificate for the
	// internal feed-signing listener (non-loopback internal binds require TLS).
	// It is loaded and validated BEFORE the database opens.
	internalTLS *tls.Certificate
}

// prepareControlPlane assembles every component strictly in dependency order:
// session manager → master-key file → registry seed → TLS keypair (direct) →
// database → service → optional legacy migration → publisher → HTTP handler.
// Every invalid value returns an error BEFORE the database is opened (the only
// persistent side effect), so a misconfiguration never touches storage or
// listens. Errors contain no secret material and no file paths.
func prepareControlPlane(cfg *config.ControlPlaneConfig, deps controlPlaneDeps) (*controlPlaneComponents, error) {
	if deps.newSessionManager == nil || deps.loadMasterKey == nil || deps.parseRegistrySeed == nil ||
		deps.newRegistryIssuer == nil || deps.loadTLSKeyPair == nil || deps.loadInternalTLSKeyPair == nil ||
		deps.openStore == nil || deps.loadInternalSecret == nil {
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

	// The internal feed-signing credential is loaded and validated BEFORE the
	// database opens (Task 8 ordering: every secret and config value is
	// settled before any SQLite side effect). It is mounted from a secure file
	// and never supplied directly in env/flags/JSON. The local byte copy is
	// wiped after the internal server is constructed.
	var internalSecret []byte
	if cfg.InternalSecretFile != "" {
		internalSecret, err = deps.loadInternalSecret(cfg.InternalSecretFile)
		if err != nil {
			return nil, err
		}
		if err := credential.ValidateSecret(internalSecret); err != nil {
			return nil, err
		}
	}

	// A non-loopback internal feed-signing listener requires TLS (config
	// validation enforces the prerequisite); the cert/key pair is loaded and
	// validated BEFORE the database opens, so a malformed pair can never touch
	// SQLite. Errors are data-free.
	var internalTLS *tls.Certificate
	if cfg.InternalTLSCertFile != "" {
		cert, err := deps.loadInternalTLSKeyPair(cfg.InternalTLSCertFile, cfg.InternalTLSKeyFile)
		if err != nil {
			return nil, errors.New("failed to load the internal TLS certificate and private key pair")
		}
		internalTLS = &cert
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
			// Feed read-back resolution: the reconciler proves a policy feed
			// points at the uploaded object by resolving it back to its ref.
			// The constructor normalizes the base URL and guarantees a non-nil
			// HTTP client plus the per-request context timeout, so a direct
			// zero-value struct (with no base URL) is never used in production.
			FeedsReader: swarm.NewBeeFeedResolver(cfg.BeeAPIURL.String(), nil),
		}
	}

	handler := controlplane.NewHTTPServerWithConfig(service, auth.SubjectResolver{Tokens: tokens}, cfg)

	comps := &controlPlaneComponents{handler: handler, tlsCert: tlsCert}
	// Wire the provisioning reconciler against the validated, already-open
	// store and the configured Bee object store / feed updater / feed
	// resolver. Construction fails closed: a Publisher missing read-back
	// capability aborts startup rather than running a worker that could mark
	// unverified jobs complete. The reconciler opens no database and performs
	// no I/O at construction.
	if service.Publisher != nil && service.Publisher.Documents != nil && service.Publisher.Feeds != nil && service.Publisher.FeedsReader != nil {
		r, err := service.NewReconciler()
		if err != nil {
			return nil, err
		}
		comps.reconciler = r
	}

	// The internal feed signer signs repository-state feed commits for the
	// registry data plane and is served on its own dedicated listener. It is
	// wired only when Bee feed capability is configured, and it depends on the
	// same Bee object store / feed resolver / updater plus the pre-validated
	// internal secret. Both CONTROPLANE_INTERNAL_ADDR and the secret file must
	// be present, or startup fails closed before any listener binds.
	if cfg.BeeAPIURL != nil {
		// Config validation has already required the internal addr + secret
		// pair when Bee signing is enabled, so this is a defensive guard only.
		if cfg.InternalAddr == "" || len(internalSecret) == 0 {
			return nil, errors.New("control-plane Bee feed signing requires CONTROLPLANE_INTERNAL_ADDR and CONTROLPLANE_INTERNAL_SECRET_FILE")
		}
		signer := &controlplane.FeedSigner{
			Store:        store,
			Feeds:        controlplane.BeeRegistryFeedUpdater{BaseURL: cfg.BeeAPIURL.String(), Keys: service},
			ResolveFeeds: swarm.NewBeeFeedResolver(cfg.BeeAPIURL.String(), nil),
			Docs:         swarm.NewBeeDocumentStore(cfg.BeeAPIURL.String(), nil),
		}
		internal, err := controlplane.NewInternalFeedServer(signer, internalSecret, nil)
		if err != nil {
			return nil, err
		}
		for i := range internalSecret {
			internalSecret[i] = 0
		}
		comps.internalHandler = internal
		comps.internalAddr = cfg.InternalAddr
		comps.internalTLS = internalTLS
	}
	return comps, nil
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
