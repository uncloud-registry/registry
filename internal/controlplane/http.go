package controlplane

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/config"
)

type HTTPServer struct {
	Service  *Service
	Subjects auth.SubjectResolver

	// Logger receives component-tagged, safe internal log lines (request ID +
	// cause classification on auth failures). Nil uses slog.Default().
	Logger *slog.Logger

	// security enforces the request-time controls (CSRF, rate limits, origin,
	// client-IP resolution, headers). It is always present; development mode
	// relaxes only the caps.
	security *securityPolicy

	// inviteFlashStore is lazily initialised on first use so a zero-value
	// *HTTPServer is safe before any flash traffic arrives.
	flashInitMu sync.Mutex
	flashes     *inviteFlashStore
}

// NewHTTPServer returns a handler with the default development security policy
// (controls enforced, developer-friendly caps).
func NewHTTPServer(service *Service, subjects auth.SubjectResolver) http.Handler {
	return NewHTTPServerWithConfig(service, subjects, nil)
}

// NewHTTPServerWithConfig returns a handler whose security policy is derived
// from an explicit ControlPlaneConfig. A nil config means development-mode
// defaults.
func NewHTTPServerWithConfig(service *Service, subjects auth.SubjectResolver, cfg *config.ControlPlaneConfig) http.Handler {
	s := &HTTPServer{Service: service, Subjects: subjects}
	s.security = newSecurityPolicy(service.Tokens, cfg)
	return s
}

// inviteFlash returns the server's one-time invite flash store, lazily creating it
// on first use so a zero-value *HTTPServer is safe and no flash memory is allocated
// on servers that never create invites.
func (s *HTTPServer) inviteFlash() *inviteFlashStore {
	s.flashInitMu.Lock()
	defer s.flashInitMu.Unlock()
	if s.flashes == nil {
		s.flashes = newInviteFlashStore()
	}
	return s.flashes
}

func (s *HTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.security != nil {
		s.security.wrap(http.HandlerFunc(s.route)).ServeHTTP(w, r)
		return
	}
	s.route(w, r)
}

// route dispatches to the concrete handler for a path/method pair.
func (s *HTTPServer) route(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/":
		s.handleUIRoot(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/ui/logout":
		s.handleLogout(w, r)
	case (r.Method == http.MethodGet || r.Method == http.MethodPost) && r.URL.Path == "/ui/login":
		s.handleUILogin(w, r)
	case (r.Method == http.MethodGet || r.Method == http.MethodPost) && r.URL.Path == "/ui/register":
		s.handleUIRegister(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/ui/registries":
		s.handleUIRegistries(w, r)
	case (r.Method == http.MethodGet || r.Method == http.MethodPost) && r.URL.Path == "/ui/registries/new":
		s.handleUICreateRegistry(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/ui/registries/") && strings.HasSuffix(r.URL.Path, "/settings"):
		s.handleUIUpdateRegistrySettings(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/ui/registries/") && strings.HasSuffix(r.URL.Path, "/invites"):
		s.handleUICreateInvite(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/ui/registries/") && strings.HasSuffix(r.URL.Path, "/revoke"):
		s.handleUIRevokeInvite(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/ui/registries/") && strings.HasSuffix(r.URL.Path, "/permissions"):
		s.handleUIUpdateCollaboratorPermissions(w, r)
	case (r.Method == http.MethodGet || r.Method == http.MethodPost) && r.URL.Path == "/ui/invites/accept":
		s.handleUIAcceptInvite(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/ui/registries/"):
		s.handleUIRegistryDetail(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/users/register":
		s.handleRegister(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/auth/login":
		s.handleLogin(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/registries":
		s.handleListRegistries(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/registries":
		s.handleCreateRegistry(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/registries/") && strings.HasSuffix(r.URL.Path, "/invites"):
		s.handleCreateInvite(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/registries/") && strings.HasSuffix(r.URL.Path, "/revoke"):
		s.handleRevokeInvite(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/invites/accept":
		s.handleAcceptInvite(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/token":
		s.handleRegistryToken(w, r)
	default:
		http.NotFound(w, r)
	}
}

type credentialsRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *HTTPServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req credentialsRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}
	user, token, err := s.Service.RegisterUser(r.Context(), req.Email, req.Password)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"user": NewPublicUser(user), "token": token})
}

func (s *HTTPServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req credentialsRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}
	// Every authentication failure produces the same generic response so a
	// caller can never distinguish unknown email from a wrong password, while
	// a safe internal cause (request-correlated, no credentials) is logged.
	user, token, err := s.Service.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		s.logAuthFailure(r, credentialCause(err))
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": errInvalidCredentials.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": NewPublicUser(user), "token": token})
}

type createRegistryRequest struct {
	Slug                string `json:"slug"`
	ENSName             string `json:"ensName"`
	AnonymousPull       bool   `json:"anonymousPull"`
	DefaultStampBatchID string `json:"defaultStampBatchID"`
}

func (s *HTTPServer) handleCreateRegistry(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.requireSessionUser(w, r)
	if !ok {
		return
	}
	var req createRegistryRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}
	registry, err := s.Service.CreateRegistry(r.Context(), userID, req.Slug, req.ENSName, req.AnonymousPull, req.DefaultStampBatchID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"registry":  NewPublicRegistry(registry.Registry),
		"bootstrap": registry.Bootstrap,
	})
}

func (s *HTTPServer) handleListRegistries(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.requireSessionUser(w, r)
	if !ok {
		return
	}
	registries, err := s.Service.ListRegistries(r.Context(), userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"registries": newPublicRegistries(registries)})
}

type createInviteRequest struct {
	Email   string `json:"email"`
	CanPull bool   `json:"canPull"`
	CanPush bool   `json:"canPush"`
}

func (s *HTTPServer) handleCreateInvite(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.requireSessionUser(w, r)
	if !ok {
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/registries/")
	path = strings.TrimSuffix(path, "/invites")
	registryID, err := strconv.ParseInt(path, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid registry id"})
		return
	}
	var req createInviteRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}
	invite, token, err := s.Service.CreateInvite(r.Context(), registryID, userID, req.Email, req.CanPull, req.CanPush)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"invite": NewPublicInvite(invite), "token": token})
}

func (s *HTTPServer) handleAcceptInvite(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.requireSessionUser(w, r)
	if !ok {
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}
	invite, err := s.Service.AcceptInvite(r.Context(), req.Token, userID)
	if err != nil {
		// Every acceptance failure — malformed token, unknown invite, wrong
		// recipient, expired, revoked, accepted by someone else — maps to the
		// SAME generic response so no invite state is ever enumerated.
		if errors.Is(err, errInviteNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "invite is not valid or has expired"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, NewPublicInvite(invite))
}

// parseInviteRevokePath extracts registryID and inviteID from the revoke routes
// /api/registries/{registryID}/invites/{inviteID}/revoke and
// /ui/registries/{registryID}/invites/{inviteID}/revoke.
func parseInviteRevokePath(path string) (int64, int64, bool) {
	rest := path
	switch {
	case strings.HasPrefix(path, "/api/registries/"):
		rest = strings.TrimPrefix(path, "/api/registries/")
	case strings.HasPrefix(path, "/ui/registries/"):
		rest = strings.TrimPrefix(path, "/ui/registries/")
	default:
		return 0, 0, false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 4 || parts[1] != "invites" || parts[3] != "revoke" {
		return 0, 0, false
	}
	registryID, err1 := strconv.ParseInt(parts[0], 10, 64)
	inviteID, err2 := strconv.ParseInt(parts[2], 10, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return registryID, inviteID, true
}

// handleRevokeInvite is the API revocation boundary. Revocation is owner-
// authorized (service layer); every failure — unknown registry/invite, non-
// owner caller, already-accepted invite — becomes the same generic not-found
// response, and neither the token nor the digest is ever involved or exposed.
func (s *HTTPServer) handleRevokeInvite(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.requireSessionUser(w, r)
	if !ok {
		return
	}
	registryID, inviteID, ok := parseInviteRevokePath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if _, err := s.Service.RevokeInvite(r.Context(), userID, registryID, inviteID); err != nil {
		if errors.Is(err, errInviteNotFound) || errors.Is(err, errInviteCannotRevoke) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "invite not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *HTTPServer) handleRegistryToken(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	if !ok {
		s.logAuthFailure(r, "missing_basic_auth")
		w.Header().Set("WWW-Authenticate", `Basic realm="uncloud-registry"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "basic auth required"})
		return
	}
	service := r.URL.Query().Get("service")
	scope := r.URL.Query().Get("scope")
	token, err := s.Service.IssueRegistryToken(r.Context(), service, scope, username, password)
	if err != nil {
		status := http.StatusUnauthorized
		message := err.Error()
		switch {
		case errors.Is(err, sql.ErrNoRows):
			// Registry for the requested host does not exist; the caller chose
			// the host so this reveals nothing about users or credentials.
			status = http.StatusNotFound
			message = "registry not found"
			s.logAuthFailure(r, "registry_not_found")
		case errors.Is(err, errInvalidCredentials):
			// Never distinguish unknown user from a wrong password.
			message = errInvalidCredentials.Error()
			s.logAuthFailure(r, credentialCause(err))
		default:
			// Other failures (malformed scope, denied permission) are safe and
			// generic; log a coarse cause without the error text.
			s.logAuthFailure(r, "token_refused")
		}
		writeJSON(w, status, map[string]string{"error": message})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": token})
}

func (s *HTTPServer) requireSessionUser(w http.ResponseWriter, r *http.Request) (int64, bool) {
	subject, ok := s.requireSessionSubject(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authorization required"})
		return 0, false
	}
	userID, err := UserIDFromSubject(subject)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return 0, false
	}
	return userID, true
}

func (s *HTTPServer) requireSessionUserID(r *http.Request) (int64, bool) {
	subject, ok := s.requireSessionSubject(r)
	if !ok {
		return 0, false
	}
	userID, err := UserIDFromSubject(subject)
	if err != nil {
		return 0, false
	}
	return userID, true
}

func (s *HTTPServer) requireSessionSubject(r *http.Request) (string, bool) {
	subject := s.Subjects.Subject(r.Header.Get("Authorization"))
	if subject == "" {
		if cookie, err := r.Cookie(sessionCookieName); err == nil {
			subject = s.Subjects.Subject("Bearer " + cookie.Value)
		}
	}
	if subject == "" {
		return "", false
	}
	return subject, true
}

// logger returns the configured Logger, defaulting to slog.Default().
func (s *HTTPServer) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

// logAuthFailure logs a safe, internal authentication-failure line: only the
// cryptographically random request ID (for correlation) and a coarse cause
// classification. It NEVER includes the email, password, token, or any error
// string. Public status/body are unaffected.
func (s *HTTPServer) logAuthFailure(r *http.Request, cause string) {
	if cause == "" {
		cause = "authentication_failed"
	}
	s.logger().Warn("authentication failed",
		"component", "controlplane",
		"request_id", RequestIDFromContext(r.Context()),
		"route", r.Method+" "+r.URL.Path,
		"cause", cause,
	)
}

// decodeJSON decodes a request JSON body through the bounded body already set
// up by the security middleware, mapping body overflow to an explicit 413.
// Non-size decode errors return the same 400 explain-the-error body as before,
// and never echo secrets (the caller is responsible for safe error text).
func (s *HTTPServer) decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	err := json.NewDecoder(r.Body).Decode(dst)
	if err == nil {
		return true
	}
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request body too large"})
		return false
	}
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	return false
}

// parseFormBounded parses a form body through the bounded request body,
// mapping overflow to an explicit 413 and other errors to the same 400 the
// handlers already produce.
func (s *HTTPServer) parseFormBounded(w http.ResponseWriter, r *http.Request) bool {
	if err := r.ParseForm(); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
