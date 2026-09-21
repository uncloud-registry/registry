package controlplane

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/uncloud-registry/registry/internal/auth"
)

type HTTPServer struct {
	Service  *Service
	Subjects auth.SubjectResolver

	// inviteFlashStore is lazily initialised on first use so a zero-value
	// *HTTPServer is safe before any flash traffic arrives.
	flashInitMu sync.Mutex
	flashes     *inviteFlashStore
}

func NewHTTPServer(service *Service, subjects auth.SubjectResolver) http.Handler {
	return &HTTPServer{Service: service, Subjects: subjects}
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
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/":
		s.handleUIRoot(w, r)
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	user, token, err := s.Service.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	invite, err := s.Service.AcceptInvite(r.Context(), req.Token, userID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, NewPublicInvite(invite))
}

func (s *HTTPServer) handleRegistryToken(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="uncloud-registry"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "basic auth required"})
		return
	}
	service := r.URL.Query().Get("service")
	scope := r.URL.Query().Get("scope")
	token, err := s.Service.IssueRegistryToken(r.Context(), service, scope, username, password)
	if err != nil {
		status := http.StatusUnauthorized
		if err == sql.ErrNoRows {
			status = http.StatusNotFound
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
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

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
