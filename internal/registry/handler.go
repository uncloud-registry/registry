package registry

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/spec"
	"github.com/uncloud-registry/registry/internal/staging"
)

type ObjectStore interface {
	Get(ctx context.Context, ref string) ([]byte, error)
}

type ObjectUploader interface {
	Put(ctx context.Context, data []byte, batchID string) (string, error)
}

type PullAuthorizer interface {
	Authorize(ctx context.Context, registry resolve.RegistryIdentity, repo string, principal auth.Principal) (bool, error)
}

type PushAuthorizer interface {
	Authorize(ctx context.Context, registry resolve.RegistryIdentity, repo string, principal auth.Principal) (batchID string, allowed bool, err error)
}

type Handler struct {
	Resolver       resolve.RegistryResolver
	Objects        ObjectStore
	Uploader       ObjectUploader
	PullAuthorizer PullAuthorizer
	PushAuthorizer PushAuthorizer
	Authenticator  Authenticator
	Staging        staging.Store
	Publisher      publish.Publisher
	SessionTTL     time.Duration
	AuthRealm      string
}

func NewHandler(resolver resolve.RegistryResolver, objects ObjectStore, uploader ObjectUploader, pullAuthorizer PullAuthorizer, pushAuthorizer PushAuthorizer, authenticator Authenticator, stageStore staging.Store, publisher publish.Publisher, authRealm string) http.Handler {
	return &Handler{
		Resolver:       resolver,
		Objects:        objects,
		Uploader:       uploader,
		PullAuthorizer: pullAuthorizer,
		PushAuthorizer: pushAuthorizer,
		Authenticator:  authenticator,
		Staging:        stageStore,
		Publisher:      publisher,
		SessionTTL:     15 * time.Minute,
		AuthRealm:      authRealm,
	}
}

// ServeHTTP authenticates every repo-scoped request BEFORE any policy
// resolution, storage read, Bee call, or staging side effect. The service
// bound into verification is the canonical host of the resolved registry
// identity; repository and action come from the matched route. Only a missing
// token on pull may degrade to the anonymous principal, and only so the auth
// policy can then explicitly allow or deny it.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v2" || r.URL.Path == "/v2/" {
		w.WriteHeader(http.StatusOK)
		return
	}

	repo, resource, reference, ok := parsePath(r.URL.Path)
	if !ok {
		writeError(w, http.StatusNotFound, "NAME_UNKNOWN", "unknown path")
		return
	}

	registryIdentity, err := h.Resolver.ResolveRegistry(r.Context(), r.Host)
	if err != nil {
		writeError(w, http.StatusBadGateway, "REGISTRY_UNAVAILABLE", err.Error())
		return
	}

	action, ok := routeAction(resource, r.Method)
	if !ok {
		writeError(w, http.StatusNotFound, "NAME_UNKNOWN", "unknown path")
		return
	}

	principal, err := h.Authenticator.Authenticate(r.Context(), r.Header.Get("Authorization"), registryIdentity.Host, repo, action)
	if err != nil {
		if errors.Is(err, auth.ErrMissingToken) && action == auth.ActionPull {
			principal = auth.Principal{Subject: auth.AnonymousSubject}
		} else {
			w.Header().Set("WWW-Authenticate", bearerChallenge(h.AuthRealm, registryIdentity.Host, repo, string(action)))
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", string(action)+" access denied")
			return
		}
	}

	switch resource {
	case "uploads":
		h.handleUpload(w, r, registryIdentity, repo, reference, principal)
	case "manifests":
		if r.Method == http.MethodPut {
			h.handleManifestPut(w, r, registryIdentity, repo, reference, principal)
			return
		}
		h.handlePullManifest(w, r, registryIdentity, repo, reference, principal)
	case "blobs":
		h.handlePullBlob(w, r, registryIdentity, repo, reference, principal)
	default:
		writeError(w, http.StatusNotFound, "NAME_UNKNOWN", "unknown path")
	}
}

// routeAction maps a matched route resource to the registry action its
// authorization scope demands. Uploads (all methods) and manifest PUT are
// push; manifest reads and blob reads are pull. The action is derived before
// any handler work so method-specific dispatch inside handlers never runs
// before authentication.
func routeAction(resource string, method string) (auth.Action, bool) {
	switch resource {
	case "uploads":
		return auth.ActionPush, true
	case "manifests":
		if method == http.MethodPut {
			return auth.ActionPush, true
		}
		return auth.ActionPull, true
	case "blobs":
		return auth.ActionPull, true
	default:
		return "", false
	}
}

func (h *Handler) handlePullManifest(w http.ResponseWriter, r *http.Request, registryIdentity resolve.RegistryIdentity, repo string, reference string, principal auth.Principal) {
	authorized, err := h.PullAuthorizer.Authorize(r.Context(), registryIdentity, repo, principal)
	if err != nil {
		writeError(w, http.StatusBadGateway, "AUTH_POLICY_UNAVAILABLE", err.Error())
		return
	}
	if !authorized {
		w.Header().Set("WWW-Authenticate", bearerChallenge(h.AuthRealm, registryIdentity.Host, repo, "pull"))
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "pull access denied")
		return
	}

	state, err := h.Resolver.ResolveRepoState(r.Context(), registryIdentity, repo)
	if err != nil {
		writeError(w, http.StatusNotFound, "NAME_UNKNOWN", err.Error())
		return
	}

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	digest := reference
	if !strings.HasPrefix(reference, "sha256:") {
		var ok bool
		digest, ok = state.Tags[reference]
		if !ok {
			writeError(w, http.StatusNotFound, "MANIFEST_UNKNOWN", "tag not found")
			return
		}
	}

	desc, ok := state.Manifests[digest]
	if !ok {
		writeError(w, http.StatusNotFound, "MANIFEST_UNKNOWN", "manifest not found")
		return
	}

	data, err := h.Objects.Get(r.Context(), desc.SwarmRef)
	if err != nil {
		writeError(w, http.StatusBadGateway, "MANIFEST_BLOB_UNKNOWN", err.Error())
		return
	}

	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Content-Type", desc.MediaType)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (h *Handler) handlePullBlob(w http.ResponseWriter, r *http.Request, registryIdentity resolve.RegistryIdentity, repo string, digest string, principal auth.Principal) {
	authorized, err := h.PullAuthorizer.Authorize(r.Context(), registryIdentity, repo, principal)
	if err != nil {
		writeError(w, http.StatusBadGateway, "AUTH_POLICY_UNAVAILABLE", err.Error())
		return
	}
	if !authorized {
		w.Header().Set("WWW-Authenticate", bearerChallenge(h.AuthRealm, registryIdentity.Host, repo, "pull"))
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "pull access denied")
		return
	}

	state, err := h.Resolver.ResolveRepoState(r.Context(), registryIdentity, repo)
	if err != nil {
		writeError(w, http.StatusNotFound, "NAME_UNKNOWN", err.Error())
		return
	}

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	desc, ok := state.Blobs[digest]
	if !ok {
		writeError(w, http.StatusNotFound, "BLOB_UNKNOWN", "blob not found")
		return
	}

	data, err := h.Objects.Get(r.Context(), desc.SwarmRef)
	if err != nil {
		writeError(w, http.StatusBadGateway, "BLOB_UNKNOWN", err.Error())
		return
	}

	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	if desc.MediaType != "" {
		w.Header().Set("Content-Type", desc.MediaType)
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (h *Handler) handleUpload(w http.ResponseWriter, r *http.Request, registryIdentity resolve.RegistryIdentity, repo string, uploadID string, principal auth.Principal) {
	actor := principal.Subject

	batchID, authorized, err := h.PushAuthorizer.Authorize(r.Context(), registryIdentity, repo, principal)
	if err != nil {
		writeError(w, http.StatusBadGateway, "AUTH_POLICY_UNAVAILABLE", err.Error())
		return
	}
	if !authorized {
		w.Header().Set("WWW-Authenticate", bearerChallenge(h.AuthRealm, registryIdentity.Host, repo, "push"))
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "push access denied")
		return
	}

	if uploadID == "" {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		session, err := h.Staging.CreateSession(r.Context(), repo, actor, h.SessionTTL)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "BLOB_UPLOAD_UNKNOWN", err.Error())
			return
		}
		location := fmt.Sprintf("/v2/%s/blobs/uploads/%s", repo, session.ID)
		w.Header().Set("Location", location)
		w.Header().Set("Docker-Upload-UUID", session.ID)
		w.Header().Set("Range", "0-0")
		w.WriteHeader(http.StatusAccepted)
		return
	}

	session, ok, err := h.Staging.GetSession(r.Context(), uploadID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "BLOB_UPLOAD_UNKNOWN", err.Error())
		return
	}
	if !ok || session.Repo != repo || session.Actor != actor {
		writeError(w, http.StatusNotFound, "BLOB_UPLOAD_UNKNOWN", "upload session not found")
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeUploadStatus(w, repo, session)
	case http.MethodPatch:
		chunk, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "BLOB_UPLOAD_INVALID", err.Error())
			return
		}
		updated, err := h.Staging.Append(r.Context(), uploadID, chunk)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "BLOB_UPLOAD_INVALID", err.Error())
			return
		}
		writeUploadAccepted(w, repo, updated)
	case http.MethodPut:
		digest := r.URL.Query().Get("digest")
		if digest == "" {
			writeError(w, http.StatusBadRequest, "DIGEST_INVALID", "missing digest parameter")
			return
		}
		finalBytes, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "BLOB_UPLOAD_INVALID", err.Error())
			return
		}
		if len(finalBytes) > 0 {
			session, err = h.Staging.Append(r.Context(), uploadID, finalBytes)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "BLOB_UPLOAD_INVALID", err.Error())
				return
			}
		}
		data, err := h.Staging.Bytes(r.Context(), uploadID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "BLOB_UPLOAD_INVALID", err.Error())
			return
		}
		if computeDigest(data) != digest {
			writeError(w, http.StatusBadRequest, "DIGEST_INVALID", "digest mismatch")
			return
		}
		ref, err := h.Uploader.Put(r.Context(), data, batchID)
		if err != nil {
			writeError(w, http.StatusBadGateway, "BLOB_UPLOAD_INVALID", err.Error())
			return
		}
		if err := h.Staging.StageBlob(r.Context(), spec.StagedBlob{
			UploadID:  uploadID,
			Repo:      repo,
			Actor:     actor,
			Digest:    digest,
			SwarmRef:  ref,
			Size:      int64(len(data)),
			MediaType: r.Header.Get("Content-Type"),
			CreatedAt: session.CreatedAt,
			ExpiresAt: session.ExpiresAt,
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "BLOB_UPLOAD_INVALID", err.Error())
			return
		}
		if err := h.Staging.DeleteSession(r.Context(), uploadID); err != nil {
			writeError(w, http.StatusInternalServerError, "BLOB_UPLOAD_INVALID", err.Error())
			return
		}
		w.Header().Set("Docker-Content-Digest", digest)
		w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", repo, digest))
		w.WriteHeader(http.StatusCreated)
	case http.MethodDelete:
		if err := h.Staging.DeleteSession(r.Context(), uploadID); err != nil {
			writeError(w, http.StatusInternalServerError, "BLOB_UPLOAD_UNKNOWN", err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, PATCH, PUT, DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *Handler) handleManifestPut(w http.ResponseWriter, r *http.Request, registryIdentity resolve.RegistryIdentity, repo string, reference string, principal auth.Principal) {
	if strings.HasPrefix(reference, "sha256:") {
		writeError(w, http.StatusBadRequest, "MANIFEST_INVALID", "manifest publish by digest is not supported in v1")
		return
	}

	actor := principal.Subject

	batchID, authorized, err := h.PushAuthorizer.Authorize(r.Context(), registryIdentity, repo, principal)
	if err != nil {
		writeError(w, http.StatusBadGateway, "AUTH_POLICY_UNAVAILABLE", err.Error())
		return
	}
	if !authorized {
		w.Header().Set("WWW-Authenticate", bearerChallenge(h.AuthRealm, registryIdentity.Host, repo, "push"))
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "push access denied")
		return
	}

	current, err := h.Resolver.ResolveRepoState(r.Context(), registryIdentity, repo)
	if err != nil {
		writeError(w, http.StatusNotFound, "NAME_UNKNOWN", err.Error())
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "MANIFEST_INVALID", err.Error())
		return
	}

	stagedBlobs, err := h.Staging.ListStagedBlobs(r.Context(), repo, actor)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "MANIFEST_INVALID", err.Error())
		return
	}
	blobMap := make(map[string]spec.BlobDescriptor, len(stagedBlobs))
	for _, blob := range stagedBlobs {
		blobMap[blob.Digest] = spec.BlobDescriptor{
			SwarmRef:  blob.SwarmRef,
			Size:      blob.Size,
			MediaType: blob.MediaType,
		}
	}

	next, err := h.Publisher.Publish(r.Context(), spec.RepoStateFeedRef(registryIdentity.Owner, repo), current, publish.BuildInput{
		Repo:           repo,
		Tag:            reference,
		ManifestDigest: computeDigest(body),
		ManifestJSON:   body,
		Manifest: spec.ManifestDescriptor{
			MediaType: r.Header.Get("Content-Type"),
			Size:      int64(len(body)),
		},
		StagedBlobs: blobMap,
	}, batchID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "MANIFEST_INVALID", err.Error())
		return
	}

	if err := h.Staging.ClearStagedBlobs(r.Context(), repo, actor); err != nil {
		writeError(w, http.StatusInternalServerError, "MANIFEST_INVALID", err.Error())
		return
	}

	digest := next.Tags[reference]
	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Location", fmt.Sprintf("/v2/%s/manifests/%s", repo, reference))
	w.WriteHeader(http.StatusCreated)
}

func parsePath(path string) (repo string, resource string, reference string, ok bool) {
	trimmed := strings.TrimPrefix(path, "/v2/")
	for _, marker := range []struct {
		resource string
		token    string
	}{
		{resource: "uploads", token: "/blobs/uploads/"},
		{resource: "manifests", token: "/manifests/"},
		{resource: "blobs", token: "/blobs/"},
	} {
		if idx := strings.Index(trimmed, marker.token); idx >= 0 {
			return trimmed[:idx], marker.resource, trimmed[idx+len(marker.token):], true
		}
	}

	return "", "", "", false
}

func bearerChallenge(realm string, service string, repo string, action string) string {
	return fmt.Sprintf(`Bearer realm=%q,service=%q,scope=%q`, realm, service, "repository:"+repo+":"+action)
}

func writeUploadStatus(w http.ResponseWriter, repo string, session spec.UploadSession) {
	w.Header().Set("Docker-Upload-UUID", session.ID)
	w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/uploads/%s", repo, session.ID))
	w.Header().Set("Range", uploadRange(session.Offset))
	w.WriteHeader(http.StatusNoContent)
}

func writeUploadAccepted(w http.ResponseWriter, repo string, session spec.UploadSession) {
	w.Header().Set("Docker-Upload-UUID", session.ID)
	w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/uploads/%s", repo, session.ID))
	w.Header().Set("Range", uploadRange(session.Offset))
	w.WriteHeader(http.StatusAccepted)
}

func uploadRange(offset int64) string {
	if offset <= 0 {
		return "0-0"
	}
	return fmt.Sprintf("0-%d", offset-1)
}

func computeDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum[:])
}

func writeError(w http.ResponseWriter, status int, code string, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"errors": []map[string]string{
			{
				"code":    code,
				"message": message,
			},
		},
	})
}
