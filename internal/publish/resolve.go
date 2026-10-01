package publish

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/uncloud-registry/registry/internal/resolve"
)

// resolveResponseMaxBody bounds the resolve endpoint's response body. A
// ResolveResponse is two bounded fields; 4 KiB is far beyond it while still
// rejecting oversized hostile input before decode.
const resolveResponseMaxBody = 4096

// ControlPlaneRegistryIdentityResolver resolves a registry host to its
// feed-owner address and control-plane RegistryID through the control plane's
// internal dynamic-resolution endpoint. It is the data-plane counterpart of
// the InternalFeedServer resolve route and reuses the SAME shared credential
// header and secret as feed commits and operation bindings — there is no
// separate bearer token for resolution.
//
// Resolution is a LIVE call on every request (no cache): the caller is the
// per-request identity resolution path, and the control plane is the single
// source of truth for host → (owner, registryID).
type ControlPlaneRegistryIdentityResolver struct {
	BaseURL    string
	Secret     []byte
	HTTPClient *http.Client
}

// ResolveRegistry implements resolve.RegistryIdentityResolver. It strips the
// port (the control plane stores hosts WITHOUT a port) before lookup, sends
// the shared credential header, and strictly decodes the response. Every raw
// transport/decode/URL error collapses to a data-free error so no host, port,
// dial detail, or body leaks through err.Error().
func (r ControlPlaneRegistryIdentityResolver) ResolveRegistry(ctx context.Context, host string) (resolve.RegistryIdentity, error) {
	hostname := stripPort(host)
	if hostname == "" {
		return resolve.RegistryIdentity{}, errors.New("resolve registry: host is empty")
	}

	baseURL, err := parseCommitBaseURL(r.BaseURL)
	if err != nil {
		return resolve.RegistryIdentity{}, errors.New("resolve registry: control plane URL is not configured")
	}
	if len(r.Secret) == 0 {
		return resolve.RegistryIdentity{}, errors.New("resolve registry: internal credential is not configured")
	}

	client := r.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	target := baseURL + InternalResolvePath + url.PathEscape(hostname)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return resolve.RegistryIdentity{}, errors.New("resolve registry: malformed request")
	}
	req.Header.Set(InternalAuthHeader, string(r.Secret))

	resp, err := client.Do(req)
	if err != nil {
		return resolve.RegistryIdentity{}, errors.New("resolve registry: control plane unavailable")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, resolveResponseMaxBody+1))
	if err != nil {
		return resolve.RegistryIdentity{}, errors.New("resolve registry: control plane unavailable")
	}
	if len(body) > resolveResponseMaxBody {
		return resolve.RegistryIdentity{}, errors.New("resolve registry: malformed response")
	}

	switch resp.StatusCode {
	case http.StatusOK:
		identity, err := decodeResolveResponse(body)
		if err != nil {
			return resolve.RegistryIdentity{}, err
		}
		identity.Host = hostname
		return identity, nil
	case http.StatusNotFound:
		return resolve.RegistryIdentity{}, fmt.Errorf("registry host %q not found", hostname)
	case http.StatusUnauthorized:
		return resolve.RegistryIdentity{}, errors.New("resolve registry: internal credential rejected")
	default:
		return resolve.RegistryIdentity{}, errors.New("resolve registry: control plane unavailable")
	}
}

// decodeResolveResponse strictly decodes a bounded resolve response: duplicate
// members, unknown fields, and trailing content are rejected, and the owner
// must be non-empty with a positive RegistryID before it is accepted.
func decodeResolveResponse(data []byte) (resolve.RegistryIdentity, error) {
	if err := rejectDuplicateJSONMembers(data); err != nil {
		return resolve.RegistryIdentity{}, errors.New("resolve registry: malformed response")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var resp ResolveResponse
	if err := dec.Decode(&resp); err != nil {
		return resolve.RegistryIdentity{}, errors.New("resolve registry: malformed response")
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return resolve.RegistryIdentity{}, errors.New("resolve registry: malformed response")
	}
	if strings.TrimSpace(resp.Owner) == "" {
		return resolve.RegistryIdentity{}, errors.New("resolve registry: malformed response")
	}
	if resp.RegistryID <= 0 {
		return resolve.RegistryIdentity{}, errors.New("resolve registry: malformed response")
	}
	return resolve.RegistryIdentity{Owner: resp.Owner, RegistryID: resp.RegistryID}, nil
}

// stripPort removes a trailing host:port from a hostname, mirroring the
// resolve package's ENS resolver. A value without a port is returned as-is.
func stripPort(host string) string {
	hostname, _, err := net.SplitHostPort(host)
	if err == nil {
		return hostname
	}
	return host
}
