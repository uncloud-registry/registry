package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// Registry token purpose separation: registry tokens are Ed25519/EdDSA only,
// carry a non-empty known kid, typ=registry, the exact control-plane issuer,
// and a repository-scoped access list. They share no parser, key, or algorithm
// with session tokens.
const (
	RegistryTokenType = "registry"
	RegistryIssuer    = "uncloud-registry/control-plane"
	accessTypeRepo    = "repository"
)

// RegistryAccess is one repository scope entry inside a registry token.
type RegistryAccess struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []Action `json:"actions"`
}

// RegistryClaims is the payload of an Ed25519 registry token.
type RegistryClaims struct {
	TokenType string           `json:"typ"`
	Service   string           `json:"service"`
	Access    []RegistryAccess `json:"access"`
	jwt.RegisteredClaims
}

// RegistryTokenRequest is the structured input to RegistryTokenIssuer.Issue.
type RegistryTokenRequest struct {
	Subject    string
	Service    string
	Repository string
	Actions    []Action
	TTL        time.Duration
}

// PublicKeySet resolves an Ed25519 verification key by its key ID, enabling key
// rotation. Errors and malformed keys must cause verification to fail closed.
type PublicKeySet interface {
	Key(ctx context.Context, keyID string) (ed25519.PublicKey, error)
}

// RegistryTokenIssuer signs scoped registry tokens with an Ed25519 private key.
type RegistryTokenIssuer struct {
	privateKey ed25519.PrivateKey
	issuer     string
	keyID      string
}

// NewRegistryTokenIssuer builds an issuer. The key MUST be Ed25519; alg fallback
// is never performed.
func NewRegistryTokenIssuer(privateKey ed25519.PrivateKey, issuer, keyID string) (*RegistryTokenIssuer, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("registry token signing key must be an ed25519 private key")
	}
	if issuer == "" {
		return nil, errors.New("registry token issuer is required")
	}
	if strings.TrimSpace(keyID) == "" {
		return nil, errors.New("registry token key id is required")
	}
	return &RegistryTokenIssuer{privateKey: privateKey, issuer: issuer, keyID: keyID}, nil
}

// Issue signs a repository-scoped registry token for the request.
func (i *RegistryTokenIssuer) Issue(_ context.Context, req RegistryTokenRequest) (string, error) {
	if req.Subject == "" || req.Service == "" || req.Repository == "" {
		return "", errors.New("registry token subject, service, and repository are required")
	}
	if len(req.Actions) == 0 {
		return "", errors.New("registry token requires at least one action")
	}
	deduped := make([]Action, 0, len(req.Actions))
	seen := map[Action]struct{}{}
	for _, a := range req.Actions {
		if a != ActionPull && a != ActionPush {
			return "", fmt.Errorf("unknown registry token action %q", a)
		}
		if _, dup := seen[a]; dup {
			continue
		}
		seen[a] = struct{}{}
		deduped = append(deduped, a)
	}

	now := time.Now()
	claims := RegistryClaims{
		TokenType: RegistryTokenType,
		Service:   req.Service,
		Access: []RegistryAccess{{
			Type:    accessTypeRepo,
			Name:    req.Repository,
			Actions: deduped,
		}},
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   req.Subject,
			Issuer:    i.issuer,
			Audience:  jwt.ClaimStrings{req.Service},
			ExpiresAt: jwt.NewNumericDate(now.Add(req.TTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        newJWTID(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = i.keyID
	return token.SignedString(i.privateKey)
}

// RegistryTokenVerifier validates Ed25519 registry tokens against a PublicKeySet
// and an expected issuer + audience/service. Verify is the consumer interface for
// Task 5.
type RegistryTokenVerifier struct {
	keys    PublicKeySet
	issuer  string
	service string
}

// NewRegistryTokenVerifier binds a verifier to a key set, the exact issuer, and
// the exact service/audience the token must have been issued for.
func NewRegistryTokenVerifier(keys PublicKeySet, issuer, service string) *RegistryTokenVerifier {
	return &RegistryTokenVerifier{keys: keys, issuer: issuer, service: service}
}

// Verify validates raw and returns the verified Principal iff the token is a
// well-formed Ed25519 registry token issued for the exact service and grants the
// requested repository+action. Every structural, key, claim, or scope violation
// fails closed with wrapped context; errors never leak key material.
func (v *RegistryTokenVerifier) Verify(raw, service, repository string, action Action) (Principal, error) {
	var empty Principal
	if v.keys == nil {
		return empty, errors.New("registry token verifier requires a public key set")
	}
	if service == "" || repository == "" {
		return empty, errors.New("service and repository are required")
	}
	if action != ActionPull && action != ActionPush {
		return empty, fmt.Errorf("unknown requested action %q", action)
	}

	// Inspect the unverified header so algorithm and key-id requirements are
	// enforced BEFORE any key material is derived.
	unverified, _, err := jwt.NewParser().ParseUnverified(raw, &RegistryClaims{})
	if err != nil {
		return empty, fmt.Errorf("malformed registry token: %w", err)
	}
	kid, _ := unverified.Header["kid"].(string)
	if strings.TrimSpace(kid) == "" {
		return empty, errors.New("registry token missing kid")
	}
	alg, _ := unverified.Header["alg"].(string)
	if alg != jwt.SigningMethodEdDSA.Alg() {
		return empty, fmt.Errorf("registry token algorithm must be EdDSA (got %q)", alg)
	}

	key, err := v.keys.Key(context.Background(), kid)
	if err != nil {
		return empty, fmt.Errorf("resolve registry token key: %w", err)
	}
	if len(key) != ed25519.PublicKeySize {
		return empty, fmt.Errorf("invalid registry token public key shape for kid %q", kid)
	}

	claims := &RegistryClaims{}
	parsed, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodEdDSA {
			return nil, fmt.Errorf("unexpected registry token algorithm %v", t.Header["alg"])
		}
		return key, nil
	})
	if err != nil {
		return empty, err
	}
	if !parsed.Valid {
		return empty, errors.New("invalid registry token")
	}
	if claims.TokenType != RegistryTokenType {
		return empty, fmt.Errorf("registry token type mismatch: %q", claims.TokenType)
	}
	if claims.Issuer != v.issuer {
		return empty, errors.New("registry token issuer mismatch")
	}
	if claims.Service != service || claims.Service != v.service {
		return empty, errors.New("registry token service mismatch")
	}
	if !hasAudience(claims.Audience, service) {
		return empty, errors.New("registry token audience mismatch")
	}
	if claims.Subject == "" {
		return empty, errors.New("registry token missing subject")
	}
	if claims.ID == "" {
		return empty, errors.New("registry token missing token id")
	}
	if claims.ExpiresAt == nil {
		return empty, errors.New("registry token missing expiry")
	}

	// Parse the access list, failing closed on any malformed, unknown, or
	// ambiguous scope representation.
	actions := map[Action]struct{}{}
	found := false
	matches := 0
	for _, entry := range claims.Access {
		if entry.Type != accessTypeRepo {
			return empty, fmt.Errorf("registry token grants unsupported access type %q", entry.Type)
		}
		if entry.Name == "" {
			return empty, errors.New("registry token grants access to an empty repository name")
		}
		entryActions, err := knownActions(entry.Actions, entry.Name)
		if err != nil {
			return empty, err
		}
		if entry.Name == repository {
			matches++
			if matches > 1 {
				return empty, errors.New("registry token grants ambiguous multi-access for the requested repository")
			}
			for a := range entryActions {
				actions[a] = struct{}{}
			}
			found = true
		}
	}
	if !found {
		return empty, ErrScopeDenied
	}
	if _, ok := actions[action]; !ok {
		return empty, ErrScopeDenied
	}

	return Principal{
		Subject:    claims.Subject,
		TokenID:    claims.ID,
		Service:    claims.Service,
		Repository: repository,
		Actions:    actions,
	}, nil
}

// knownActions rejects duplicate or unknown actions inside a granted scope.
func knownActions(actions []Action, repo string) (map[Action]struct{}, error) {
	set := make(map[Action]struct{}, len(actions))
	for _, a := range actions {
		if a != ActionPull && a != ActionPush {
			return nil, fmt.Errorf("registry token grants unknown action %q for repository %q", a, repo)
		}
		if _, dup := set[a]; dup {
			return nil, fmt.Errorf("registry token grants duplicate action %q for repository %q", a, repo)
		}
		set[a] = struct{}{}
	}
	return set, nil
}

// ParseDockerScope parses a Docker token scope exactly as
// "repository:<name>:<comma-separated-actions>". It rejects missing/extra
// fields, an empty repository, and empty, duplicate, or unknown actions, and it
// normalizes nothing silently. Identifiers are preserved literally.
func ParseDockerScope(scope string) (repository string, actions []Action, err error) {
	parts := strings.Split(scope, ":")
	if len(parts) != 3 {
		return "", nil, fmt.Errorf("invalid scope %q: expected repository:<name>:<actions>", scope)
	}
	if parts[0] != accessTypeRepo {
		return "", nil, fmt.Errorf("invalid scope %q: unsupported scope type %q", scope, parts[0])
	}
	repository = parts[1]
	if repository == "" {
		return "", nil, fmt.Errorf("invalid scope %q: empty repository name", scope)
	}

	rawActions := strings.Split(parts[2], ",")
	actions = make([]Action, 0, len(rawActions))
	seen := map[Action]struct{}{}
	for _, raw := range rawActions {
		if raw == "" {
			return "", nil, fmt.Errorf("invalid scope %q: empty action", scope)
		}
		a := Action(raw)
		if a != ActionPull && a != ActionPush {
			return "", nil, fmt.Errorf("invalid scope %q: unknown action %q", scope, raw)
		}
		if _, dup := seen[a]; dup {
			return "", nil, fmt.Errorf("invalid scope %q: duplicate action %q", scope, raw)
		}
		seen[a] = struct{}{}
		actions = append(actions, a)
	}
	return repository, actions, nil
}

func newJWTID() string {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(raw)
}
