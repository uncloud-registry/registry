package spec

import (
	"encoding/json"
	"errors"
	"fmt"
)

type RootRegistryDocument struct {
	Version  int                      `json:"version"`
	Registry string                   `json:"registry"`
	Repos    map[string]RepoRootEntry `json:"repos"`
	Auth     RootAuthConfig           `json:"auth"`
	Stamps   RootStampConfig          `json:"stamps"`
}

type RepoRootEntry struct {
	StateFeed string `json:"stateFeed"`
}

type RootAuthConfig struct {
	Realm             string `json:"realm"`
	Service           string `json:"service"`
	DefaultPolicyFeed string `json:"defaultPolicyFeed"`
}

type RootStampConfig struct {
	DefaultPolicyFeed string `json:"defaultPolicyFeed"`
}

type RepoStateDocument struct {
	Version    int                           `json:"version"`
	Repo       string                        `json:"repo"`
	Generation int64                         `json:"generation"`
	UpdatedAt  string                        `json:"updatedAt"`
	Tags       map[string]string             `json:"tags"`
	Manifests  map[string]ManifestDescriptor `json:"manifests"`
	Blobs      map[string]BlobDescriptor     `json:"blobs"`
	// TagPublications records, PER TAG, the durable publication provenance of
	// the tag's CURRENT mapping: the exact operation identity that produced
	// it, the generation it was applied at, and the digest it points at. One
	// bounded entry per tag — replaced when the tag moves, retained across
	// unrelated publications, and never an unbounded history — so a retry can
	// recover the EXACT prior operation from durable state instead of
	// re-inferring it from the current generation. A document WITHOUT this
	// field (legacy valid state) keeps decoding; there the exact prior
	// operation identity is simply not recoverable and must never be
	// fabricated.
	TagPublications map[string]TagPublication `json:"tagPublications,omitempty"`
}

// TagPublication is the durable per-tag provenance entry (Task 14 round 2).
type TagPublication struct {
	OperationID string `json:"operationID"`
	Generation  int64  `json:"generation"`
	Digest      string `json:"digest"`
}

type ManifestDescriptor struct {
	SwarmRef  string `json:"swarmRef"`
	MediaType string `json:"mediaType"`
	Size      int64  `json:"size"`
}

type BlobDescriptor struct {
	SwarmRef  string `json:"swarmRef"`
	Size      int64  `json:"size"`
	MediaType string `json:"mediaType"`
}

type AuthPolicyDocument struct {
	Version       int                            `json:"version"`
	DefaultAccess string                         `json:"defaultAccess"`
	DefaultRepo   *RepoAuthPolicyEntry           `json:"defaultRepo,omitempty"`
	Repos         map[string]RepoAuthPolicyEntry `json:"repos"`
}

type RepoAuthPolicyEntry struct {
	Pull []string `json:"pull"`
	Push []string `json:"push"`
}

type StampPolicyDocument struct {
	Version       int                          `json:"version"`
	DefaultPolicy StampAccessPolicy            `json:"defaultPolicy"`
	Repos         map[string]StampAccessPolicy `json:"repos"`
}

type StampAccessPolicy struct {
	BatchID      string   `json:"batchID"`
	AllowPushFor []string `json:"allowPushFor"`
}

type UploadSession struct {
	ID         string `json:"id"`
	Repo       string `json:"repo"`
	Actor      string `json:"actor"`
	Offset     int64  `json:"offset"`
	CreatedAt  string `json:"createdAt"`
	ExpiresAt  string `json:"expiresAt"`
	BlobDigest string `json:"blobDigest,omitempty"`
}

type StagedBlob struct {
	UploadID  string `json:"uploadID"`
	Repo      string `json:"repo"`
	Actor     string `json:"actor"`
	Digest    string `json:"digest"`
	SwarmRef  string `json:"swarmRef"`
	Size      int64  `json:"size"`
	MediaType string `json:"mediaType,omitempty"`
	CreatedAt string `json:"createdAt"`
	ExpiresAt string `json:"expiresAt"`
}

func DecodeRootRegistryDocument(data []byte) (RootRegistryDocument, error) {
	var doc RootRegistryDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return RootRegistryDocument{}, fmt.Errorf("decode root registry document: %w", err)
	}
	return doc, doc.Validate()
}

func DecodeRepoStateDocument(data []byte) (RepoStateDocument, error) {
	var doc RepoStateDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return RepoStateDocument{}, fmt.Errorf("decode repo state document: %w", err)
	}
	return doc, doc.Validate()
}

func DecodeAuthPolicyDocument(data []byte) (AuthPolicyDocument, error) {
	var doc AuthPolicyDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return AuthPolicyDocument{}, fmt.Errorf("decode auth policy document: %w", err)
	}
	return doc, doc.Validate()
}

func DecodeStampPolicyDocument(data []byte) (StampPolicyDocument, error) {
	var doc StampPolicyDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return StampPolicyDocument{}, fmt.Errorf("decode stamp policy document: %w", err)
	}
	return doc, doc.Validate()
}

func (d RootRegistryDocument) Validate() error {
	switch {
	case d.Version != 1:
		return fmt.Errorf("unsupported root registry document version: %d", d.Version)
	case d.Registry == "":
		return errors.New("root registry document missing registry")
	case d.Repos == nil:
		return errors.New("root registry document missing repos")
	case d.Auth.Realm == "":
		return errors.New("root registry document missing auth.realm")
	case d.Auth.Service == "":
		return errors.New("root registry document missing auth.service")
	case d.Auth.DefaultPolicyFeed == "":
		return errors.New("root registry document missing auth.defaultPolicyFeed")
	case d.Stamps.DefaultPolicyFeed == "":
		return errors.New("root registry document missing stamps.defaultPolicyFeed")
	}

	for repo, entry := range d.Repos {
		if repo == "" {
			return errors.New("root registry document has empty repo key")
		}
		if entry.StateFeed == "" {
			return fmt.Errorf("root registry document repo %q missing stateFeed", repo)
		}
	}

	return nil
}

func (d RepoStateDocument) Validate() error {
	switch {
	case d.Version != 1:
		return fmt.Errorf("unsupported repo state version: %d", d.Version)
	case d.Repo == "":
		return errors.New("repo state missing repo")
	case d.Generation < 0:
		return errors.New("repo state generation must be non-negative")
	case d.Tags == nil:
		return errors.New("repo state missing tags")
	case d.Manifests == nil:
		return errors.New("repo state missing manifests")
	case d.Blobs == nil:
		return errors.New("repo state missing blobs")
	}

	for tag, digest := range d.Tags {
		if tag == "" || digest == "" {
			return errors.New("repo state tags must not contain empty key or value")
		}
		if _, ok := d.Manifests[digest]; !ok {
			return fmt.Errorf("repo state tag %q points to missing manifest %q", tag, digest)
		}
	}

	for digest, manifest := range d.Manifests {
		if digest == "" || manifest.SwarmRef == "" {
			return errors.New("repo state manifests must contain digest and swarmRef")
		}
	}

	for digest, blob := range d.Blobs {
		if digest == "" || blob.SwarmRef == "" {
			return errors.New("repo state blobs must contain digest and swarmRef")
		}
	}

	// Per-tag publication provenance is validated to be COHERENT with the
	// document so malformed or forged provenance FAILS CLOSED at decode and
	// can never be echoed to a caller: the operation ID must satisfy the exact
	// bounded grammar, the applied generation must lie within
	// [1, doc.Generation], and the recorded digest must equal the tag's
	// CURRENT mapping (so a forged entry cannot point at a different target).
	// An absent or null field on an otherwise valid document (legacy state)
	// is fine: the exact prior operation is simply not recoverable there.
	if d.TagPublications != nil {
		for tag, pub := range d.TagPublications {
			if tag == "" || pub.OperationID == "" || pub.Digest == "" {
				return errors.New("repo state publication provenance must not contain empty tag, operationID, or digest")
			}
			if !IsValidPublicationOperationID(pub.OperationID) {
				return fmt.Errorf("repo state publication provenance operation ID for tag %q violates the bounded operation-ID grammar", tag)
			}
			if pub.Generation < 1 || pub.Generation > d.Generation {
				return fmt.Errorf("repo state publication provenance generation for tag %q is outside the document generation range", tag)
			}
			if d.Tags[tag] != pub.Digest {
				return fmt.Errorf("repo state publication provenance digest for tag %q disagrees with the current tag mapping", tag)
			}
		}
	}

	return nil
}

func (d AuthPolicyDocument) Validate() error {
	switch {
	case d.Version != 1:
		return fmt.Errorf("unsupported auth policy version: %d", d.Version)
	case d.DefaultAccess == "":
		return errors.New("auth policy missing defaultAccess")
	case d.Repos == nil:
		return errors.New("auth policy missing repos")
	}

	return nil
}

func (d StampPolicyDocument) Validate() error {
	switch {
	case d.Version != 1:
		return fmt.Errorf("unsupported stamp policy version: %d", d.Version)
	case d.DefaultPolicy.BatchID == "":
		return errors.New("stamp policy missing defaultPolicy.batchID")
	case d.Repos == nil:
		return errors.New("stamp policy missing repos")
	}

	if err := d.DefaultPolicy.Validate(); err != nil {
		return fmt.Errorf("invalid default stamp policy: %w", err)
	}

	for repo, policy := range d.Repos {
		if repo == "" {
			return errors.New("stamp policy contains empty repo key")
		}
		if err := policy.Validate(); err != nil {
			return fmt.Errorf("invalid stamp policy for repo %q: %w", repo, err)
		}
	}

	return nil
}

func (p StampAccessPolicy) Validate() error {
	if p.BatchID == "" {
		return errors.New("stamp access policy missing batchID")
	}
	return nil
}

// PublicationOperationIDMaxLen mirrors publish.OperationIDMaxLen (128 bytes):
// the maximum length of a persisted publication provenance operation ID.
// Kept in lockstep by the parity test in internal/spec.
const PublicationOperationIDMaxLen = 128

// IsValidPublicationOperationID reports whether s satisfies the EXACT
// operation-ID grammar publish.ValidateOperationID enforces (bounded
// JSON-safe printable ASCII: 0x20..0x7e minus the HTML/JSON-significant
// characters ", \, <, >, &). It exists so persisted provenance operation IDs
// are validated at decode time without an import cycle (publish imports
// spec); the parity test keeps the two grammars byte-identical, so a value
// that passes here is exactly a value publish would accept as a caller key.
func IsValidPublicationOperationID(s string) bool {
	if s == "" || len(s) > PublicationOperationIDMaxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e || c == '"' || c == '\\' || c == '<' || c == '>' || c == '&' {
			return false
		}
	}
	return true
}
