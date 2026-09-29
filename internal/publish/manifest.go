package publish

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Supported top-level artifact media types. ParseArtifact accepts EXACTLY
// these four; any other top-level media type (including schema-1 manifests and
// empty values) is an unsupported-artifact error.
const (
	MediaTypeOCIManifest        = "application/vnd.oci.image.manifest.v1+json"
	MediaTypeOCIIndex           = "application/vnd.oci.image.index.v1+json"
	MediaTypeDockerManifest     = "application/vnd.docker.distribution.manifest.v2+json"
	MediaTypeDockerManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"
)

// MaxArtifactBodyBytes is the documented upper bound on a manifest/index body.
// It is enforced BEFORE any JSON decode so an oversized upload can never reach
// the parser. 4 MiB accommodates images with thousands of layers while
// bounding memory and CPU per publication.
const MaxArtifactBodyBytes = 4 << 20

// Metadata string bounds for accepted descriptor/platform fields. annotations,
// urls, and data are now accepted on OCI descriptors (see descriptorPolicy);
// every string and collection is bounded here.
const (
	maxDescriptorMediaTypeLen = 4096
	maxPlatformStringLen      = 1024
	maxPlatformFeatures       = 64
	maxArtifactTypeLen        = 4096
	maxAnnotationsCount       = 1024
	maxAnnotationKeyLen       = 4096
	maxAnnotationValueLen     = 4096
	maxDescriptorURLsCount    = 256
	maxDescriptorURLLen       = 4096
)

// Shared index-size policy. These maxima are the SINGLE authority used by the
// artifact parser (fail-before-upload), the registry read-after-write
// verification, and the control-plane feed signer (fail-closed) so an image
// index / manifest list can never drive an unbounded verification read and one
// digest is never read more than once.
//
//   - MaxIndexChildDescriptors bounds the number of child descriptors an index
//     may DECLARE (including identical duplicates). A list body is already
//     bounded by MaxArtifactBodyBytes, but this makes the count burden explicit
//     and independent of the body-size cap.
//   - MaxUniqueIndexChildManifests bounds the number of DISTINCT child digests
//     after digest deduplication — the number of child bodies verification will
//     ever read.
//   - MaxAggregateIndexChildBytes bounds the aggregate of the DECLARED sizes of
//     the DISTINCT children. Verification reads each distinct child body
//     exactly once and rejects the set when the sum of the ACTUAL read bytes
//     exceeds this bound too, so the aggregate verification read is bounded
//     within the same artifact size regime (each child is itself capped at
//     MaxArtifactBodyBytes).
const (
	MaxIndexChildDescriptors    = 10000
	MaxUniqueIndexChildManifests = 4096
	MaxAggregateIndexChildBytes  = 256 << 20 // 256 MiB
)

// supportedChildManifestMediaTypes are the ONLY media types an index child
// descriptor may reference. Each child of an OCI image index / Docker manifest
// list MUST be a single-platform image manifest; a nested index (an index
// referencing another index) is NOT supported in v1 — no recursion. Anything
// else (a bare blob type, an artifact type, etc.) is an invalid child and is
// rejected before any publication write.
var supportedChildManifestMediaTypes = map[string]struct{}{
	MediaTypeOCIManifest:    {},
	MediaTypeDockerManifest: {},
}

// IsSupportedChildManifestMediaType reports whether mt is a media type an
// index child descriptor may reference: a supported single-platform image
// manifest, and never a nested index. It is the single authority used by the
// publication reference gate and the read-after-write verification.
func IsSupportedChildManifestMediaType(mt string) bool {
	_, ok := supportedChildManifestMediaTypes[mt]
	return ok
}

// ArtifactKind discriminates the two supported top-level shapes.
type ArtifactKind int

const (
	// ArtifactKindManifest is an OCI image manifest / Docker schema-2
	// manifest: requires config and layers.
	ArtifactKindManifest ArtifactKind = iota
	// ArtifactKindIndex is an OCI image index / Docker manifest list:
	// requires a manifests array (which MAY be empty — both the OCI image
	// index spec and the Docker manifest-list spec require the property but
	// impose no non-empty minimum) and forbids the manifest-only
	// (config/layers) shape.
	ArtifactKindIndex
)

// Descriptor is a validated OCI descriptor as referenced by a manifest or
// index. It is the metadata Tasks 13/19 consume: digest, size, media type,
// platform (index children only), and — for OCI descriptors — the optional
// urls / annotations / data members that are validated for type, boundedness,
// and (for data) base64/size/digest coherence. Parsing is validation, never
// transcoding: the original artifact body is retained byte-identically, so
// these fields are introspection only and never re-emitted.
type Descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Platform    *Platform         `json:"platform,omitempty"`
	URLs        []string          `json:"urls,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Data        []byte            `json:"data,omitempty"`
}

// descriptorPolicy controls which OPTIONAL descriptor members are valid in a
// given structural position, so descriptor schema validation is
// media-type-and-position specific. All OCI descriptors accept the OCI 1.1
// optional urls / annotations / data members; Docker descriptors reject the
// OCI-only annotations/data, and a Docker manifest-list child additionally
// REQUIRES a platform object while an OCI image-index child keeps platform
// optional.
type descriptorPolicy struct {
	allowPlatform    bool
	requirePlatform  bool // Docker manifest-list children only
	allowURLs        bool
	allowAnnotations bool
	allowData        bool
}

var (
	// ociDescriptorPolicy applies to OCI descriptors: manifest config, manifest
	// layer, and any subject descriptor. All OCI 1.1 optional descriptor
	// members (urls, annotations, data) are valid; platform is not (platform is
	// only meaningful on index children).
	ociDescriptorPolicy = descriptorPolicy{allowURLs: true, allowAnnotations: true, allowData: true}
	// ociIndexChildPolicy applies to an OCI image-index child descriptor:
	// platform is additional and OPTIONAL, and OCI optional members are valid.
	ociIndexChildPolicy = descriptorPolicy{allowPlatform: true, allowURLs: true, allowAnnotations: true, allowData: true}
	// dockerManifestConfigPolicy applies to a Docker schema-2 config
	// descriptor: its spec surface is exactly mediaType / size / digest, with
	// no optional members.
	dockerManifestConfigPolicy = descriptorPolicy{}
	// dockerManifestLayerPolicy applies to a Docker schema-2 layer descriptor:
	// urls is allowed per the Docker Distribution manifest-v2-2 descriptor;
	// annotations and data are OCI-only and rejected.
	dockerManifestLayerPolicy = descriptorPolicy{allowURLs: true}
	// dockerManifestListChildPolicy applies to a Docker manifest-list child:
	// platform is REQUIRED per the Docker Distribution manifest-v2-2 schema,
	// and no OCI-only member (urls is also not part of the manifest-list child
	// schema) is accepted.
	dockerManifestListChildPolicy = descriptorPolicy{requirePlatform: true}
)

// Platform is a validated index-child platform. architecture and os are
// required; every string is bounded. os.features lists mandatory OS features
// and features lists mandatory CPU features (per the Docker manifest-list and
// OCI image-index platform objects); both are optional, bounded arrays of
// strings.
type Platform struct {
	Architecture string   `json:"architecture"`
	OS           string   `json:"os"`
	OSVersion    string   `json:"os.version,omitempty"`
	OSFeatures   []string `json:"os.features,omitempty"`
	Features     []string `json:"features,omitempty"`
	Variant      string   `json:"variant,omitempty"`
}

// Artifact is the validated parse result. Exactly one of Config+Layers
// (manifest) or Manifests (index) is populated; MediaType echoes the exact
// validated top-level media type. The OCI 1.1 optional top-level members
// (artifactType, subject, annotations) are validated and reflected here for
// OCI manifests and OCI image indexes; Docker types reject them as
// unknown-member (they are not part of the Docker schema-2 / manifest-list
// surface).
type Artifact struct {
	MediaType    string
	Kind         ArtifactKind
	Config       *Descriptor
	Layers       []Descriptor
	Manifests    []Descriptor
	ArtifactType string
	Subject      *Descriptor
	Annotations  map[string]string
}

// References returns exactly the descriptors this artifact depends on —
// manifest config + layers, or index child manifests — in deterministic
// document order, deduplicated by digest. Conflicting duplicates (same digest
// with different size or media type) are rejected at parse time, so a digest
// that appears more than once here is guaranteed to carry identical metadata.
func (a Artifact) References() []Descriptor {
	var src []Descriptor
	switch a.Kind {
	case ArtifactKindIndex:
		src = a.Manifests
	default:
		if a.Config != nil {
			src = append(src, *a.Config)
		}
		src = append(src, a.Layers...)
	}
	seen := make(map[string]struct{}, len(src))
	out := make([]Descriptor, 0, len(src))
	for _, d := range src {
		if _, dup := seen[d.Digest]; dup {
			continue
		}
		seen[d.Digest] = struct{}{}
		out = append(out, d)
	}
	return out
}

// ValidationErrorKind is a stable, mappable class of artifact-validation
// failure. Task 14 maps these to public registry error responses; the kind
// surface must stay small and stable.
type ValidationErrorKind string

const (
	ErrKindBodyTooLarge           ValidationErrorKind = "body_too_large"
	ErrKindMalformedJSON          ValidationErrorKind = "malformed_json"
	ErrKindDuplicateMember        ValidationErrorKind = "duplicate_member"
	ErrKindUnknownMember          ValidationErrorKind = "unknown_member"
	ErrKindWrongType              ValidationErrorKind = "wrong_type"
	ErrKindSchemaVersion          ValidationErrorKind = "schema_version"
	ErrKindMissingField           ValidationErrorKind = "missing_field"
	ErrKindInvalidShape           ValidationErrorKind = "invalid_shape"
	ErrKindInvalidDigest          ValidationErrorKind = "invalid_digest"
	ErrKindInvalidSize            ValidationErrorKind = "invalid_size"
	ErrKindIntegerOverflow        ValidationErrorKind = "integer_overflow"
	ErrKindConflictingDescriptors ValidationErrorKind = "conflicting_descriptors"
	ErrKindInvalidPlatform        ValidationErrorKind = "invalid_platform"
	ErrKindUnsupportedMediaType   ValidationErrorKind = "unsupported_media_type"
	ErrKindMediaTypeMismatch      ValidationErrorKind = "media_type_mismatch"
	ErrKindDigestMismatch         ValidationErrorKind = "digest_mismatch"
	ErrKindSizeMismatch           ValidationErrorKind = "size_mismatch"
	ErrKindMissingReference       ValidationErrorKind = "missing_reference"
	// ErrKindUnsupportedNestedMediaType rejects an index child whose media
	// type is itself an index (OCI image index / Docker manifest list) or any
	// media type that is not a supported single-platform child manifest.
	// Recursive nested indexes are not supported in v1.
	ErrKindUnsupportedNestedMediaType ValidationErrorKind = "unsupported_nested_media_type"
	// ErrKindIndexTooLarge rejects an image index / manifest list whose child
	// descriptor set exceeds one of the shared aggregate bounds
	// (MaxIndexChildDescriptors, MaxUniqueIndexChildManifests, or
	// MaxAggregateIndexChildBytes). The parser enforces it before any upload;
	// the registry verification and control-plane feed signer re-enforce it
	// fail-closed so an oversized index can never drive an unbounded
	// verification read.
	ErrKindIndexTooLarge ValidationErrorKind = "index_too_large"
	// ErrKindUnsupportedPublication is a retained, stable validation kind that
	// was the pre-Task-19 gate rejecting index publication. Task 19 enabled
	// index publication, so this kind is no longer emitted; it is preserved in
	// the stable kind surface for compatibility and not reused for a new
	// meaning.
	ErrKindUnsupportedPublication ValidationErrorKind = "unsupported_artifact_publication"
)

// ValidationError is the typed artifact/publication validation failure. It
// carries ONLY a stable Kind, a fixed/bounded structural Field path, and a
// GENERIC safe message — never untrusted body-member values, media types,
// digests, repo/tag, huge input, or any attacker-controlled detail. Nothing is
// retained as an internal cause and no raw parser/mime/input error is wrapped,
// so the public error is data-free through Error(), %+v, errors.Unwrap/Is/As,
// and every reflection-visible exported member. Kind gives Task 14 a stable
// class for public error mapping.
type ValidationError struct {
	Kind  ValidationErrorKind
	Field string
	Err   error
}

func (e *ValidationError) Error() string {
	if e.Field == "" {
		return fmt.Sprintf("artifact validation: %v", e.Err)
	}
	return fmt.Sprintf("artifact validation: %s: %v", e.Field, e.Err)
}

// Unwrap exposes only the stable generic Err, which is a fixed, data-free
// message. It deliberately cannot reach any attacker-controlled string.
func (e *ValidationError) Unwrap() []error { return []error{e.Err} }

func newValidationError(kind ValidationErrorKind, field string, msg string) *ValidationError {
	return &ValidationError{Kind: kind, Field: field, Err: errors.New(msg)}
}

// errDuplicateMember marks a duplicate object member anywhere in the doc.
// (The other numeric/null sentinels were removed when parsing moved to exact,
// explicit checks that build their own typed errors.)
var errDuplicateMember = errors.New("JSON object contains duplicate members")

// unknownMemberMarker is the fixed structural path placeholder used in place of
// an attacker-controlled unknown JSON member key, so the validation error's
// Field remains a stable, bounded schema path and never echoes the key.
const unknownMemberMarker = "<unknown-member>"

// conflictMarker is the fixed structural Field placeholder used when the same
// (attacker-controlled) digest appears more than once with conflicting size or
// media type. Echoing the digest as a field path would leak untrusted data, so
// the public error carries only this stable marker plus the Kind.
const conflictMarker = "<conflicting-digest>"

// Exact, case-sensitive key vocabularies for each object shape. decoding is
// done through map[string]json.RawMessage, whose keys are the JSON literal
// keys as written — so a case variant ("SchemaVersion", "MediaType") never
// matches and is rejected as an unknown member, and a null value arrives as
// the raw token "null" and is rejected as the wrong type (never silently
// coerced to a zero value).
//
// The ENVELOPE vocabulary is media-type specific: OCI manifests and OCI image
// indexes additionally accept the OCI 1.1 optional top-level members
// artifactType, subject, and annotations, while Docker schema-2 manifests and
// Docker manifest lists must keep rejecting those OCI-only members. Both OCI
// types and both Docker types share one envelope surface each. config /
// layers / manifests are kept KNOWN on every type so the cross-kind SHAPE
// checks (an index must not carry config/layers; a manifest must not carry a
// manifests array) still fire with the dedicated invalid_shape kind instead of
// degrading to a generic unknown-member rejection.
var (
	ociEnvelopeKeys = map[string]struct{}{
		"schemaVersion": {},
		"mediaType":     {},
		"artifactType":  {},
		"config":        {},
		"layers":        {},
		"manifests":     {},
		"subject":       {},
		"annotations":   {},
	}
	dockerEnvelopeKeys = map[string]struct{}{
		"schemaVersion": {},
		"mediaType":     {},
		"config":        {},
		"layers":        {},
		"manifests":     {},
	}
	platformKnownKeys = map[string]struct{}{
		"architecture": {},
		"os":           {},
		"os.version":   {},
		"os.features":  {},
		"features":     {},
		"variant":      {},
	}
)

// descriptorKnownKeys returns the exact descriptor key vocabulary for a
// descriptorPolicy. mediaType / digest / size are always present; platform is
// always present too so a present-but-disallowed platform is rejected with the
// dedicated invalid_shape kind rather than a generic unknown-member; the OCI
// optional members (urls, annotations, data) are added only when the policy
// allows them. Docker descriptors therefore reject annotations/data as
// OCI-only members while OCI descriptors accept them.
func descriptorKnownKeys(policy descriptorPolicy) map[string]struct{} {
	keys := map[string]struct{}{
		"mediaType": {},
		"digest":    {},
		"size":      {},
		"platform":  {},
	}
	if policy.allowURLs {
		keys["urls"] = struct{}{}
	}
	if policy.allowAnnotations {
		keys["annotations"] = struct{}{}
	}
	if policy.allowData {
		keys["data"] = struct{}{}
	}
	return keys
}

func joinPath(base, part string) string {
	if base == "" {
		return part
	}
	return base + "." + part
}

// isNullRaw reports whether raw is exactly the JSON token null.
func isNullRaw(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// decodeObjectMembers decodes a JSON object into its exact-literal, case-
// sensitive member map, rejecting any key outside the known vocabulary as an
// unknown member. Duplicate members have already been rejected globally by
// walkStrict. A non-object value (including null) is wrong type.
func decodeObjectMembers(raw json.RawMessage, field string, known map[string]struct{}) (map[string]json.RawMessage, error) {
	if isNullRaw(raw) {
		return nil, newValidationError(ErrKindWrongType, field, "value must be a JSON object, not null")
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, newValidationError(ErrKindWrongType, field, "value must be a JSON object")
	}
	for k := range m {
		if _, ok := known[k]; !ok {
			// The unknown key name is untrusted attacker content and must NOT
			// become part of the structural path (Field) rendered by Error().
			// Use a fixed literal placeholder so the public error stays
			// data-free while remaining a stable, bounded schema path.
			return nil, newValidationError(ErrKindUnknownMember, joinPath(field, unknownMemberMarker), "unknown JSON member is not accepted")
		}
	}
	return m, nil
}

// decodeRequiredString decodes a REQUIRED string field. A present null or any
// non-string value is the wrong type — null never coalesces to an empty value.
func decodeRequiredString(raw json.RawMessage, field string) (string, error) {
	if isNullRaw(raw) {
		return "", newValidationError(ErrKindWrongType, field, "value must be a string, not null")
	}
	if len(raw) == 0 || raw[0] != '"' {
		return "", newValidationError(ErrKindWrongType, field, "value must be a string")
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", newValidationError(ErrKindWrongType, field, "value must be a string")
	}
	return s, nil
}

// decodeStrictInt decodes an integer field EXACTLY: null, strings, floats,
// and exponents are rejected; values beyond int64 range surface as overflow.
func decodeStrictInt(raw json.RawMessage, field string) (int64, error) {
	if isNullRaw(raw) {
		return 0, newValidationError(ErrKindWrongType, field, "value must be a JSON integer, not null")
	}
	if len(raw) == 0 || raw[0] == '"' {
		return 0, newValidationError(ErrKindWrongType, field, "value must be a JSON integer, not a string")
	}
	v, err := strconv.ParseInt(string(bytes.TrimSpace(raw)), 10, 64)
	if err != nil {
		if errors.Is(err, strconv.ErrRange) {
			return 0, newValidationError(ErrKindIntegerOverflow, field, "integer value exceeds the int64 range")
		}
		return 0, newValidationError(ErrKindWrongType, field, "value must be a JSON integer, not a floating-point number or other value")
	}
	return v, nil
}

// ParseArtifact strictly parses and validates an OCI image manifest, Docker
// schema-2 manifest, OCI image index, or Docker manifest list BEFORE any
// publication write. Every failure is a typed *ValidationError whose message
// never echoes the untrusted body. mediaType is the top-level (Content-Type)
// media type; it must be EXACTLY one of the supported types, and an embedded
// mediaType member, when present, must equal it.
//
// Strictness contract:
//   - body size bounded by MaxArtifactBodyBytes before any JSON decode;
//   - single JSON object document: no duplicate members (nested included),
//     no unknown members, no case-variant keys, no trailing content;
//   - schemaVersion exactly 2 (never 2.0, never "2", never null);
//   - manifests require config and layers; indexes require a present manifests
//     array (which MAY be empty per the OCI and Docker manifest-list specs)
//     and forbid config/layers;
//   - every descriptor requires non-empty bounded mediaType, canonical
//     lowercase "sha256:<64 lowercase hex>" digest, and present non-negative
//     integer size;
//   - platform allowed only on index children, object-shaped, with required
//     architecture/os and bounded strings;
//   - duplicate digests must carry identical size AND media type
//     (conflicts fail, never last-wins);
//   - unsupported or empty top-level media type is rejected.
func ParseArtifact(mediaType string, body []byte) (Artifact, error) {
	if len(body) > MaxArtifactBodyBytes {
		return Artifact{}, newValidationError(ErrKindBodyTooLarge, "",
			fmt.Sprintf("artifact body exceeds the %d-byte bound", MaxArtifactBodyBytes))
	}

	// Duplicate-member and well-formedness check over the whole document,
	// BEFORE any lenient decode could apply last-wins semantics. walkStrict
	// tracks decoded (unescaped) keys, so an escaped spelling that decodes to
	// an already-seen key is a duplicate.
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := walkStrict(dec); err != nil {
		if errors.Is(err, errDuplicateMember) {
			return Artifact{}, newValidationError(ErrKindDuplicateMember, "", err.Error())
		}
		return Artifact{}, newValidationError(ErrKindMalformedJSON, "", "malformed JSON document")
	}

	kind, ok := supportedArtifactMediaTypes[mediaType]
	if !ok {
		return Artifact{}, newValidationError(ErrKindUnsupportedMediaType, "mediaType",
			"unsupported top-level artifact media type")
	}

	// Top level must be exactly one JSON object with no trailing content.
	dec = json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var first json.RawMessage
	if err := dec.Decode(&first); err != nil {
		return Artifact{}, newValidationError(ErrKindMalformedJSON, "", "malformed JSON document")
	}
	if len(first) == 0 || first[0] != '{' {
		return Artifact{}, newValidationError(ErrKindWrongType, "", "top-level value must be a JSON object")
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Artifact{}, newValidationError(ErrKindMalformedJSON, "",
			"exactly one JSON document is allowed (trailing content rejected)")
	}

	// The ENVELOPE key vocabulary is media-type specific: OCI manifests and OCI
	// image indexes accept the OCI 1.1 optional top-level members (artifactType,
	// subject, annotations) while Docker schema-2 manifests and Docker manifest
	// lists must reject those OCI-only members as unknown.
	var envelopeKeys map[string]struct{}
	oci := false
	switch {
	case mediaType == MediaTypeOCIManifest, mediaType == MediaTypeOCIIndex:
		envelopeKeys, oci = ociEnvelopeKeys, true
	case mediaType == MediaTypeDockerManifest, mediaType == MediaTypeDockerManifestList:
		envelopeKeys = dockerEnvelopeKeys
	}
	env, err := decodeObjectMembers(first, "", envelopeKeys)
	if err != nil {
		return Artifact{}, err
	}

	// schemaVersion: required, strict integer, exactly 2.
	svRaw, present := env["schemaVersion"]
	if !present {
		return Artifact{}, newValidationError(ErrKindMissingField, "schemaVersion", "schemaVersion is required")
	}
	sv, err := decodeStrictInt(svRaw, "schemaVersion")
	if err != nil {
		return Artifact{}, err
	}
	if sv != 2 {
		return Artifact{}, newValidationError(ErrKindSchemaVersion, "schemaVersion", "schemaVersion must be exactly 2")
	}

	// Embedded mediaType: optional in presence, but a PRESENT value must be a
	// non-empty string that EXACTLY equals the top-level media type. A present
	// empty string is rejected (never equated with an absent member). Docker
	// schema-2 requires it; when present on any type it must agree.
	if mtRaw, present := env["mediaType"]; present {
		mt, err := decodeRequiredString(mtRaw, "mediaType")
		if err != nil {
			return Artifact{}, err
		}
		if mt == "" {
			return Artifact{}, newValidationError(ErrKindMediaTypeMismatch, "mediaType",
				"a present embedded mediaType must be non-empty")
		}
		if mt != mediaType {
			return Artifact{}, newValidationError(ErrKindMediaTypeMismatch, "mediaType",
				"embedded mediaType disagrees with the top-level media type")
		}
	}

	a := Artifact{MediaType: mediaType, Kind: kind}

	// The OCI 1.1 optional top-level members are validated only for the OCI
	// media types; Docker types reject them as unknown-member because they are
	// not part of the Docker schema-2 / manifest-list envelope (the envelope
	// key map already excludes them).
	if artifactTypeRaw, present := env["artifactType"]; present {
		s, err := decodeRequiredString(artifactTypeRaw, "artifactType")
		if err != nil {
			return Artifact{}, err
		}
		if s == "" {
			return Artifact{}, newValidationError(ErrKindInvalidShape, "artifactType",
				"a present artifactType must be non-empty")
		}
		if len(s) > maxArtifactTypeLen {
			return Artifact{}, newValidationError(ErrKindInvalidShape, "artifactType",
				fmt.Sprintf("artifactType exceeds the %d-byte bound", maxArtifactTypeLen))
		}
		a.ArtifactType = s
	}
	if subjectRaw, present := env["subject"]; present {
		subject, err := decodeDescriptor(subjectRaw, "subject", ociDescriptorPolicy)
		if err != nil {
			return Artifact{}, err
		}
		a.Subject = &subject
	}
	if annotationsRaw, present := env["annotations"]; present {
		ann, err := decodeAnnotations(annotationsRaw, "annotations")
		if err != nil {
			return Artifact{}, err
		}
		a.Annotations = ann
	}

	switch kind {
	case ArtifactKindManifest:
		// Descriptor schemas differ by media type: OCI descriptors accept the
		// OCI 1.1 optional url/annotations/data members; Docker schema-2
		// config descriptors accept none and Docker layer descriptors accept
		// only urls — Docker descriptors never accept annotations/data (OCI-only).
		configPolicy, layerPolicy := ociDescriptorPolicy, ociDescriptorPolicy
		if !oci {
			configPolicy, layerPolicy = dockerManifestConfigPolicy, dockerManifestLayerPolicy
		}
		cRaw, present := env["config"]
		if !present {
			return Artifact{}, newValidationError(ErrKindMissingField, "config", "manifest requires a config descriptor")
		}
		config, err := decodeDescriptor(cRaw, "config", configPolicy)
		if err != nil {
			return Artifact{}, err
		}
		a.Config = &config
		lRaw, present := env["layers"]
		if !present {
			return Artifact{}, newValidationError(ErrKindMissingField, "layers", "manifest requires a layers array")
		}
		layers, err := decodeDescriptorArray(lRaw, "layers", layerPolicy)
		if err != nil {
			return Artifact{}, err
		}
		a.Layers = layers
		if _, present := env["manifests"]; present {
			return Artifact{}, newValidationError(ErrKindInvalidShape, "manifests",
				"an image manifest must not contain a manifests array (index-only shape)")
		}
	case ArtifactKindIndex:
		// Child descriptor schema differs by media type: an OCI image-index
		// child keeps platform OPTIONAL and accepts OCI optional members; a
		// Docker manifest-list child REQUIRES a valid platform object and
		// rejects OCI-only members.
		childPolicy := ociIndexChildPolicy
		if !oci {
			childPolicy = dockerManifestListChildPolicy
		}
		mRaw, present := env["manifests"]
		if !present {
			return Artifact{}, newValidationError(ErrKindMissingField, "manifests", "index requires a manifests array")
		}
		// manifests is REQUIRED to be present but MAY be an empty array: both
		// the OCI image-index spec ("the size of the array MAY be zero") and
		// the Docker manifest-list spec (no non-empty minimum) permit it.
		manifests, err := decodeDescriptorArray(mRaw, "manifests", childPolicy)
		if err != nil {
			return Artifact{}, err
		}
		a.Manifests = manifests
		// Enforce the shared index-size policy BEFORE returning so an
		// oversized child set is rejected at parse — before any upload.
		if err := ValidateIndexAggregateBounds(a.Manifests); err != nil {
			return Artifact{}, err
		}
		if _, present := env["config"]; present {
			return Artifact{}, newValidationError(ErrKindInvalidShape, "config",
				"an index must not contain config (manifest-only shape)")
		}
		if _, present := env["layers"]; present {
			return Artifact{}, newValidationError(ErrKindInvalidShape, "layers",
				"an index must not contain layers (manifest-only shape)")
		}
	}

	if err := rejectConflictingDescriptors(a); err != nil {
		return Artifact{}, err
	}
	return a, nil
}

var supportedArtifactMediaTypes = map[string]ArtifactKind{
	MediaTypeOCIManifest:        ArtifactKindManifest,
	MediaTypeDockerManifest:     ArtifactKindManifest,
	MediaTypeOCIIndex:           ArtifactKindIndex,
	MediaTypeDockerManifestList: ArtifactKindIndex,
}

// decodeDescriptorArray decodes a descriptor array. A present null or any
// non-array is the wrong type; each element must itself be an object
// descriptor (never null).
func decodeDescriptorArray(raw json.RawMessage, field string, policy descriptorPolicy) ([]Descriptor, error) {
	if isNullRaw(raw) {
		return nil, newValidationError(ErrKindWrongType, field, "value must be a JSON array, not null")
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, newValidationError(ErrKindWrongType, field, "value must be a JSON array")
	}
	out := make([]Descriptor, 0, len(items))
	for i, item := range items {
		itemField := fmt.Sprintf("%s[%d]", field, i)
		if isNullRaw(item) || len(item) == 0 || item[0] != '{' {
			return nil, newValidationError(ErrKindWrongType, itemField, "descriptor must be a JSON object, not null")
		}
		d, err := decodeDescriptor(item, itemField, policy)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

// decodeDescriptor applies the strict descriptor contract with exact key and
// type enforcement, using the media-type/position specific descriptorPolicy.
func decodeDescriptor(raw json.RawMessage, field string, policy descriptorPolicy) (Descriptor, error) {
	members, err := decodeObjectMembers(raw, field, descriptorKnownKeys(policy))
	if err != nil {
		return Descriptor{}, err
	}

	mRaw, present := members["mediaType"]
	if !present {
		return Descriptor{}, newValidationError(ErrKindMissingField, joinPath(field, "mediaType"), "descriptor mediaType is required")
	}
	mediaType, err := decodeRequiredString(mRaw, joinPath(field, "mediaType"))
	if err != nil {
		return Descriptor{}, err
	}
	if mediaType == "" {
		return Descriptor{}, newValidationError(ErrKindMissingField, joinPath(field, "mediaType"), "descriptor mediaType must be non-empty")
	}
	if len(mediaType) > maxDescriptorMediaTypeLen {
		return Descriptor{}, newValidationError(ErrKindInvalidShape, joinPath(field, "mediaType"),
			fmt.Sprintf("descriptor mediaType exceeds the %d-byte bound", maxDescriptorMediaTypeLen))
	}

	dRaw, present := members["digest"]
	if !present {
		return Descriptor{}, newValidationError(ErrKindMissingField, joinPath(field, "digest"), "descriptor digest is required")
	}
	digest, err := decodeRequiredString(dRaw, joinPath(field, "digest"))
	if err != nil {
		return Descriptor{}, err
	}
	if !isCanonicalDigest(digest) {
		return Descriptor{}, newValidationError(ErrKindInvalidDigest, joinPath(field, "digest"),
			"digest must be the canonical lowercase form sha256:<64 lowercase hex>")
	}

	sRaw, present := members["size"]
	if !present {
		return Descriptor{}, newValidationError(ErrKindMissingField, joinPath(field, "size"), "descriptor size is required")
	}
	size, err := decodeStrictInt(sRaw, joinPath(field, "size"))
	if err != nil {
		return Descriptor{}, err
	}
	if size < 0 {
		return Descriptor{}, newValidationError(ErrKindInvalidSize, joinPath(field, "size"), "descriptor size must be non-negative")
	}

	d := Descriptor{MediaType: mediaType, Digest: digest, Size: size}

	// Optional OCI descriptor members — urls / annotations / data — are valid
	// only where the policy allows them (OCI descriptors). Each member must be
	// the correct JSON type and bounded.
	if uRaw, present := members["urls"]; present {
		if !policy.allowURLs {
			return Descriptor{}, newValidationError(ErrKindInvalidShape, joinPath(field, "urls"),
				"urls is not accepted on this descriptor")
		}
		urls, err := decodeDescriptorURLs(uRaw, joinPath(field, "urls"))
		if err != nil {
			return Descriptor{}, err
		}
		d.URLs = urls
	}
	if anRaw, present := members["annotations"]; present {
		if !policy.allowAnnotations {
			return Descriptor{}, newValidationError(ErrKindInvalidShape, joinPath(field, "annotations"),
				"annotations is not accepted on this descriptor")
		}
		ann, err := decodeAnnotations(anRaw, joinPath(field, "annotations"))
		if err != nil {
			return Descriptor{}, err
		}
		d.Annotations = ann
	}
	if dataRaw, present := members["data"]; present {
		if !policy.allowData {
			return Descriptor{}, newValidationError(ErrKindInvalidShape, joinPath(field, "data"),
				"data is not accepted on this descriptor")
		}
		data, err := decodeDescriptorData(dataRaw, joinPath(field, "data"), digest, size)
		if err != nil {
			return Descriptor{}, err
		}
		d.Data = data
	}

	pRaw, present := members["platform"]
	if !present {
		if policy.requirePlatform {
			return Descriptor{}, newValidationError(ErrKindMissingField, joinPath(field, "platform"),
				"a Docker manifest-list child requires a valid platform object")
		}
		return d, nil
	}
	if !policy.allowPlatform && !policy.requirePlatform {
		return Descriptor{}, newValidationError(ErrKindInvalidShape, joinPath(field, "platform"),
			"platform is only valid on index child manifests")
	}
	p, err := decodePlatform(pRaw, joinPath(field, "platform"))
	if err != nil {
		return Descriptor{}, err
	}
	d.Platform = p
	return d, nil
}

// decodeAnnotations strictly decodes a bounded string→string annotation map. A
// present null or any non-object is the wrong type; duplicate keys were
// already rejected by the global walkStrict, so this map decode is safe. Every
// key is required non-empty and every key/value length is bounded, and errors
// never echo an annotation key/value (the field path stays a fixed placeholder
// for values; the key is attacker-controlled and never rendered).
func decodeAnnotations(raw json.RawMessage, field string) (map[string]string, error) {
	if isNullRaw(raw) {
		return nil, newValidationError(ErrKindWrongType, field, "value must be a JSON object of string-to-string annotations, not null")
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		// A non-object value (array or scalar) is the wrong type; a present
		// null was already rejected above. An empty object {} is a valid empty
		// annotation map (m is non-nil, len zero).
		return nil, newValidationError(ErrKindWrongType, field, "value must be a JSON object of string-to-string annotations")
	}
	if len(m) > maxAnnotationsCount {
		return nil, newValidationError(ErrKindInvalidShape, field,
			fmt.Sprintf("annotation map exceeds %d entries", maxAnnotationsCount))
	}
	out := make(map[string]string, len(m))
	for k, vRaw := range m {
		if k == "" {
			return nil, newValidationError(ErrKindInvalidShape, field, "an annotation key must be non-empty")
		}
		if len(k) > maxAnnotationKeyLen {
			return nil, newValidationError(ErrKindInvalidShape, field,
				fmt.Sprintf("annotation key exceeds the %d-byte bound", maxAnnotationKeyLen))
		}
		// The value field path uses the fixed unknownMemberMarker placeholder —
		// the annotation KEY is attacker-controlled and must never become part
		// of the public structural path.
		v, err := decodeRequiredString(vRaw, joinPath(field, unknownMemberMarker))
		if err != nil {
			return nil, err
		}
		if len(v) > maxAnnotationValueLen {
			return nil, newValidationError(ErrKindInvalidShape, field,
				fmt.Sprintf("annotation value exceeds the %d-byte bound", maxAnnotationValueLen))
		}
		out[k] = v
	}
	return out, nil
}

// decodeDescriptorURLs strictly decodes a bounded array of non-empty URL
// strings. Errors never echo a URL value.
func decodeDescriptorURLs(raw json.RawMessage, field string) ([]string, error) {
	if isNullRaw(raw) {
		return nil, newValidationError(ErrKindWrongType, field, "value must be a JSON array of URL strings, not null")
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, newValidationError(ErrKindWrongType, field, "value must be a JSON array of URL strings")
	}
	if len(items) > maxDescriptorURLsCount {
		return nil, newValidationError(ErrKindInvalidShape, field,
			fmt.Sprintf("descriptor urls list exceeds %d entries", maxDescriptorURLsCount))
	}
	out := make([]string, 0, len(items))
	for i, item := range items {
		u, err := decodeRequiredString(item, fmt.Sprintf("%s[%d]", field, i))
		if err != nil {
			return nil, err
		}
		if u == "" {
			return nil, newValidationError(ErrKindInvalidShape, fmt.Sprintf("%s[%d]", field, i), "a descriptor url must be non-empty")
		}
		if len(u) > maxDescriptorURLLen {
			return nil, newValidationError(ErrKindInvalidShape, fmt.Sprintf("%s[%d]", field, i),
				fmt.Sprintf("descriptor url exceeds the %d-byte bound", maxDescriptorURLLen))
		}
		out = append(out, u)
	}
	return out, nil
}

// decodeDescriptorData strictly decodes and verifies a descriptor's embedded
// `data` member: it must be a valid base64 (RFC 4648 section 4) string whose
// decoded bytes are byte-identical to the referenced content — i.e. the
// decoded length equals the declared size and the SHA-256 digest of the decoded
// bytes equals the declared digest. This is the OCI "base64/size coherence"
// contract; any mismatch is rejected (fail closed). The decoded bytes are
// bounded by the artifact body bound, so this decode is always bounded.
func decodeDescriptorData(raw json.RawMessage, field string, digest string, size int64) ([]byte, error) {
	s, err := decodeRequiredString(raw, field)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, newValidationError(ErrKindInvalidSize, field,
			"descriptor data must be a valid base64 encoding")
	}
	if int64(len(decoded)) != size {
		return nil, newValidationError(ErrKindInvalidSize, field,
			"descriptor data decodes to a byte length that disagrees with the declared size")
	}
	if ComputeDigest(decoded) != digest {
		return nil, newValidationError(ErrKindInvalidDigest, field,
			"descriptor data does not hash to the declared digest")
	}
	return decoded, nil
}

// decodePlatform strictly decodes and bounds an index-child platform.
func decodePlatform(raw json.RawMessage, field string) (*Platform, error) {
	members, err := decodeObjectMembers(raw, field, platformKnownKeys)
	if err != nil {
		return nil, err
	}

	aRaw, present := members["architecture"]
	if !present {
		return nil, newValidationError(ErrKindInvalidPlatform, joinPath(field, "architecture"), "platform architecture is required")
	}
	architecture, err := decodeRequiredString(aRaw, joinPath(field, "architecture"))
	if err != nil {
		return nil, err
	}
	if architecture == "" {
		return nil, newValidationError(ErrKindInvalidPlatform, joinPath(field, "architecture"), "platform architecture is required")
	}

	oRaw, present := members["os"]
	if !present {
		return nil, newValidationError(ErrKindInvalidPlatform, joinPath(field, "os"), "platform os is required")
	}
	osv, err := decodeRequiredString(oRaw, joinPath(field, "os"))
	if err != nil {
		return nil, err
	}
	if osv == "" {
		return nil, newValidationError(ErrKindInvalidPlatform, joinPath(field, "os"), "platform os is required")
	}

	p := &Platform{Architecture: architecture, OS: osv}

	if vRaw, present := members["os.version"]; present {
		s, err := decodeRequiredString(vRaw, joinPath(field, "os.version"))
		if err != nil {
			return nil, err
		}
		p.OSVersion = s
	}
	if vRaw, present := members["variant"]; present {
		s, err := decodeRequiredString(vRaw, joinPath(field, "variant"))
		if err != nil {
			return nil, err
		}
		p.Variant = s
	}
	if fRaw, present := members["os.features"]; present {
		feats, err := decodePlatformFeatureArray(fRaw, joinPath(field, "os.features"))
		if err != nil {
			return nil, err
		}
		p.OSFeatures = feats
	}
	if fRaw, present := members["features"]; present {
		feats, err := decodePlatformFeatureArray(fRaw, joinPath(field, "features"))
		if err != nil {
			return nil, err
		}
		p.Features = feats
	}

	for name, v := range map[string]string{
		"architecture": p.Architecture,
		"os":           p.OS,
		"os.version":   p.OSVersion,
		"variant":      p.Variant,
	} {
		if len(v) > maxPlatformStringLen {
			return nil, newValidationError(ErrKindInvalidPlatform, joinPath(field, name),
				fmt.Sprintf("platform %s exceeds the %d-byte bound", name, maxPlatformStringLen))
		}
	}
	for i, f := range p.OSFeatures {
		if len(f) > maxPlatformStringLen {
			return nil, newValidationError(ErrKindInvalidPlatform, fmt.Sprintf("%s.os.features[%d]", field, i),
				fmt.Sprintf("platform os.features entry exceeds the %d-byte bound", maxPlatformStringLen))
		}
	}
	for i, f := range p.Features {
		if len(f) > maxPlatformStringLen {
			return nil, newValidationError(ErrKindInvalidPlatform, fmt.Sprintf("%s.features[%d]", field, i),
				fmt.Sprintf("platform features entry exceeds the %d-byte bound", maxPlatformStringLen))
		}
	}
	return p, nil
}

// decodePlatformFeatureArray strictly decodes a bounded platform feature list
// (os.features or features): a non-null array with at most maxPlatformFeatures
// entries, each entry a non-null strict JSON string. Unmarshaling straight
// into []string would silently coerce a null array member to "" (encoding/
// json's string-target null behavior), hiding a null behind an accepted empty
// string, so each member is decoded as a RAW token and required to be a
// non-null string. Errors are data-free (never echo a feature value).
func decodePlatformFeatureArray(raw json.RawMessage, field string) ([]string, error) {
	if isNullRaw(raw) {
		return nil, newValidationError(ErrKindWrongType, field, "value must be a JSON array of strings, not null")
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, newValidationError(ErrKindWrongType, field, "value must be a JSON array of strings")
	}
	if items == nil {
		items = []json.RawMessage{}
	}
	if len(items) > maxPlatformFeatures {
		return nil, newValidationError(ErrKindInvalidPlatform, field,
			fmt.Sprintf("platform feature list exceeds %d entries", maxPlatformFeatures))
	}
	feats := make([]string, 0, len(items))
	for i, item := range items {
		s, err := decodeRequiredString(item, fmt.Sprintf("%s[%d]", field, i))
		if err != nil {
			return nil, err
		}
		feats = append(feats, s)
	}
	return feats, nil
}

// rejectConflictingDescriptors fails the artifact when the same digest
// appears more than once with conflicting size or media type. Identical
// duplicates are allowed and deduplicated by References. The check runs over
// the RAW descriptor set (config + every layer / every child) so a conflict
// cannot hide behind deduplication.
func rejectConflictingDescriptors(a Artifact) error {
	type meta struct {
		size      int64
		mediaType string
	}
	seen := make(map[string]meta)
	check := func(d Descriptor) error {
		if prev, dup := seen[d.Digest]; dup {
			if prev.size != d.Size || prev.mediaType != d.MediaType {
				// Field must stay data-free: the conflicting digest is attacker
				// controlled and must NOT become part of the structural path.
				return newValidationError(ErrKindConflictingDescriptors, conflictMarker,
					"digest is referenced more than once with conflicting size or media type")
			}
			return nil
		}
		seen[d.Digest] = meta{size: d.Size, mediaType: d.MediaType}
		return nil
	}
	if a.Config != nil {
		if err := check(*a.Config); err != nil {
			return err
		}
	}
	for _, d := range a.Layers {
		if err := check(d); err != nil {
			return err
		}
	}
	for _, d := range a.Manifests {
		if err := check(d); err != nil {
			return err
		}
	}
	return nil
}

// ValidateIndexAggregateBounds enforces the shared index-size policy over an
// index / manifest-list child descriptor set (the RAW list, including identical
// duplicates):
//
//   - total declared descriptor count <= MaxIndexChildDescriptors;
//   - distinct child digest count <= MaxUniqueIndexChildManifests;
//   - sum of the DECLARED sizes of the distinct children <=
//     MaxAggregateIndexChildBytes.
//
// It is the SINGLE authority used by the artifact parser (fail-before-upload),
// the registry read-after-write verification, and the control-plane feed
// signer (fail-closed). It is overflow-safe: a single size larger than the
// aggregate bound or an aggregate sum that would exceed the bound fails
// before it can overflow int64. Errors are typed and data-free.
func ValidateIndexAggregateBounds(manifests []Descriptor) error {
	if len(manifests) > MaxIndexChildDescriptors {
		return newValidationError(ErrKindIndexTooLarge, "manifests",
			fmt.Sprintf("index child descriptor count exceeds %d", MaxIndexChildDescriptors))
	}
	if len(manifests) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(manifests))
	var distinct int
	var aggregate int64
	for _, d := range manifests {
		if _, dup := seen[d.Digest]; dup {
			continue
		}
		seen[d.Digest] = struct{}{}
		distinct++
		if d.Size > MaxAggregateIndexChildBytes {
			return newValidationError(ErrKindIndexTooLarge, "manifests",
				fmt.Sprintf("index child aggregate declared bytes exceed %d", MaxAggregateIndexChildBytes))
		}
		if aggregate > MaxAggregateIndexChildBytes-d.Size {
			return newValidationError(ErrKindIndexTooLarge, "manifests",
				fmt.Sprintf("index child aggregate declared bytes exceed %d", MaxAggregateIndexChildBytes))
		}
		aggregate += d.Size
	}
	if distinct > MaxUniqueIndexChildManifests {
		return newValidationError(ErrKindIndexTooLarge, "manifests",
			fmt.Sprintf("index references more than %d distinct child manifests", MaxUniqueIndexChildManifests))
	}
	return nil
}

// UniqueIndexChildren reduces an index / manifest-list child descriptor list to
// the DISTINCT child digests, preserving first-seen document order, after
// enforcing ValidateIndexAggregateBounds. Verification paths iterate this set
// to READ and HASH each distinct child body exactly once — a digest that
// appears multiple times is never read more than once — while still running
// per-descriptor semantic validation over every descriptor (including
// duplicates) in document order.
func UniqueIndexChildren(manifests []Descriptor) ([]Descriptor, error) {
	if err := ValidateIndexAggregateBounds(manifests); err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(manifests))
	out := make([]Descriptor, 0, len(manifests))
	for _, d := range manifests {
		if _, dup := seen[d.Digest]; dup {
			continue
		}
		seen[d.Digest] = struct{}{}
		out = append(out, d)
	}
	return out, nil
}

// walkStrict validates the whole body token stream: well-formed JSON with no
// duplicate object members at any nesting depth. It returns errDuplicateMember
// for duplicates and a plain error for any malformed input.
func walkStrict(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return errors.New("malformed JSON")
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			members := make(map[string]struct{})
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return errors.New("malformed JSON")
				}
				key, ok := keyTok.(string)
				if !ok {
					return errors.New("malformed JSON")
				}
				if _, dup := members[key]; dup {
					return errDuplicateMember
				}
				members[key] = struct{}{}
				if err := walkStrict(dec); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil {
				return errors.New("malformed JSON")
			}
		case '[':
			for dec.More() {
				if err := walkStrict(dec); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil {
				return errors.New("malformed JSON")
			}
		default:
			return errors.New("malformed JSON")
		}
	case string, json.Number, float64, bool, nil:
		return nil
	default:
		return errors.New("malformed JSON")
	}
	return nil
}

// isCanonicalDigest reports whether s is exactly "sha256:" followed by 64
// lowercase hexadecimal characters — the only digest form descriptors accept.
func isCanonicalDigest(s string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	h := s[len(prefix):]
	if len(h) != 64 {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
