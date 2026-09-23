package publish

import (
	"bytes"
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

// Metadata string bounds for accepted descriptor/platform fields. annotations
// and urls are NOT accepted in v1 descriptors (unknown-member rejection), so
// only mediaType and platform strings need bounds here.
const (
	maxDescriptorMediaTypeLen = 4096
	maxPlatformStringLen      = 1024
	maxPlatformFeatures       = 64
)

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
// and (index children only) an optional platform.
type Descriptor struct {
	MediaType string    `json:"mediaType"`
	Digest    string    `json:"digest"`
	Size      int64     `json:"size"`
	Platform  *Platform `json:"platform,omitempty"`
}

// Platform is a validated index-child platform. architecture and os are
// required; every string is bounded.
type Platform struct {
	Architecture string   `json:"architecture"`
	OS           string   `json:"os"`
	OSVersion    string   `json:"os.version,omitempty"`
	OSFeatures   []string `json:"os.features,omitempty"`
	Variant      string   `json:"variant,omitempty"`
}

// Artifact is the validated parse result. Exactly one of Config+Layers
// (manifest) or Manifests (index) is populated; MediaType echoes the exact
// validated top-level media type.
type Artifact struct {
	MediaType string
	Kind      ArtifactKind
	Config    *Descriptor
	Layers    []Descriptor
	Manifests []Descriptor
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
)

// ValidationError is the typed artifact/publication validation failure. Its
// message carries only a structural field path and a generic reason — never
// the untrusted body or secrets — while Kind gives Task 14 a stable class for
// public error mapping.
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

func (e *ValidationError) Unwrap() error { return e.Err }

func newValidationError(kind ValidationErrorKind, field string, msg string) *ValidationError {
	return &ValidationError{Kind: kind, Field: field, Err: errors.New(msg)}
}

// errDuplicateMember marks a duplicate object member anywhere in the doc.
// (The other numeric/null sentinels were removed when parsing moved to exact,
// explicit checks that build their own typed errors.)
var errDuplicateMember = errors.New("JSON object contains duplicate members")

// Exact, case-sensitive key vocabularies for each object shape. decoding is
// done through map[string]json.RawMessage, whose keys are the JSON literal
// keys as written — so a case variant ("SchemaVersion", "MediaType") never
// matches and is rejected as an unknown member, and a null value arrives as
// the raw token "null" and is rejected as the wrong type (never silently
// coerced to a zero value).
var (
	envelopeKnownKeys = map[string]struct{}{
		"schemaVersion": {},
		"mediaType":     {},
		"config":        {},
		"layers":        {},
		"manifests":     {},
	}
	descriptorKnownKeys = map[string]struct{}{
		"mediaType": {},
		"digest":    {},
		"size":      {},
		"platform":  {},
	}
	platformKnownKeys = map[string]struct{}{
		"architecture": {},
		"os":           {},
		"os.version":   {},
		"os.features":  {},
		"variant":      {},
	}
)

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
			return nil, newValidationError(ErrKindUnknownMember, joinPath(field, k), "unknown JSON member is not accepted")
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

	env, err := decodeObjectMembers(first, "", envelopeKnownKeys)
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

	// Embedded mediaType: optional, but present-null or non-string is wrong
	// type, and a non-empty value must agree with the top-level media type.
	if mtRaw, present := env["mediaType"]; present {
		mt, err := decodeRequiredString(mtRaw, "mediaType")
		if err != nil {
			return Artifact{}, err
		}
		if mt != "" && mt != mediaType {
			return Artifact{}, newValidationError(ErrKindMediaTypeMismatch, "mediaType",
				"embedded mediaType disagrees with the top-level media type")
		}
	}

	a := Artifact{MediaType: mediaType, Kind: kind}
	switch kind {
	case ArtifactKindManifest:
		cRaw, present := env["config"]
		if !present {
			return Artifact{}, newValidationError(ErrKindMissingField, "config", "manifest requires a config descriptor")
		}
		config, err := decodeDescriptor(cRaw, "config", false)
		if err != nil {
			return Artifact{}, err
		}
		a.Config = &config
		lRaw, present := env["layers"]
		if !present {
			return Artifact{}, newValidationError(ErrKindMissingField, "layers", "manifest requires a layers array")
		}
		layers, err := decodeDescriptorArray(lRaw, "layers", false)
		if err != nil {
			return Artifact{}, err
		}
		a.Layers = layers
		if _, present := env["manifests"]; present {
			return Artifact{}, newValidationError(ErrKindInvalidShape, "manifests",
				"an image manifest must not contain a manifests array (index-only shape)")
		}
	case ArtifactKindIndex:
		mRaw, present := env["manifests"]
		if !present {
			return Artifact{}, newValidationError(ErrKindMissingField, "manifests", "index requires a manifests array")
		}
		// manifests is REQUIRED to be present but MAY be an empty array: both
		// the OCI image-index spec ("the size of the array MAY be zero") and
		// the Docker manifest-list spec (no non-empty minimum) permit it.
		manifests, err := decodeDescriptorArray(mRaw, "manifests", true)
		if err != nil {
			return Artifact{}, err
		}
		a.Manifests = manifests
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
func decodeDescriptorArray(raw json.RawMessage, field string, allowPlatform bool) ([]Descriptor, error) {
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
		d, err := decodeDescriptor(item, itemField, allowPlatform)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

// decodeDescriptor applies the strict descriptor contract with exact key and
// type enforcement.
func decodeDescriptor(raw json.RawMessage, field string, allowPlatform bool) (Descriptor, error) {
	members, err := decodeObjectMembers(raw, field, descriptorKnownKeys)
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

	pRaw, present := members["platform"]
	if !present {
		return d, nil
	}
	if !allowPlatform {
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
		if isNullRaw(fRaw) {
			return nil, newValidationError(ErrKindWrongType, joinPath(field, "os.features"), "value must be a JSON array of strings, not null")
		}
		var feats []string
		if err := json.Unmarshal(fRaw, &feats); err != nil {
			return nil, newValidationError(ErrKindWrongType, joinPath(field, "os.features"), "value must be a JSON array of strings")
		}
		if feats == nil {
			feats = []string{}
		}
		if len(feats) > maxPlatformFeatures {
			return nil, newValidationError(ErrKindInvalidPlatform, joinPath(field, "os.features"),
				fmt.Sprintf("platform os.features exceeds %d entries", maxPlatformFeatures))
		}
		p.OSFeatures = feats
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
	return p, nil
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
				return newValidationError(ErrKindConflictingDescriptors, d.Digest,
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
