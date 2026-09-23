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
	// requires a non-empty manifests array and forbids the manifest-only
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

// untrusted-content sentinels returned by the strict numeric unmarshalers so
// decode failures map to the correct kind instead of a generic wrong-type.
var (
	errIntegerOverflow = errors.New("integer overflow")
	errNotInteger      = errors.New("value must be a JSON integer")
	errNullNotAllowed  = errors.New("null is not allowed")
	// errDuplicateMember marks a duplicate object member anywhere in the doc.
	errDuplicateMember = errors.New("JSON object contains duplicate members")
)

// strictInt64 decodes a JSON integer ONLY: floats, exponents, strings, and
// null are rejected, and values beyond int64 range surface as overflow.
type strictInt64 int64

func (n *strictInt64) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || data[0] == '"' || data[0] == 'n' {
		return errNullNotAllowed
	}
	v, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		if errors.Is(err, strconv.ErrRange) {
			return errIntegerOverflow
		}
		return errNotInteger
	}
	*n = strictInt64(v)
	return nil
}

// requiredInt64 is strictInt64 with presence tracking so a REQUIRED numeric
// field (descriptor size) cannot be silently confused with an absent field.
type requiredInt64 struct {
	set bool
	v   int64
}

func (n *requiredInt64) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || data[0] == '"' || data[0] == 'n' {
		return errNullNotAllowed
	}
	v, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		if errors.Is(err, strconv.ErrRange) {
			return errIntegerOverflow
		}
		return errNotInteger
	}
	n.set = true
	n.v = v
	return nil
}

// rawPlatform is the strict-decode shape for a descriptor platform. Unknown
// platform members are rejected; architecture and os are required, and every
// accepted string/array is bounded.
type rawPlatform struct {
	Architecture string   `json:"architecture"`
	OS           string   `json:"os"`
	OSVersion    string   `json:"os.version"`
	OSFeatures   []string `json:"os.features"`
	Variant      string   `json:"variant"`
}

// rawDescriptor is the strict-decode shape for a descriptor. annotations and
// urls are NOT accepted (unknown-member rejection): v1 records only
// mediaType/digest/size/platform. Platform is kept raw so its presence, null
// value, and content can be validated distinctly.
type rawDescriptor struct {
	MediaType string          `json:"mediaType"`
	Digest    string          `json:"digest"`
	Size      requiredInt64   `json:"size"`
	Platform  json.RawMessage `json:"platform"`
}

// rawEnvelope is the strict-decode shape for the whole artifact document. All
// known fields are captured so shape rules (manifest vs index) can be
// enforced explicitly; unknown top-level members are rejected.
type rawEnvelope struct {
	SchemaVersion strictInt64      `json:"schemaVersion"`
	MediaType     string           `json:"mediaType"`
	Config        *rawDescriptor   `json:"config"`
	Layers        *[]rawDescriptor `json:"layers"`
	Manifests     *[]rawDescriptor `json:"manifests"`
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
//     no unknown members, no trailing content;
//   - schemaVersion exactly 2 (never 2.0, never "2", never null);
//   - manifests require config and layers; indexes require a non-empty
//     manifests array and forbid config/layers;
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
	// BEFORE any lenient decode could apply last-wins semantics.
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
	sdec := json.NewDecoder(bytes.NewReader(first))
	sdec.UseNumber()
	sdec.DisallowUnknownFields()
	var env rawEnvelope
	if err := sdec.Decode(&env); err != nil {
		return Artifact{}, mapDecodeError(err)
	}

	if env.SchemaVersion != 2 {
		return Artifact{}, newValidationError(ErrKindSchemaVersion, "schemaVersion",
			"schemaVersion must be exactly 2")
	}
	if env.MediaType != "" && env.MediaType != mediaType {
		return Artifact{}, newValidationError(ErrKindMediaTypeMismatch, "mediaType",
			"embedded mediaType disagrees with the top-level media type")
	}

	a := Artifact{MediaType: mediaType, Kind: kind}
	switch kind {
	case ArtifactKindManifest:
		if env.Config == nil {
			return Artifact{}, newValidationError(ErrKindMissingField, "config",
				"manifest requires a config descriptor")
		}
		if env.Layers == nil {
			return Artifact{}, newValidationError(ErrKindMissingField, "layers",
				"manifest requires a layers array")
		}
		if env.Manifests != nil {
			return Artifact{}, newValidationError(ErrKindInvalidShape, "manifests",
				"an image manifest must not contain a manifests array (index-only shape)")
		}
		config, err := validateDescriptor(env.Config, "config", false)
		if err != nil {
			return Artifact{}, err
		}
		a.Config = &config
		a.Layers = make([]Descriptor, 0, len(*env.Layers))
		for i := range *env.Layers {
			d, err := validateDescriptor(&(*env.Layers)[i], fmt.Sprintf("layers[%d]", i), false)
			if err != nil {
				return Artifact{}, err
			}
			a.Layers = append(a.Layers, d)
		}
	case ArtifactKindIndex:
		if env.Manifests == nil {
			return Artifact{}, newValidationError(ErrKindMissingField, "manifests",
				"index requires a manifests array")
		}
		if len(*env.Manifests) == 0 {
			return Artifact{}, newValidationError(ErrKindInvalidShape, "manifests",
				"index must reference at least one child manifest")
		}
		if env.Config != nil || env.Layers != nil {
			return Artifact{}, newValidationError(ErrKindInvalidShape, "",
				"an index must not contain config or layers (manifest-only shape)")
		}
		a.Manifests = make([]Descriptor, 0, len(*env.Manifests))
		for i := range *env.Manifests {
			d, err := validateDescriptor(&(*env.Manifests)[i], fmt.Sprintf("manifests[%d]", i), true)
			if err != nil {
				return Artifact{}, err
			}
			a.Manifests = append(a.Manifests, d)
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

// validateDescriptor applies the strict descriptor contract.
func validateDescriptor(raw *rawDescriptor, field string, allowPlatform bool) (Descriptor, error) {
	if raw == nil {
		return Descriptor{}, newValidationError(ErrKindMissingField, field,
			"descriptor is required")
	}
	if raw.MediaType == "" {
		return Descriptor{}, newValidationError(ErrKindMissingField, field+".mediaType",
			"descriptor mediaType must be non-empty")
	}
	if len(raw.MediaType) > maxDescriptorMediaTypeLen {
		return Descriptor{}, newValidationError(ErrKindInvalidShape, field+".mediaType",
			fmt.Sprintf("descriptor mediaType exceeds the %d-byte bound", maxDescriptorMediaTypeLen))
	}
	if !isCanonicalDigest(raw.Digest) {
		return Descriptor{}, newValidationError(ErrKindInvalidDigest, field+".digest",
			"digest must be the canonical lowercase form sha256:<64 lowercase hex>")
	}
	if !raw.Size.set {
		return Descriptor{}, newValidationError(ErrKindMissingField, field+".size",
			"descriptor size is required")
	}
	if raw.Size.v < 0 {
		return Descriptor{}, newValidationError(ErrKindInvalidSize, field+".size",
			"descriptor size must be non-negative")
	}

	d := Descriptor{
		MediaType: raw.MediaType,
		Digest:    raw.Digest,
		Size:      raw.Size.v,
	}
	if len(raw.Platform) == 0 {
		return d, nil
	}
	if !allowPlatform {
		return Descriptor{}, newValidationError(ErrKindInvalidShape, field+".platform",
			"platform is only valid on index child manifests")
	}
	p, err := decodePlatform(raw.Platform, field+".platform")
	if err != nil {
		return Descriptor{}, err
	}
	d.Platform = p
	return d, nil
}

// decodePlatform strictly decodes and bounds an index-child platform.
func decodePlatform(raw json.RawMessage, field string) (*Platform, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, newValidationError(ErrKindInvalidPlatform, field,
			"platform must be an object, not null")
	}
	pd := json.NewDecoder(bytes.NewReader(raw))
	pd.UseNumber()
	pd.DisallowUnknownFields()
	var rp rawPlatform
	if err := pd.Decode(&rp); err != nil {
		return nil, newValidationError(ErrKindInvalidPlatform, field,
			"platform must be an object with only known members")
	}
	if err := pd.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, newValidationError(ErrKindInvalidPlatform, field,
			"platform must be a single object value")
	}
	if rp.Architecture == "" {
		return nil, newValidationError(ErrKindInvalidPlatform, field+".architecture",
			"platform architecture is required")
	}
	if rp.OS == "" {
		return nil, newValidationError(ErrKindInvalidPlatform, field+".os",
			"platform os is required")
	}
	for name, v := range map[string]string{
		"architecture": rp.Architecture,
		"os":           rp.OS,
		"os.version":   rp.OSVersion,
		"variant":      rp.Variant,
	} {
		if len(v) > maxPlatformStringLen {
			return nil, newValidationError(ErrKindInvalidPlatform, field+"."+name,
				fmt.Sprintf("platform %s exceeds the %d-byte bound", name, maxPlatformStringLen))
		}
	}
	if len(rp.OSFeatures) > maxPlatformFeatures {
		return nil, newValidationError(ErrKindInvalidPlatform, field+".os.features",
			fmt.Sprintf("platform os.features exceeds %d entries", maxPlatformFeatures))
	}
	for i, f := range rp.OSFeatures {
		if len(f) > maxPlatformStringLen {
			return nil, newValidationError(ErrKindInvalidPlatform, fmt.Sprintf("%s.os.features[%d]", field, i),
				fmt.Sprintf("platform os.features entry exceeds the %d-byte bound", maxPlatformStringLen))
		}
	}
	return &Platform{
		Architecture: rp.Architecture,
		OS:           rp.OS,
		OSVersion:    rp.OSVersion,
		OSFeatures:   rp.OSFeatures,
		Variant:      rp.Variant,
	}, nil
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

// mapDecodeError converts a strict-decode failure into the correct typed
// kind, preserving integer-overflow and unknown-member precision.
func mapDecodeError(err error) error {
	switch {
	case errors.Is(err, errIntegerOverflow):
		return newValidationError(ErrKindIntegerOverflow, "",
			"integer value exceeds the int64 range")
	case errors.Is(err, errNotInteger), errors.Is(err, errNullNotAllowed):
		return newValidationError(ErrKindWrongType, "",
			"numeric fields must be JSON integers, not strings, floats, or null")
	case strings.Contains(err.Error(), "unknown field"):
		return newValidationError(ErrKindUnknownMember, "",
			"unknown JSON member is not accepted")
	default:
		return newValidationError(ErrKindWrongType, "",
			"field has the wrong JSON type")
	}
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
