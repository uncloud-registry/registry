package publish

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestValidateMediaTypeSyntax pins the strict RFC 6838 media-type validator:
// every positive vendor/tree/suffix/parameter form the OCI spec permits is
// accepted, and every malformed shape is rejected — without ever echoing the
// rejected value in the error message.
func TestValidateMediaTypeSyntax(t *testing.T) {
	positive := []string{
		MediaTypeOCIManifest,              // vendor tree
		MediaTypeOCIIndex,                 // vendor tree nested with +json suffix
		MediaTypeDockerManifest,           // docker vendor tree
		"application/vnd.example.sbom.v1", // vendor tree with suffix
		"application/vnd.example+type",
		"image/svg+xml",                       // tree suffix
		"text/plain; charset=utf-8",           // parameter
		"application/json; charset=\"utf-8\"", // quoted parameter value
		"application/octet-stream",
		"Application/JSON", // case-insensitive types are valid
	}
	for _, s := range positive {
		t.Run("accept:"+s, func(t *testing.T) {
			if err := ValidateMediaTypeSyntax(s); err != nil {
				t.Fatalf("ValidateMediaTypeSyntax(%q) = %v, want nil", s, err)
			}
		})
	}

	negative := []string{
		"",
		"json",
		"/json",
		"application/",
		"application/json/",
		"a/b/c",
		"a b/c",
		"a/\tb",
		" application/json",
		"application/json ",
		"application/\njson",
		"application/json; charset",
		"application/json; =x",
		"application/json\x00",
	}
	for _, s := range negative {
		t.Run("reject", func(t *testing.T) {
			if err := ValidateMediaTypeSyntax(s); err == nil {
				t.Fatalf("ValidateMediaTypeSyntax(%q) accepted a malformed media type", s)
			}
		})
	}
}

// TestValidateMediaTypeSyntaxDataFree proves the validator's error never
// contains the rejected value.
func TestValidateMediaTypeSyntaxDataFree(t *testing.T) {
	const evil = "application/evil<>&\"'`\x01"
	err := ValidateMediaTypeSyntax(evil)
	if err == nil {
		t.Fatal("malformed value must be rejected")
	}
	if strings.Contains(err.Error(), "evil") {
		t.Fatalf("media-type error leaks the rejected value: %q", err.Error())
	}
}

// TestValidateDescriptorURI pins the RFC 3986 URI-reference validator: absolute
// URIs AND valid relative references (path, ../, /abs, //host, opaque schemes)
// are accepted; malformed percent escapes, whitespace/control bytes, and bad
// http(s) authorities are rejected — without echoing the rejected value.
func TestValidateDescriptorURI(t *testing.T) {
	positive := []string{
		"https://example.com/v1/artifact", // absolute https
		"http://example.com:8080/x",       // absolute http
		"ftp://example.com/file",          // absolute non-http scheme
		"urn:isbn:0451450523",             // opaque absolute scheme
		"mailto:a@b.com",
		"relative/path", // relative reference
		"../up/resource",
		"/abs/path",
		"//host.network/path", // network-path reference
		"file.txt",
		"subdir?query=1",
		"#fragment",
	}
	for _, s := range positive {
		t.Run("accept:"+s, func(t *testing.T) {
			if err := ValidateDescriptorURI(s); err != nil {
				t.Fatalf("ValidateDescriptorURI(%q) = %v, want nil", s, err)
			}
		})
	}

	negative := []string{
		"",
		"http://host/a b",   // literal space
		"http://host/\t",    // literal tab
		"http://host/a\x00", // control
		"http://host/a\x7f", // delete
		"http://host/a%zz",  // malformed percent escape
		"http://host/a%",    // truncated escape
		"http:///nohost",    // empty http authority
		"https://",          // empty https authority
		"1abc:not-a-scheme", // malformed scheme start
		"a b",               // whitespace in relative ref
	}
	for _, s := range negative {
		t.Run("reject", func(t *testing.T) {
			if err := ValidateDescriptorURI(s); err == nil {
				t.Fatalf("ValidateDescriptorURI(%q) accepted a malformed URI", s)
			}
		})
	}
}

// TestValidateDescriptorURIDataFree proves the URI validator's error never
// contains the rejected value.
func TestValidateDescriptorURIDataFree(t *testing.T) {
	const evil = "https://evil.example/path with %zz control\x00"
	err := ValidateDescriptorURI(evil)
	if err == nil {
		t.Fatal("malformed URI must be rejected")
	}
	for _, bad := range []string{"evil", "%zz", "\x00"} {
		if strings.Contains(err.Error(), bad) {
			t.Fatalf("URI error leaks the rejected value %q: %q", bad, err.Error())
		}
	}
}

// ociArtifactTypeManifest is an OCI manifest whose config descriptor carries
// the OCI 1.1 descriptor artifactType plus a valid urls member, and whose layer
// descriptor carries a descriptor artifactType.
func ociArtifactTypeManifest() string {
	return fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q,"artifactType":%q,"urls":["https://example.com/cfg"]},"layers":[{"mediaType":%q,"size":1024,"digest":%q,"artifactType":%q,"urls":["relative/layer.tar"]}]}`,
		ociConfigMT, dig('c'), "application/vnd.example.config.sbom", ociLayerMT, dig('a'), "application/vnd.example.layer.type")
}

// TestParseArtifactDockerRequiresEmbeddedMediaType proves the adjacent-minor
// fix: a Docker schema-2 manifest AND a Docker manifest list REQUIRE the
// embedded top-level mediaType (Docker Distribution's manifest-v2-2 schema
// requires it), while an OCI manifest keeps it optional.
func TestParseArtifactDockerRequiresEmbeddedMediaType(t *testing.T) {
	// Docker schema-2 manifest with NO embedded mediaType → missing field.
	dockerManNoMT := fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[]}`,
		dockerConfigMT, dig('c'))
	_, err := ParseArtifact(dockerManMT, []byte(dockerManNoMT))
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Kind != ErrKindMissingField {
		t.Fatalf("Docker manifest without embedded mediaType must be rejected as missing_field, got %v", err)
	}

	// Docker manifest list with NO embedded mediaType → missing field.
	dockerListNoMT := fmt.Sprintf(`{"schemaVersion":2,"manifests":[]}`)
	_, err = ParseArtifact(dockerListMT, []byte(dockerListNoMT))
	if !errors.As(err, &ve) || ve.Kind != ErrKindMissingField {
		t.Fatalf("Docker manifest list without embedded mediaType must be rejected as missing_field, got %v", err)
	}

	// Same Docker manifest with the matching embedded mediaType → accepted.
	dockerManWithMT := fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[]}`,
		dockerManMT, dockerConfigMT, dig('c'))
	if _, err := ParseArtifact(dockerManMT, []byte(dockerManWithMT)); err != nil {
		t.Fatalf("Docker manifest with matching embedded mediaType must be accepted: %v", err)
	}

	// OCI manifest WITHOUT an embedded mediaType stays valid (optional).
	ociManNoMT := fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[]}`,
		ociConfigMT, dig('c'))
	if _, err := ParseArtifact(ociManifestMT, []byte(ociManNoMT)); err != nil {
		t.Fatalf("OCI manifest without embedded mediaType must remain optional: %v", err)
	}
}

// TestParseArtifactDescriptorArtifactTypeAccepted proves an OCI manifest whose
// config and layer descriptors carry artifactType AND valid urls accepts and
// PRESERVES the parsed descriptor artifactType/urls for introspection while the
// exact source bytes are retained for storage/pull.
func TestParseArtifactDescriptorArtifactTypeAccepted(t *testing.T) {
	body := ociArtifactTypeManifest()
	a, err := ParseArtifact(ociManifestMT, []byte(body))
	if err != nil {
		t.Fatalf("OCI manifest with descriptor artifactType must parse: %v", err)
	}
	if a.Config == nil || a.Config.ArtifactType != "application/vnd.example.config.sbom" {
		t.Fatalf("config descriptor artifactType not preserved: %+v", a.Config)
	}
	if a.Config == nil || len(a.Config.URLs) != 1 || a.Config.URLs[0] != "https://example.com/cfg" {
		t.Fatalf("config descriptor urls not preserved: %+v", a.Config)
	}
	if len(a.Layers) != 1 || a.Layers[0].ArtifactType != "application/vnd.example.layer.type" {
		t.Fatalf("layer descriptor artifactType not preserved: %+v", a.Layers)
	}
	if len(a.Layers[0].URLs) != 1 || a.Layers[0].URLs[0] != "relative/layer.tar" {
		t.Fatalf("layer descriptor relative urls not preserved: %+v", a.Layers[0])
	}
}

// TestParseArtifactIndexChildArtifactTypeAccepted proves an OCI image-index
// CHILD accepts and preserves the descriptor artifactType (OCI descriptor
// positions include index children).
func TestParseArtifactIndexChildArtifactTypeAccepted(t *testing.T) {
	body := fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":512,"digest":%q,"artifactType":%q,"urls":["https://example.com/m"]}]}`,
		ociIndexMT, ociManifestMT, dig('b'), "application/vnd.example.sbom.v1")
	a, err := ParseArtifact(ociIndexMT, []byte(body))
	if err != nil {
		t.Fatalf("OCI index child with artifactType must parse: %v", err)
	}
	if len(a.Manifests) != 1 || a.Manifests[0].ArtifactType != "application/vnd.example.sbom.v1" {
		t.Fatalf("index child artifactType not preserved: %+v", a.Manifests)
	}
	if len(a.Manifests[0].URLs) != 1 || a.Manifests[0].URLs[0] != "https://example.com/m" {
		t.Fatalf("index child urls not preserved: %+v", a.Manifests[0])
	}
}

// TestParseArtifactSubjectDescriptorArtifactTypeAccepted proves the top-level
// subject descriptor (also an OCI descriptor position) accepts and preserves
// artifactType.
func TestParseArtifactSubjectDescriptorArtifactTypeAccepted(t *testing.T) {
	body := fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"subject":{"mediaType":%q,"size":17,"digest":%q,"artifactType":%q},"manifests":[]}`,
		ociIndexMT, ociManifestMT, dig('d'), "application/vnd.example.subject.type")
	a, err := ParseArtifact(ociIndexMT, []byte(body))
	if err != nil {
		t.Fatalf("OCI index subject with artifactType must parse: %v", err)
	}
	if a.Subject == nil || a.Subject.ArtifactType != "application/vnd.example.subject.type" {
		t.Fatalf("subject descriptor artifactType not preserved: %+v", a.Subject)
	}
}

// TestParseArtifactDescriptorArtifactTypeRejectedOnDocker proves Docker
// descriptors reject the OCI-only artifactType as an unknown/shape member.
func TestParseArtifactDescriptorArtifactTypeRejectedOnDocker(t *testing.T) {
	cfg := fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"config":{"mediaType":%q,"size":24,"digest":%q,"artifactType":%q},"layers":[]}`,
		dockerManMT, dockerConfigMT, dig('c'), "application/vnd.example.type")
	_, err := ParseArtifact(dockerManMT, []byte(cfg))
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("Docker config artifactType must be rejected as a validation error, got %T: %v", err, err)
	}
	if ve.Kind != ErrKindInvalidShape && ve.Kind != ErrKindUnknownMember {
		t.Fatalf("Docker descriptor artifactType must be invalid_shape/unknown_member, got %s", ve.Kind)
	}
}

// TestParseArtifactDescriptorArtifactTypeInvalid proves a malformed descriptor
// artifactType is rejected with the invalid-media-type kind and a data-free
// message.
func TestParseArtifactDescriptorArtifactTypeInvalid(t *testing.T) {
	body := fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q,"artifactType":"not a media type"},"layers":[]}`,
		ociConfigMT, dig('c'))
	_, err := ParseArtifact(ociManifestMT, []byte(body))
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("malformed descriptor artifactType must be a validation error, got %T: %v", err, err)
	}
	if ve.Kind != ErrKindInvalidMediaType {
		t.Fatalf("expected invalid_media_type, got %s", ve.Kind)
	}
	if strings.Contains(err.Error(), "not a media type") {
		t.Fatalf("validation error leaks the rejected artifactType: %q", err.Error())
	}
}

// TestParseArtifactDescriptorArtifactTypeEmptyRejected proves a PRESENT empty
// descriptor artifactType is rejected (never treated as absent).
func TestParseArtifactDescriptorArtifactTypeEmptyRejected(t *testing.T) {
	body := fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q,"artifactType":""},"layers":[]}`,
		ociConfigMT, dig('c'))
	if _, err := ParseArtifact(ociManifestMT, []byte(body)); err == nil {
		t.Fatal("present-empty descriptor artifactType must be rejected")
	}
}

// TestParseArtifactDescriptorMediaTypeInvalid proves a descriptor mediaType
// that is not a valid RFC 6838 media type is rejected before publication.
func TestParseArtifactDescriptorMediaTypeInvalid(t *testing.T) {
	body := fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":"application/octet stream","size":24,"digest":%q},"layers":[]}`,
		dig('c'))
	_, err := ParseArtifact(ociManifestMT, []byte(body))
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("malformed descriptor mediaType must be a validation error, got %T: %v", err, err)
	}
	if ve.Kind != ErrKindInvalidMediaType {
		t.Fatalf("expected invalid_media_type, got %s", ve.Kind)
	}
	if strings.Contains(err.Error(), "octet stream") {
		t.Fatalf("validation error leaks the rejected mediaType: %q", err.Error())
	}
}

// TestParseArtifactDescriptorURLInvalid proves a descriptor url that is not a
// valid RFC 3986 URI reference is rejected before publication.
func TestParseArtifactDescriptorURLInvalid(t *testing.T) {
	body := fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q,"urls":["https://host/a b"]},"layers":[]}`,
		ociConfigMT, dig('c'))
	_, err := ParseArtifact(ociManifestMT, []byte(body))
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("malformed descriptor url must be a validation error, got %T: %v", err, err)
	}
	if ve.Kind != ErrKindInvalidURI {
		t.Fatalf("expected invalid_uri, got %s", ve.Kind)
	}
}

// TestParseArtifactTopLevelArtifactTypeInvalid proves a top-level OCI
// artifactType that is not a valid RFC 6838 media type is rejected with the
// invalid-media-type kind and a data-free message.
func TestParseArtifactTopLevelArtifactTypeInvalid(t *testing.T) {
	body := fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"artifactType":"bad type","config":{"mediaType":%q,"size":24,"digest":%q},"layers":[]}`,
		ociManifestMT, ociConfigMT, dig('c'))
	_, err := ParseArtifact(ociManifestMT, []byte(body))
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("malformed top-level artifactType must be a validation error, got %T: %v", err, err)
	}
	if ve.Kind != ErrKindInvalidMediaType {
		t.Fatalf("expected invalid_media_type, got %s", ve.Kind)
	}
	if strings.Contains(err.Error(), "bad type") {
		t.Fatalf("validation error leaks the rejected artifactType: %q", err.Error())
	}
}
