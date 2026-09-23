package publish

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/uncloud-registry/registry/internal/spec"
)

// dig returns a canonical sha256 digest whose 64 hex chars are all seed.
func dig(seed byte) string {
	return "sha256:" + strings.Repeat(string(seed), 64)
}

const (
	ociConfigMT    = "application/vnd.oci.image.config.v1+json"
	ociLayerMT     = "application/vnd.oci.image.layer.v1.tar+gzip"
	ociManifestMT  = "application/vnd.oci.image.manifest.v1+json"
	ociIndexMT     = "application/vnd.oci.image.index.v1+json"
	dockerManMT    = "application/vnd.docker.distribution.manifest.v2+json"
	dockerListMT   = "application/vnd.docker.distribution.manifest.list.v2+json"
	dockerConfigMT = "application/vnd.docker.container.image.v1+json"
	dockerLayerMT  = "application/vnd.docker.image.rootfs.diff.tar.gzip"
)

// ociManifest is the canonical valid OCI image manifest used as the base of
// most mutation cases: config descriptor + a single layer descriptor.
func ociManifestBody() string {
	return fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[{"mediaType":%q,"size":1024,"digest":%q}]}`,
		ociConfigMT, dig('c'), ociLayerMT, dig('a'))
}

// ociIndex is the canonical valid OCI image index with two children.
func ociIndex() string {
	return fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":512,"digest":%q,"platform":{"architecture":"amd64","os":"linux"}},{"mediaType":%q,"size":513,"digest":%q,"platform":{"architecture":"arm64","os":"linux","variant":"v8"}}]}`,
		ociIndexMT, ociManifestMT, dig('b'), ociManifestMT, dig('d'))
}

type parseCase struct {
	name        string
	mediaType   string
	body        string
	wantKind    ArtifactKind
	wantErr     bool
	wantErrKind ValidationErrorKind
	check       func(t *testing.T, a Artifact)
}

func TestParseArtifact(t *testing.T) {
	cases := []parseCase{
		{
			name:      "oci manifest valid with embedded media type",
			mediaType: ociManifestMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[{"mediaType":%q,"size":1024,"digest":%q}]}`,
				ociManifestMT, ociConfigMT, dig('c'), ociLayerMT, dig('a')),
			wantKind: ArtifactKindManifest,
			check: func(t *testing.T, a Artifact) {
				if a.Config == nil || a.Config.Digest != dig('c') || a.Config.Size != 24 || a.Config.MediaType != ociConfigMT {
					t.Fatalf("config mismatch: %+v", a.Config)
				}
				if len(a.Layers) != 1 || a.Layers[0].Digest != dig('a') || a.Layers[0].Size != 1024 {
					t.Fatalf("layers mismatch: %+v", a.Layers)
				}
			},
		},
		{
			name:      "oci manifest valid without embedded media type and empty layers",
			mediaType: ociManifestMT,
			body:      fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[]}`, ociConfigMT, dig('c')),
			wantKind:  ArtifactKindManifest,
		},
		{
			name:      "docker schema2 manifest valid with embedded media type",
			mediaType: dockerManMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[{"mediaType":%q,"size":1024,"digest":%q}]}`,
				dockerManMT, dockerConfigMT, dig('c'), dockerLayerMT, dig('a')),
			wantKind: ArtifactKindManifest,
		},
		{
			name:      "oci index valid two children",
			mediaType: ociIndexMT,
			body:      ociIndex(),
			wantKind:  ArtifactKindIndex,
			check: func(t *testing.T, a Artifact) {
				if len(a.Manifests) != 2 {
					t.Fatalf("expected 2 children, got %+v", a.Manifests)
				}
				if a.Manifests[1].Platform == nil || a.Manifests[1].Platform.Architecture != "arm64" || a.Manifests[1].Platform.Variant != "v8" {
					t.Fatalf("child platform mismatch: %+v", a.Manifests[1].Platform)
				}
			},
		},
		{
			name:      "docker manifest list valid",
			mediaType: dockerListMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":500,"digest":%q,"platform":{"architecture":"arm64","os":"linux"}}]}`,
				dockerListMT, dockerManMT, dig('e')),
			wantKind: ArtifactKindIndex,
		},
		{
			name:      "duplicate identical layer digest allowed and deduplicated",
			mediaType: ociManifestMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[{"mediaType":%q,"size":1024,"digest":%q},{"mediaType":%q,"size":1024,"digest":%q}]}`,
				ociConfigMT, dig('c'), ociLayerMT, dig('a'), ociLayerMT, dig('a')),
			wantKind: ArtifactKindManifest,
			check: func(t *testing.T, a Artifact) {
				if got := a.References(); len(got) != 2 || got[0].Digest != dig('c') || got[1].Digest != dig('a') {
					t.Fatalf("references must dedupe identical layers: %+v", got)
				}
			},
		},

		// Unsupported / incoherent media types.
		{
			name:        "unsupported top-level media type",
			mediaType:   "application/vnd.docker.distribution.manifest.v1+json",
			body:        ociManifestBody(),
			wantErr:     true,
			wantErrKind: ErrKindUnsupportedMediaType,
		},
		{
			name:        "empty top-level media type",
			mediaType:   "",
			body:        ociManifestBody(),
			wantErr:     true,
			wantErrKind: ErrKindUnsupportedMediaType,
		},
		{
			name:      "embedded media type disagrees with top-level",
			mediaType: dockerManMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[{"mediaType":%q,"size":1024,"digest":%q}]}`,
				ociManifestMT, ociConfigMT, dig('c'), ociLayerMT, dig('a')),
			wantErr:     true,
			wantErrKind: ErrKindMediaTypeMismatch,
		},
		{
			name:      "embedded index media type disagrees with top-level",
			mediaType: ociIndexMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":512,"digest":%q,"platform":{"architecture":"amd64","os":"linux"}}]}`,
				dockerListMT, ociManifestMT, dig('b')),
			wantErr:     true,
			wantErrKind: ErrKindMediaTypeMismatch,
		},

		// JSON structure.
		{
			name:        "malformed truncated JSON",
			mediaType:   ociManifestMT,
			body:        `{"schemaVersion":2,`,
			wantErr:     true,
			wantErrKind: ErrKindMalformedJSON,
		},
		{
			name:        "garbage body",
			mediaType:   ociManifestMT,
			body:        "this is not json at all",
			wantErr:     true,
			wantErrKind: ErrKindMalformedJSON,
		},
		{
			name:        "top-level array",
			mediaType:   ociManifestMT,
			body:        `[1,2,3]`,
			wantErr:     true,
			wantErrKind: ErrKindWrongType,
		},
		{
			name:        "top-level string",
			mediaType:   ociManifestMT,
			body:        `"hello"`,
			wantErr:     true,
			wantErrKind: ErrKindWrongType,
		},
		{
			name:        "top-level number",
			mediaType:   ociManifestMT,
			body:        `42`,
			wantErr:     true,
			wantErrKind: ErrKindWrongType,
		},
		{
			name:        "top-level null",
			mediaType:   ociManifestMT,
			body:        `null`,
			wantErr:     true,
			wantErrKind: ErrKindWrongType,
		},
		{
			name:        "duplicate top-level member",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[]}`, ociConfigMT, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindDuplicateMember,
		},
		{
			name:        "duplicate nested descriptor member",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q,"digest":%q},"layers":[]}`, ociConfigMT, dig('c'), dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindDuplicateMember,
		},
		{
			name:      "duplicate member inside platform",
			mediaType: ociIndexMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":512,"digest":%q,"platform":{"architecture":"amd64","os":"linux","os":"linux"}}]}`,
				ociIndexMT, ociManifestMT, dig('b')),
			wantErr:     true,
			wantErrKind: ErrKindDuplicateMember,
		},
		{
			name:        "unknown top-level member",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"subject":"sha256:%s","config":{"mediaType":%q,"size":24,"digest":%q},"layers":[]}`, strings.Repeat("f", 64), ociConfigMT, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindUnknownMember,
		},
		{
			name:        "unknown descriptor member urls",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q,"urls":["http://x"]},"layers":[]}`, ociConfigMT, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindUnknownMember,
		},
		{
			name:        "unknown descriptor member annotations",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q,"annotations":{"k":"v"}},"layers":[]}`, ociConfigMT, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindUnknownMember,
		},
		{
			name:        "trailing second document",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[]} {"x":1}`, ociConfigMT, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindMalformedJSON,
		},

		// Exact, case-sensitive keys (encoding/json's case-insensitive struct
		// matching and null-to-zero coercion must not apply).
		{
			name:        "case-variant schemaVersion rejected",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"SchemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[]}`, ociConfigMT, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindUnknownMember,
		},
		{
			name:        "exact plus case-variant top-level member rejected",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"SchemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[]}`, ociConfigMT, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindUnknownMember,
		},
		{
			name:        "escaped root duplicate that decodes to same key rejected",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"s\u0063hemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[]}`, ociConfigMT, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindDuplicateMember,
		},
		{
			name:        "case-variant top-level mediaType rejected",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"MediaType":%q,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[]}`, ociManifestMT, ociConfigMT, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindUnknownMember,
		},
		{
			name:        "case-variant config key rejected",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"Config":{"mediaType":%q,"size":24,"digest":%q},"layers":[]}`, ociConfigMT, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindUnknownMember,
		},
		{
			name:        "case-variant layers key rejected",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q},"Layers":[]}`, ociConfigMT, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindUnknownMember,
		},
		{
			name:        "case-variant manifests key rejected",
			mediaType:   ociIndexMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"Manifests":[]}`, ociIndexMT),
			wantErr:     true,
			wantErrKind: ErrKindUnknownMember,
		},
		{
			name:      "platform case-variant Variant key rejected",
			mediaType: ociIndexMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":512,"digest":%q,"platform":{"architecture":"amd64","os":"linux","Variant":"v8"}}]}`,
				ociIndexMT, ociManifestMT, dig('b')),
			wantErr:     true,
			wantErrKind: ErrKindUnknownMember,
		},
		{
			name:      "platform case-variant os.version key rejected",
			mediaType: ociIndexMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":512,"digest":%q,"platform":{"architecture":"amd64","os":"windows","OS.version":"10.0"}}]}`,
				ociIndexMT, ociManifestMT, dig('b')),
			wantErr:     true,
			wantErrKind: ErrKindUnknownMember,
		},
		{
			name:      "platform case-variant os.features key rejected",
			mediaType: ociIndexMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":512,"digest":%q,"platform":{"architecture":"amd64","os":"linux","OS.features":["x"]}}]}`,
				ociIndexMT, ociManifestMT, dig('b')),
			wantErr:     true,
			wantErrKind: ErrKindUnknownMember,
		},
		{
			name:        "top-level mediaType null rejected",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"mediaType":null,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[]}`, ociConfigMT, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindWrongType,
		},
		{
			name:        "descriptor case-variant MediaType key rejected",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"config":{"MediaType":%q,"size":24,"digest":%q},"layers":[]}`, ociConfigMT, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindUnknownMember,
		},
		{
			name:        "descriptor case-variant Digest key rejected",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"Digest":%q},"layers":[]}`, ociConfigMT, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindUnknownMember,
		},
		{
			name:        "descriptor case-variant Size key rejected",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"Size":24,"digest":%q},"layers":[]}`, ociConfigMT, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindUnknownMember,
		},
		{
			name:        "descriptor mediaType null rejected",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":null,"size":24,"digest":%q},"layers":[]}`, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindWrongType,
		},
		{
			name:        "descriptor digest null rejected",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":null},"layers":[]}`, ociConfigMT),
			wantErr:     true,
			wantErrKind: ErrKindWrongType,
		},
		{
			name:      "descriptor Platform null rejected",
			mediaType: ociIndexMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":512,"digest":%q,"Platform":{"architecture":"amd64","os":"linux"}}]}`,
				ociIndexMT, ociManifestMT, dig('b')),
			wantErr:     true,
			wantErrKind: ErrKindUnknownMember,
		},
		{
			name:      "platform case-variant Architecture key rejected",
			mediaType: ociIndexMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":512,"digest":%q,"platform":{"Architecture":"amd64","os":"linux"}}]}`,
				ociIndexMT, ociManifestMT, dig('b')),
			wantErr:     true,
			wantErrKind: ErrKindUnknownMember,
		},
		{
			name:      "platform case-variant OS key rejected",
			mediaType: ociIndexMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":512,"digest":%q,"platform":{"architecture":"amd64","OS":"linux"}}]}`,
				ociIndexMT, ociManifestMT, dig('b')),
			wantErr:     true,
			wantErrKind: ErrKindUnknownMember,
		},
		{
			name:      "platform architecture null rejected",
			mediaType: ociIndexMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":512,"digest":%q,"platform":{"architecture":null,"os":"linux"}}]}`,
				ociIndexMT, ociManifestMT, dig('b')),
			wantErr:     true,
			wantErrKind: ErrKindWrongType,
		},
		{
			name:      "platform os null rejected",
			mediaType: ociIndexMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":512,"digest":%q,"platform":{"architecture":"amd64","os":null}}]}`,
				ociIndexMT, ociManifestMT, dig('b')),
			wantErr:     true,
			wantErrKind: ErrKindWrongType,
		},
		{
			name:      "platform os.features null rejected",
			mediaType: ociIndexMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":512,"digest":%q,"platform":{"architecture":"amd64","os":"linux","os.features":null}}]}`,
				ociIndexMT, ociManifestMT, dig('b')),
			wantErr:     true,
			wantErrKind: ErrKindWrongType,
		},

		// schemaVersion.
		{
			name:        "schemaVersion 1 rejected",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":1,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[]}`, ociConfigMT, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindSchemaVersion,
		},
		{
			name:        "schemaVersion 3 rejected",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":3,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[]}`, ociConfigMT, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindSchemaVersion,
		},
		{
			name:        "schemaVersion missing rejected",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[]}`, ociConfigMT, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindMissingField,
		},
		{
			name:        "schemaVersion float 2.0 rejected",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2.0,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[]}`, ociConfigMT, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindWrongType,
		},
		{
			name:        "schemaVersion string rejected",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":"2","config":{"mediaType":%q,"size":24,"digest":%q},"layers":[]}`, ociConfigMT, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindWrongType,
		},
		{
			name:        "schemaVersion null rejected",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":null,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[]}`, ociConfigMT, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindWrongType,
		},

		// Required fields.
		{
			name:        "manifest missing config",
			mediaType:   ociManifestMT,
			body:        `{"schemaVersion":2,"layers":[]}`,
			wantErr:     true,
			wantErrKind: ErrKindMissingField,
		},
		{
			name:        "config null rejected",
			mediaType:   ociManifestMT,
			body:        `{"schemaVersion":2,"config":null,"layers":[]}`,
			wantErr:     true,
			wantErrKind: ErrKindWrongType,
		},
		{
			name:        "config missing mediaType",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"config":{"size":24,"digest":%q},"layers":[]}`, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindMissingField,
		},
		{
			name:        "config empty mediaType",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":"","size":24,"digest":%q},"layers":[]}`, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindMissingField,
		},
		{
			name:        "config missing digest",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24},"layers":[]}`, ociConfigMT),
			wantErr:     true,
			wantErrKind: ErrKindMissingField,
		},
		{
			name:        "config missing size",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"digest":%q},"layers":[]}`, ociConfigMT, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindMissingField,
		},
		{
			name:        "manifest missing layers",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q}}`, ociConfigMT, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindMissingField,
		},
		{
			name:        "layers null rejected",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":null}`, ociConfigMT, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindWrongType,
		},
		{
			name:        "layers wrong type rejected",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":{"a":1}}`, ociConfigMT, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindWrongType,
		},
		{
			name:        "layer descriptor missing mediaType",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[{"size":1024,"digest":%q}]}`, ociConfigMT, dig('c'), dig('a')),
			wantErr:     true,
			wantErrKind: ErrKindMissingField,
		},
		{
			name:        "layer descriptor missing digest",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[{"mediaType":%q,"size":1024}]}`, ociConfigMT, dig('c'), ociLayerMT),
			wantErr:     true,
			wantErrKind: ErrKindMissingField,
		},
		{
			name:        "layer descriptor missing size",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[{"mediaType":%q,"digest":%q}]}`, ociConfigMT, dig('c'), ociLayerMT, dig('a')),
			wantErr:     true,
			wantErrKind: ErrKindMissingField,
		},

		// Numbers: strings/floats/overflow/null for sizes.
		{
			name:        "size as string rejected",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":"24","digest":%q},"layers":[]}`, ociConfigMT, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindWrongType,
		},
		{
			name:        "size as float rejected",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":2.5,"digest":%q},"layers":[]}`, ociConfigMT, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindWrongType,
		},
		{
			name:        "size integer overflow rejected",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":9223372036854775808,"digest":%q},"layers":[]}`, ociConfigMT, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindIntegerOverflow,
		},
		{
			name:        "size null rejected",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":null,"digest":%q},"layers":[]}`, ociConfigMT, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindWrongType,
		},
		{
			name:        "negative size rejected",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":-1,"digest":%q},"layers":[]}`, ociConfigMT, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindInvalidSize,
		},

		// Digests.
		{
			name:        "uppercase digest rejected",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":"sha256:%s"},"layers":[]}`, ociConfigMT, strings.ToUpper(strings.Repeat("c", 64))),
			wantErr:     true,
			wantErrKind: ErrKindInvalidDigest,
		},
		{
			name:        "short digest rejected",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":"sha256:abc"},"layers":[]}`, ociConfigMT),
			wantErr:     true,
			wantErrKind: ErrKindInvalidDigest,
		},
		{
			name:        "non-hex digest rejected",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":"sha256:%s"},"layers":[]}`, ociConfigMT, strings.Repeat("z", 64)),
			wantErr:     true,
			wantErrKind: ErrKindInvalidDigest,
		},
		{
			name:        "digest missing sha256 prefix rejected",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[]}`, ociConfigMT, strings.Repeat("c", 64)),
			wantErr:     true,
			wantErrKind: ErrKindInvalidDigest,
		},
		{
			name:        "sha512 digest rejected",
			mediaType:   ociManifestMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":"sha512:%s"},"layers":[]}`, ociConfigMT, strings.Repeat("c", 64)),
			wantErr:     true,
			wantErrKind: ErrKindInvalidDigest,
		},
		{
			name:      "layer uppercase digest rejected",
			mediaType: ociManifestMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[{"mediaType":%q,"size":1024,"digest":"sha256:%s"}]}`,
				ociConfigMT, dig('c'), ociLayerMT, strings.ToUpper(strings.Repeat("a", 64))),
			wantErr:     true,
			wantErrKind: ErrKindInvalidDigest,
		},

		// Index shape.
		{
			name:        "index missing manifests",
			mediaType:   ociIndexMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q}`, ociIndexMT),
			wantErr:     true,
			wantErrKind: ErrKindMissingField,
		},
		{
			name:        "index manifests null rejected",
			mediaType:   ociIndexMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":null}`, ociIndexMT),
			wantErr:     true,
			wantErrKind: ErrKindWrongType,
		},
		{
			name:      "oci index empty manifests valid (spec: size MAY be zero)",
			mediaType: ociIndexMT,
			body:      fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[]}`, ociIndexMT),
			wantKind:  ArtifactKindIndex,
			check: func(t *testing.T, a Artifact) {
				if a.Manifests == nil || len(a.Manifests) != 0 {
					t.Fatalf("expected an empty present manifests list, got %+v", a.Manifests)
				}
				if got := a.References(); len(got) != 0 {
					t.Fatalf("empty index must have no references, got %+v", got)
				}
			},
		},
		{
			name:      "docker manifest list empty manifests valid",
			mediaType: dockerListMT,
			body:      fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[]}`, dockerListMT),
			wantKind:  ArtifactKindIndex,
		},
		{
			name:      "index with config forbidden (manifest-only shape)",
			mediaType: ociIndexMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"config":{"mediaType":%q,"size":24,"digest":%q},"manifests":[{"mediaType":%q,"size":512,"digest":%q,"platform":{"architecture":"amd64","os":"linux"}}]}`,
				ociIndexMT, ociConfigMT, dig('c'), ociManifestMT, dig('b')),
			wantErr:     true,
			wantErrKind: ErrKindInvalidShape,
		},
		{
			name:      "index with layers forbidden (manifest-only shape)",
			mediaType: ociIndexMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"layers":[{"mediaType":%q,"size":1024,"digest":%q}],"manifests":[{"mediaType":%q,"size":512,"digest":%q,"platform":{"architecture":"amd64","os":"linux"}}]}`,
				ociIndexMT, ociLayerMT, dig('a'), ociManifestMT, dig('b')),
			wantErr:     true,
			wantErrKind: ErrKindInvalidShape,
		},
		{
			name:      "manifest with manifests array forbidden (index-only shape)",
			mediaType: ociManifestMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[],"manifests":[{"mediaType":%q,"size":512,"digest":%q,"platform":{"architecture":"amd64","os":"linux"}}]}`,
				ociConfigMT, dig('c'), ociManifestMT, dig('b')),
			wantErr:     true,
			wantErrKind: ErrKindInvalidShape,
		},

		// Platforms.
		{
			name:      "platform missing os rejected",
			mediaType: ociIndexMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":512,"digest":%q,"platform":{"architecture":"amd64"}}]}`,
				ociIndexMT, ociManifestMT, dig('b')),
			wantErr:     true,
			wantErrKind: ErrKindInvalidPlatform,
		},
		{
			name:      "platform missing architecture rejected",
			mediaType: ociIndexMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":512,"digest":%q,"platform":{"os":"linux"}}]}`,
				ociIndexMT, ociManifestMT, dig('b')),
			wantErr:     true,
			wantErrKind: ErrKindInvalidPlatform,
		},
		{
			name:      "platform as string rejected",
			mediaType: ociIndexMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":512,"digest":%q,"platform":"linux/amd64"}]}`,
				ociIndexMT, ociManifestMT, dig('b')),
			wantErr:     true,
			wantErrKind: ErrKindWrongType,
		},
		{
			name:      "platform null rejected",
			mediaType: ociIndexMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":512,"digest":%q,"platform":null}]}`,
				ociIndexMT, ociManifestMT, dig('b')),
			wantErr:     true,
			wantErrKind: ErrKindWrongType,
		},
		{
			name:      "unknown platform member rejected",
			mediaType: ociIndexMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":512,"digest":%q,"platform":{"architecture":"amd64","os":"linux","kube":"x"}}]}`,
				ociIndexMT, ociManifestMT, dig('b')),
			wantErr:     true,
			wantErrKind: ErrKindUnknownMember,
		},
		{
			name:      "platform on manifest config forbidden",
			mediaType: ociManifestMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q,"platform":{"architecture":"amd64","os":"linux"}},"layers":[]}`,
				ociConfigMT, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindInvalidShape,
		},
		{
			name:      "platform on manifest layer forbidden",
			mediaType: ociManifestMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[{"mediaType":%q,"size":1024,"digest":%q,"platform":{"architecture":"amd64","os":"linux"}}]}`,
				ociConfigMT, dig('c'), ociLayerMT, dig('a')),
			wantErr:     true,
			wantErrKind: ErrKindInvalidShape,
		},

		// Conflicting duplicate digests.
		{
			name:      "config and layer share digest with different size",
			mediaType: ociManifestMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[{"mediaType":%q,"size":99,"digest":%q}]}`,
				ociConfigMT, dig('c'), ociLayerMT, dig('c')),
			wantErr:     true,
			wantErrKind: ErrKindConflictingDescriptors,
		},
		{
			name:      "duplicate layer digest with different media type",
			mediaType: ociManifestMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[{"mediaType":%q,"size":1024,"digest":%q},{"mediaType":%q,"size":1024,"digest":%q}]}`,
				ociConfigMT, dig('c'), ociLayerMT, dig('a'), dockerLayerMT, dig('a')),
			wantErr:     true,
			wantErrKind: ErrKindConflictingDescriptors,
		},
		{
			name:      "index children share digest with different size",
			mediaType: ociIndexMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":512,"digest":%q,"platform":{"architecture":"amd64","os":"linux"}},{"mediaType":%q,"size":513,"digest":%q,"platform":{"architecture":"arm64","os":"linux"}}]}`,
				ociIndexMT, ociManifestMT, dig('b'), ociManifestMT, dig('b')),
			wantErr:     true,
			wantErrKind: ErrKindConflictingDescriptors,
		},

		// Body size bound.
		{
			name:        "body exceeds documented bound",
			mediaType:   ociManifestMT,
			body:        strings.Repeat(" ", MaxArtifactBodyBytes+1),
			wantErr:     true,
			wantErrKind: ErrKindBodyTooLarge,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, err := ParseArtifact(tc.mediaType, []byte(tc.body))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got artifact %+v", a)
				}
				var ve *ValidationError
				if !errors.As(err, &ve) {
					t.Fatalf("expected typed ValidationError, got %T: %v", err, err)
				}
				if ve.Kind != tc.wantErrKind {
					t.Fatalf("expected kind %q, got %q (err %v)", tc.wantErrKind, ve.Kind, err)
				}
				// Errors must never echo the untrusted body.
				if strings.Contains(err.Error(), tc.body) {
					t.Fatalf("error must not embed the body: %q", err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if a.Kind != tc.wantKind {
				t.Fatalf("expected kind %v, got %v", tc.wantKind, a.Kind)
			}
			if a.MediaType != tc.mediaType {
				t.Fatalf("expected media type %q, got %q", tc.mediaType, a.MediaType)
			}
			if tc.check != nil {
				tc.check(t, a)
			}
		})
	}
}

func TestArtifactReferencesDeterministicOrderAndDedupe(t *testing.T) {
	// Manifest: config C and layers [A, B, A] (A duplicated identically, B in
	// between) must yield exactly [C, A, B] preserving document order.
	manifest := fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[{"mediaType":%q,"size":1,"digest":%q},{"mediaType":%q,"size":2,"digest":%q},{"mediaType":%q,"size":1,"digest":%q}]}`,
		ociConfigMT, dig('c'), ociLayerMT, dig('a'), ociLayerMT, dig('b'), ociLayerMT, dig('a'))
	a, err := ParseArtifact(ociManifestMT, []byte(manifest))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := a.References()
	want := []string{dig('c'), dig('a'), dig('b')}
	if len(got) != len(want) {
		t.Fatalf("references length %d, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].Digest != want[i] {
			t.Fatalf("references[%d] = %s, want %s (full %+v)", i, got[i].Digest, want[i], got)
		}
	}
	// Metadata is preserved through dedupe: the surviving A keeps size 1.
	if got[1].Size != 1 || got[1].MediaType != ociLayerMT {
		t.Fatalf("deduped descriptor metadata lost: %+v", got[1])
	}

	// Index children [X, Y, X] must yield exactly [X, Y].
	index := fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":1,"digest":%q,"platform":{"architecture":"amd64","os":"linux"}},{"mediaType":%q,"size":2,"digest":%q,"platform":{"architecture":"arm64","os":"linux"}},{"mediaType":%q,"size":1,"digest":%q,"platform":{"architecture":"amd64","os":"linux"}}]}`,
		ociIndexMT, ociManifestMT, dig('b'), ociManifestMT, dig('c'), ociManifestMT, dig('b'))
	idx, err := ParseArtifact(ociIndexMT, []byte(index))
	if err != nil {
		t.Fatalf("parse index: %v", err)
	}
	gotIdx := idx.References()
	if len(gotIdx) != 2 || gotIdx[0].Digest != dig('b') || gotIdx[1].Digest != dig('c') {
		t.Fatalf("index references must be deterministic and deduped: %+v", gotIdx)
	}
	if gotIdx[0].Platform == nil || gotIdx[0].Platform.Architecture != "amd64" {
		t.Fatalf("index child platform metadata lost: %+v", gotIdx[0].Platform)
	}
}

func TestParseArtifactErrorsAreDataFree(t *testing.T) {
	const marker = "SECRETBODYECHOMARKER42"
	// The marker is attacker-controlled content inside the body; no error may
	// echo it.
	bodies := []string{
		// Unknown field carrying the marker in its VALUE.
		fmt.Sprintf(`{"schemaVersion":2,"subject":%q,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[]}`, marker, ociConfigMT, dig('c')),
		// Unknown field whose KEY IS the marker (key must not become the path).
		fmt.Sprintf(`{"schemaVersion":2,%q:1,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[]}`, marker, ociConfigMT, dig('c')),
		// Duplicate member whose value is the marker.
		fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"mediaType":%q,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[]}`, marker, marker, ociConfigMT, dig('c')),
		// Trailing garbage with the marker.
		`{"schemaVersion":2,"config":{"mediaType":"` + ociConfigMT + `","size":24,"digest":"` + dig('c') + `"},"layers":[]} "` + marker + `"`,
	}
	for i, body := range bodies {
		if _, err := ParseArtifact(ociManifestMT, []byte(body)); err == nil {
			t.Fatalf("body %d: expected error", i)
		} else if strings.Contains(err.Error(), marker) {
			t.Fatalf("body %d: error echoes attacker content: %q", i, err.Error())
		}
	}
}

// countingObjects counts every object write and records refs, so tests can
// prove that invalid input causes ZERO object writes.
type countingObjects struct {
	puts int
	refs []string
}

func (c *countingObjects) Put(_ context.Context, data []byte, _ string) (string, error) {
	c.puts++
	ref := fmt.Sprintf("swarm-ref-%d", c.puts)
	c.refs = append(c.refs, ref)
	return ref, nil
}

// countingFeeds counts every feed update so tests can prove zero feed writes.
type countingFeeds struct {
	updates int
}

func (c *countingFeeds) UpdateFeed(_ context.Context, _ string, _ string) error {
	c.updates++
	return nil
}

func validBuildInput(t *testing.T) BuildInput {
	t.Helper()
	body := []byte(ociManifestBody())
	return BuildInput{
		Repo:           "backend/api",
		Tag:            "latest",
		ManifestDigest: ComputeDigest(body),
		ManifestJSON:   body,
		Manifest: spec.ManifestDescriptor{
			MediaType: ociManifestMT,
			Size:      int64(len(body)),
		},
		StagedBlobs: map[string]spec.BlobDescriptor{
			dig('c'): {SwarmRef: "swarm-config", Size: 24, MediaType: ociConfigMT},
			dig('a'): {SwarmRef: "swarm-layer", Size: 1024, MediaType: ociLayerMT},
		},
	}
}

// TestPublishValidatesBeforeAnyWrite proves that every invalid input class
// produces ZERO object writes and ZERO feed updates.
func TestPublishValidatesBeforeAnyWrite(t *testing.T) {
	current := spec.RepoStateDocument{}
	ctx := context.Background()

	cases := []struct {
		name     string
		mut      func(input BuildInput) BuildInput
		wantKind ValidationErrorKind
	}{
		{
			name: "malformed manifest body",
			mut: func(input BuildInput) BuildInput {
				input.ManifestJSON = []byte("not json")
				input.ManifestDigest = ComputeDigest(input.ManifestJSON)
				input.Manifest.Size = int64(len(input.ManifestJSON))
				return input
			},
			wantKind: ErrKindMalformedJSON,
		},
		{
			name: "unsupported content type",
			mut: func(input BuildInput) BuildInput {
				input.Manifest.MediaType = "text/plain"
				return input
			},
			wantKind: ErrKindUnsupportedMediaType,
		},
		{
			name: "embedded media type disagrees with content type",
			mut: func(input BuildInput) BuildInput {
				input.Manifest.MediaType = ociManifestMT
				body := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[{"mediaType":%q,"size":1024,"digest":%q}]}`,
					dockerManMT, dockerConfigMT, dig('c'), dockerLayerMT, dig('a')))
				input.ManifestJSON = body
				input.ManifestDigest = ComputeDigest(body)
				input.Manifest.Size = int64(len(body))
				return input
			},
			wantKind: ErrKindMediaTypeMismatch,
		},
		{
			name: "handler-provided digest disagrees with body",
			mut: func(input BuildInput) BuildInput {
				input.ManifestDigest = dig('f')
				return input
			},
			wantKind: ErrKindDigestMismatch,
		},
		{
			name: "handler-provided size disagrees with body",
			mut: func(input BuildInput) BuildInput {
				input.Manifest.Size = int64(len(input.ManifestJSON)) + 1
				return input
			},
			wantKind: ErrKindSizeMismatch,
		},
		{
			name: "referenced blob neither staged nor in state",
			mut: func(input BuildInput) BuildInput {
				input.StagedBlobs = map[string]spec.BlobDescriptor{}
				return input
			},
			wantKind: ErrKindMissingReference,
		},
		{
			name: "non-empty index publication rejected before reference resolution (Task 19)",
			mut: func(input BuildInput) BuildInput {
				body := []byte(ociIndex())
				input.ManifestJSON = body
				input.ManifestDigest = ComputeDigest(body)
				input.Manifest.MediaType = ociIndexMT
				input.Manifest.Size = int64(len(body))
				input.StagedBlobs = map[string]spec.BlobDescriptor{}
				return input
			},
			wantKind: ErrKindUnsupportedPublication,
		},
		{
			name: "empty index publication rejected (Task 19)",
			mut: func(input BuildInput) BuildInput {
				body := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[]}`, ociIndexMT))
				input.ManifestJSON = body
				input.ManifestDigest = ComputeDigest(body)
				input.Manifest.MediaType = ociIndexMT
				input.Manifest.Size = int64(len(body))
				input.StagedBlobs = map[string]spec.BlobDescriptor{}
				return input
			},
			wantKind: ErrKindUnsupportedPublication,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			objs := &countingObjects{}
			feeds := &countingFeeds{}
			p := Publisher{Builder: DefaultBuilder{}, Objects: objs, Feeds: feeds}

			input := tc.mut(validBuildInput(t))
			_, err := p.Publish(ctx, "feed://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", current, input, "batch-1")
			if err == nil {
				t.Fatal("expected publish to fail")
			}
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("expected typed ValidationError, got %T: %v", err, err)
			}
			if ve.Kind != tc.wantKind {
				t.Fatalf("expected kind %q, got %q (err %v)", tc.wantKind, ve.Kind, err)
			}
			if objs.puts != 0 {
				t.Fatalf("invalid input caused %d object writes, want 0", objs.puts)
			}
			if feeds.updates != 0 {
				t.Fatalf("invalid input caused %d feed updates, want 0", feeds.updates)
			}
		})
	}
}

// TestPublishValidArtifactWritesManifestStateAndFeedOnce pins the happy path:
// exactly two object writes (manifest bytes, repo state) and one feed update,
// with the parsed references recorded into the new repo state.
func TestPublishValidArtifactWritesManifestStateAndFeedOnce(t *testing.T) {
	objs := &countingObjects{}
	feeds := &countingFeeds{}
	p := Publisher{Builder: DefaultBuilder{}, Objects: objs, Feeds: feeds}

	input := validBuildInput(t)
	current := spec.RepoStateDocument{}

	next, err := p.Publish(context.Background(), "feed://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", current, input, "batch-1")
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if objs.puts != 2 {
		t.Fatalf("expected 2 object writes (manifest + state), got %d", objs.puts)
	}
	if feeds.updates != 1 {
		t.Fatalf("expected 1 feed update, got %d", feeds.updates)
	}
	if next.Generation != 1 {
		t.Fatalf("expected generation 1, got %d", next.Generation)
	}
	if next.Tags["latest"] != input.ManifestDigest {
		t.Fatalf("tag did not point at the manifest: %+v", next.Tags)
	}
	man, ok := next.Manifests[input.ManifestDigest]
	if !ok || man.SwarmRef != "swarm-ref-1" || man.MediaType != ociManifestMT || man.Size != int64(len(input.ManifestJSON)) {
		t.Fatalf("manifest descriptor not recorded correctly: %+v", next.Manifests)
	}
	if len(next.Blobs) != 2 {
		t.Fatalf("expected both referenced blobs in state, got %+v", next.Blobs)
	}
}

// TestBuildNextDirectCoherence proves that a DIRECT caller of
// DefaultBuilder.BuildNext gets the SAME body/digest/size/media coherence and
// reference-availability validation as the publish path, before any state is
// derived — a wrong digest, size, media type, or staged metadata fails typed
// and leaves input/current untouched.
func TestBuildNextDirectCoherence(t *testing.T) {
	current := spec.RepoStateDocument{Generation: 7}

	cases := []struct {
		name     string
		mut      func(BuildInput) BuildInput
		wantKind ValidationErrorKind
	}{
		{name: "wrong body digest", wantKind: ErrKindDigestMismatch,
			mut: func(i BuildInput) BuildInput { i.ManifestDigest = dig('f'); return i }},
		{name: "wrong body size", wantKind: ErrKindSizeMismatch,
			mut: func(i BuildInput) BuildInput { i.Manifest.Size = int64(len(i.ManifestJSON)) + 1; return i }},
		{name: "unsupported media type", wantKind: ErrKindUnsupportedMediaType,
			mut: func(i BuildInput) BuildInput { i.Manifest.MediaType = "text/plain"; return i }},
		{name: "staged blob size mismatch", wantKind: ErrKindSizeMismatch,
			mut: func(i BuildInput) BuildInput {
				s := i.StagedBlobs[dig('c')]
				s.Size = 99
				i.StagedBlobs[dig('c')] = s
				return i
			}},
		{name: "staged concrete media mismatch", wantKind: ErrKindMediaTypeMismatch,
			mut: func(i BuildInput) BuildInput {
				s := i.StagedBlobs[dig('a')]
				s.MediaType = "text/plain"
				i.StagedBlobs[dig('a')] = s
				return i
			}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := tc.mut(validBuildInput(t))
			next, err := (DefaultBuilder{}).BuildNext(current, input)
			if err == nil {
				t.Fatal("expected direct BuildNext to fail")
			}
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("expected typed ValidationError, got %T: %v", err, err)
			}
			if ve.Kind != tc.wantKind {
				t.Fatalf("expected kind %q, got %q (err %v)", tc.wantKind, ve.Kind, err)
			}
			// No state may be derived or the input description mutated.
			if next.Version != 0 || next.Repo != "" || next.Generation != 0 {
				t.Fatalf("BuildNext must not derive state on failure, got %+v", next)
			}
			if current.Generation != 7 {
				t.Fatalf("BuildNext mutated current, generation=%d", current.Generation)
			}
		})
	}
}

// TestBuildNextDirectValid proves a direct BuildNext with a valid input
// succeeds and carries the parsed references into state.
func TestBuildNextDirectValid(t *testing.T) {
	input := validBuildInput(t)
	input.Manifest.SwarmRef = "swarm-ref-manifest"
	next, err := (DefaultBuilder{}).BuildNext(spec.RepoStateDocument{}, input)
	if err != nil {
		t.Fatalf("direct BuildNext: %v", err)
	}
	if next.Generation != 1 || len(next.Blobs) != 2 || next.Blobs[dig('c')].Size != 24 {
		t.Fatalf("direct BuildNext state wrong: %+v", next)
	}
}

// TestPublishReferenceMetadata exercises the reference size/media coherence
// checks against both current-state and staged blob records. Failing cases
// produce ZERO object writes; the current-state record is authoritative when a
// digest exists both current and staged; unspecified (octet-stream/empty)
// staged and current types are the upload transport's transparent placeholder.
func TestPublishReferenceMetadata(t *testing.T) {
	ctx := context.Background()

	// currentWithBlobs returns a repo state carrying dig('c') and dig('a')
	// with the given stored size/media type overrides.
	currentWithBlobs := func(c, a spec.BlobDescriptor) spec.RepoStateDocument {
		return spec.RepoStateDocument{Blobs: map[string]spec.BlobDescriptor{
			dig('c'): c,
			dig('a'): a,
		}}
	}
	configDesc := spec.BlobDescriptor{SwarmRef: "s-c", Size: 24, MediaType: ociConfigMT}
	layerDesc := spec.BlobDescriptor{SwarmRef: "s-a", Size: 1024, MediaType: ociLayerMT}

	failCases := []struct {
		name     string
		current  spec.RepoStateDocument
		staged   map[string]spec.BlobDescriptor
		wantKind ValidationErrorKind
	}{
		{name: "current blob size mismatch", current: currentWithBlobs(
			spec.BlobDescriptor{SwarmRef: "s-c", Size: 25, MediaType: ociConfigMT}, layerDesc), wantKind: ErrKindSizeMismatch},
		{name: "current concrete media mismatch", current: currentWithBlobs(
			spec.BlobDescriptor{SwarmRef: "s-c", Size: 24, MediaType: "text/plain"}, layerDesc), wantKind: ErrKindMediaTypeMismatch},
		{name: "staged blob size mismatch", current: spec.RepoStateDocument{}, staged: map[string]spec.BlobDescriptor{
			dig('c'): {SwarmRef: "s-c", Size: 99, MediaType: ociConfigMT},
			dig('a'): {SwarmRef: "s-a", Size: 1024, MediaType: ociLayerMT},
		}, wantKind: ErrKindSizeMismatch},
		{name: "staged concrete media mismatch", current: spec.RepoStateDocument{}, staged: map[string]spec.BlobDescriptor{
			dig('c'): {SwarmRef: "s-c", Size: 24, MediaType: ociConfigMT},
			dig('a'): {SwarmRef: "s-a", Size: 1024, MediaType: "text/plain"},
		}, wantKind: ErrKindMediaTypeMismatch},
		{name: "staged malformed media rejected", current: spec.RepoStateDocument{}, staged: map[string]spec.BlobDescriptor{
			dig('c'): {SwarmRef: "s-c", Size: 24, MediaType: ociConfigMT},
			dig('a'): {SwarmRef: "s-a", Size: 1024, MediaType: "not a mediatype"},
		}, wantKind: ErrKindMediaTypeMismatch},
		{name: "staged conflicts even when current matches (both sources validated)", current: currentWithBlobs(configDesc, layerDesc), staged: map[string]spec.BlobDescriptor{
			dig('c'): {SwarmRef: "stale-c", Size: 99, MediaType: "text/plain"},
			dig('a'): {SwarmRef: "stale-a", Size: 1, MediaType: "text/plain"},
		}, wantKind: ErrKindSizeMismatch},
		{name: "staged concrete media conflicts when current matches", current: currentWithBlobs(configDesc, layerDesc), staged: map[string]spec.BlobDescriptor{
			dig('c'): {SwarmRef: "s-c", Size: 24, MediaType: ociConfigMT},
			dig('a'): {SwarmRef: "s-a", Size: 1024, MediaType: "text/plain"},
		}, wantKind: ErrKindMediaTypeMismatch},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			input := validBuildInput(t)
			input.StagedBlobs = tc.staged
			objs := &countingObjects{}
			feeds := &countingFeeds{}
			p := Publisher{Builder: DefaultBuilder{}, Objects: objs, Feeds: feeds}
			_, err := p.Publish(ctx, "feed://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", tc.current, input, "batch-1")
			if err == nil {
				t.Fatal("expected publish to fail")
			}
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("expected typed ValidationError, got %T: %v", err, err)
			}
			if ve.Kind != tc.wantKind {
				t.Fatalf("expected kind %q, got %q (err %v)", tc.wantKind, ve.Kind, err)
			}
			if objs.puts != 0 || feeds.updates != 0 {
				t.Fatalf("conflict caused writes: puts=%d feeds=%d", objs.puts, feeds.updates)
			}
		})
	}

	successCases := []struct {
		name    string
		current spec.RepoStateDocument
		staged  map[string]spec.BlobDescriptor
	}{
		{name: "generic octet-stream staged accepted", current: spec.RepoStateDocument{}, staged: map[string]spec.BlobDescriptor{
			dig('c'): {SwarmRef: "s-c", Size: 24, MediaType: "application/octet-stream"},
			dig('a'): {SwarmRef: "s-a", Size: 1024, MediaType: "application/octet-stream"},
		}},
		{name: "empty staged media type accepted", current: spec.RepoStateDocument{}, staged: map[string]spec.BlobDescriptor{
			dig('c'): {SwarmRef: "s-c", Size: 24},
			dig('a'): {SwarmRef: "s-a", Size: 1024},
		}},
		{name: "current octet-stream blob accepted", current: currentWithBlobs(
			spec.BlobDescriptor{SwarmRef: "s-c", Size: 24, MediaType: "application/octet-stream"},
			spec.BlobDescriptor{SwarmRef: "s-a", Size: 1024, MediaType: "application/octet-stream"}), staged: map[string]spec.BlobDescriptor{}},
		{name: "descriptor media type is canonical over octet-stream", current: spec.RepoStateDocument{}, staged: map[string]spec.BlobDescriptor{
			dig('c'): {SwarmRef: "s-c", Size: 24, MediaType: blobGenericMediaType},
			dig('a'): {SwarmRef: "s-a", Size: 1024, MediaType: blobGenericMediaType},
		}},
		{name: "concrete current and staged agree with descriptor", current: currentWithBlobs(configDesc, layerDesc), staged: map[string]spec.BlobDescriptor{}},
	}
	for _, tc := range successCases {
		t.Run(tc.name, func(t *testing.T) {
			input := validBuildInput(t)
			input.StagedBlobs = tc.staged
			objs := &countingObjects{}
			feeds := &countingFeeds{}
			p := Publisher{Builder: DefaultBuilder{}, Objects: objs, Feeds: feeds}
			if _, err := p.Publish(ctx, "feed://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", tc.current, input, "batch-1"); err != nil {
				t.Fatalf("expected publish to succeed: %v", err)
			}
			if objs.puts != 2 || feeds.updates != 1 {
				t.Fatalf("coherent publish must write manifest+state and one feed, got puts=%d feeds=%d", objs.puts, feeds.updates)
			}
		})
	}
}

// TestBuildNextRejectsIndexPublication proves direct BuildNext refuses ANY
// index kind (empty and non-empty) with a typed unsupported-publication error
// BEFORE deriving state or mutating current. Parser support for indexes is
// unaffected; publication is gated until Task 19.
func TestBuildNextRejectsIndexPublication(t *testing.T) {
	bodies := []string{
		fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[]}`, ociIndexMT),
		ociIndex(),
	}
	for _, body := range bodies {
		input := validBuildInput(t)
		input.ManifestJSON = []byte(body)
		input.ManifestDigest = ComputeDigest([]byte(body))
		input.Manifest.MediaType = ociIndexMT
		input.Manifest.Size = int64(len(body))
		input.StagedBlobs = map[string]spec.BlobDescriptor{}

		current := spec.RepoStateDocument{Generation: 7}
		next, err := (DefaultBuilder{}).BuildNext(current, input)
		if err == nil {
			t.Fatal("expected direct BuildNext to reject index publication")
		}
		var ve *ValidationError
		if !errors.As(err, &ve) || ve.Kind != ErrKindUnsupportedPublication {
			t.Fatalf("expected unsupported_artifact_publication, got %v", err)
		}
		if next.Generation != 0 || next.Repo != "" {
			t.Fatalf("BuildNext derived state on index rejection: %+v", next)
		}
		if current.Generation != 7 {
			t.Fatalf("BuildNext mutated current: generation=%d", current.Generation)
		}
	}
}

// TestBuildNextPrefersCurrentRecordOverStagedGeneric proves the builder never
// lets a staged unspecified (empty/octet-stream) record overwrite the richer
// authoritative current record for the same digest, and that staged blobs
// whose digest is NEITHER in current NOR referenced by the next manifest (the
// 'z' entry) are not copied at all — staged copying is referenced-only.
func TestBuildNextPrefersCurrentRecordOverStagedGeneric(t *testing.T) {
	current := spec.RepoStateDocument{Blobs: map[string]spec.BlobDescriptor{
		dig('c'): {SwarmRef: "s-c-current", Size: 24, MediaType: ociConfigMT},
		dig('a'): {SwarmRef: "s-a-current", Size: 1024, MediaType: ociLayerMT},
	}}
	input := validBuildInput(t)
	input.Manifest.SwarmRef = "swarm-ref-manifest"
	input.StagedBlobs = map[string]spec.BlobDescriptor{
		dig('c'): {SwarmRef: "s-c-staged", Size: 24},                                       // unspecified media
		dig('a'): {SwarmRef: "s-a-staged", Size: 1024, MediaType: blobGenericMediaType},    // octet-stream generic
		dig('z'): {SwarmRef: "s-z-staged", Size: 7, MediaType: "application/octet-stream"}, // unrelated staged blob
	}

	next, err := (DefaultBuilder{}).BuildNext(current, input)
	if err != nil {
		t.Fatalf("direct BuildNext with dual-source generic/rich: %v", err)
	}
	if got := next.Blobs[dig('c')]; got.SwarmRef != "s-c-current" || got.MediaType != ociConfigMT || got.Size != 24 {
		t.Fatalf("current config record degraded by generic staged entry: %+v", got)
	}
	if got := next.Blobs[dig('a')]; got.SwarmRef != "s-a-current" || got.MediaType != ociLayerMT || got.Size != 1024 {
		t.Fatalf("current layer record degraded by octet-stream staged entry: %+v", got)
	}
	if got, ok := next.Blobs[dig('z')]; ok {
		t.Fatalf("unreferenced staged blob must NOT be copied into next state, got %+v", got)
	}
}

// TestPublishDualSourceKeepsCurrentRichRecord runs the same dual-source
// generic/rich scenario through Publish and asserts the resulting next state,
// not just write counts, keeps the current authoritative records.
func TestPublishDualSourceKeepsCurrentRichRecord(t *testing.T) {
	current := spec.RepoStateDocument{Blobs: map[string]spec.BlobDescriptor{
		dig('c'): {SwarmRef: "s-c-current", Size: 24, MediaType: ociConfigMT},
		dig('a'): {SwarmRef: "s-a-current", Size: 1024, MediaType: ociLayerMT},
	}}
	input := validBuildInput(t)
	input.StagedBlobs = map[string]spec.BlobDescriptor{
		dig('c'): {SwarmRef: "s-c-staged", Size: 24},
		dig('a'): {SwarmRef: "s-a-staged", Size: 1024, MediaType: blobGenericMediaType},
	}

	objs := &countingObjects{}
	feeds := &countingFeeds{}
	p := Publisher{Builder: DefaultBuilder{}, Objects: objs, Feeds: feeds}
	next, err := p.Publish(context.Background(), "feed://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", current, input, "batch-1")
	if err != nil {
		t.Fatalf("publish dual-source generic/rich: %v", err)
	}
	if got := next.Blobs[dig('c')]; got.SwarmRef != "s-c-current" || got.MediaType != ociConfigMT {
		t.Fatalf("published state degraded config record: %+v", got)
	}
	if got := next.Blobs[dig('a')]; got.SwarmRef != "s-a-current" || got.MediaType != ociLayerMT {
		t.Fatalf("published state degraded layer record: %+v", got)
	}
	if objs.puts != 2 || feeds.updates != 1 {
		t.Fatalf("coherent dual-source publish writes: puts=%d feeds=%d", objs.puts, feeds.updates)
	}
}

// TestPublishValidationErrorsAreDataFree proves the Publish path never echoes
// attacker-controlled values (stored media type, digest, size, repo/tag)
// through ValidationError.Error, even though the internal cause may retain
// them for errors.Is/As. Each failing publication makes zero object writes and
// zero feed updates.
func TestPublishValidationErrorsAreDataFree(t *testing.T) {
	const marker = "SECRETMEDIAMARKER42"
	ctx := context.Background()
	current := spec.RepoStateDocument{}

	cases := []struct {
		name string
		mut  func(input BuildInput) BuildInput
	}{
		{
			name: "stored blob media malformed",
			mut: func(input BuildInput) BuildInput {
				s := input.StagedBlobs[dig('a')]
				s.SwarmRef = marker
				s.MediaType = marker // malformed concrete stored type
				input.StagedBlobs[dig('a')] = s
				return input
			},
		},
		{
			name: "stored blob concrete media mismatch",
			mut: func(input BuildInput) BuildInput {
				s := input.StagedBlobs[dig('a')]
				s.MediaType = "application/x-" + marker // well-formed but conflicting
				input.StagedBlobs[dig('a')] = s
				return input
			},
		},
		{
			name: "stored blob size mismatch",
			mut: func(input BuildInput) BuildInput {
				s := input.StagedBlobs[dig('c')]
				s.SwarmRef = marker
				s.Size = 999
				input.StagedBlobs[dig('c')] = s
				return input
			},
		},
		{
			name: "missing reference",
			mut: func(input BuildInput) BuildInput {
				input.StagedBlobs = map[string]spec.BlobDescriptor{}
				return input
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			objs := &countingObjects{}
			feeds := &countingFeeds{}
			p := Publisher{Builder: DefaultBuilder{}, Objects: objs, Feeds: feeds}
			input := tc.mut(validBuildInput(t))
			_, err := p.Publish(ctx, "feed://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", current, input, "batch-1")
			if err == nil {
				t.Fatal("expected validation error")
			}
			if strings.Contains(err.Error(), marker) {
				t.Fatalf("publish error echoes attacker marker %q: %q", marker, err.Error())
			}
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("expected typed ValidationError, got %T: %v", err, err)
			}
			if objs.puts != 0 || feeds.updates != 0 {
				t.Fatalf("validation failure caused writes: puts=%d feeds=%d", objs.puts, feeds.updates)
			}
		})
	}
}

// collectErrChain appends err and every error reachable from it through
// errors.Unwrap — through BOTH the single-error and the []error Unwrap forms —
// so a caller can assert a marker is absent from every recursively unwrapped
// error, not just the top one.
func collectErrChain(err error, out *[]error) {
	if err == nil {
		return
	}
	*out = append(*out, err)
	switch u := err.(type) {
	case interface{ Unwrap() []error }:
		for _, e := range u.Unwrap() {
			collectErrChain(e, out)
		}
	case interface{ Unwrap() error }:
		collectErrChain(u.Unwrap(), out)
	}
}

// assertValidationErrorDataFree asserts a *ValidationError (reachable via
// errors.As) and EVERY error reachable from it through formatting, %+v, and
// every recursively unwrapped error contains only data-free content: the
// attacker marker appears nowhere. It also asserts the kind classification
// still works and that the ValidationError type exposes no raw cause.
func assertValidationErrorDataFree(t *testing.T, err error, marker string, wantKind ValidationErrorKind) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a validation error")
	}

	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("errors.As must still classify the typed ValidationError, got %T: %v", err, err)
	}
	if ve.Kind != wantKind {
		t.Fatalf("expected kind %q, got %q (err %v)", wantKind, ve.Kind, err)
	}

	var chain []error
	collectErrChain(err, &chain)
	for i, e := range chain {
		if strings.Contains(e.Error(), marker) {
			t.Fatalf("unwrapped error[%d] echoes attacker marker %q: %q", i, marker, e.Error())
		}
		if s := fmt.Sprintf("%+v", e); strings.Contains(s, marker) {
			t.Fatalf("unwrapped error[%d] %%-formatted echoes attacker marker %q: %s", i, marker, s)
		}
	}
	if s := fmt.Sprintf("%+v", err); strings.Contains(s, marker) {
		t.Fatalf("%%-formatted error echoes attacker marker %q: %s", marker, s)
	}

	// A returned error's whole reachable surface must be data free, including
	// any exported accessor/interface on the typed error.
	for _, iface := range []any{ve} {
		if s := fmt.Sprintf("%+v", iface); strings.Contains(s, marker) {
			t.Fatalf("exported error value %%-formatted echoes attacker marker %q: %s", marker, s)
		}
	}
	// Reflected exported string fields must be data free too.
	rv := reflect.ValueOf(ve).Elem()
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if f.PkgPath != "" {
			continue // unexported
		}
		if f.Type.Kind() == reflect.String && strings.Contains(rv.Field(i).String(), marker) {
			t.Fatalf("exported field %s echoes attacker marker %q", f.Name, marker)
		}
	}
}

// TestValidationErrorExposesNoCause pins the compile-time-invisible contract:
// the ValidationError method set has no Cause accessor and the struct retains
// only the stable Kind/Field/Err state. A Cause method cannot be called
// directly (it no longer exists), so reflection asserts its absence, along
// with the absence of any unexported detail field.
func TestValidationErrorExposesNoCause(t *testing.T) {
	rt := reflect.TypeOf((*ValidationError)(nil)).Elem()
	if m, ok := rt.MethodByName("Cause"); ok {
		t.Fatalf("ValidationError must not expose a Cause accessor, found method %v", m.Func.Type())
	}
	if m, ok := rt.MethodByName("CauseOf"); ok {
		t.Fatalf("ValidationError must not expose a cause accessor, found method %v", m.Func.Type())
	}
	// The struct must retain ONLY the three stable, data-free fields.
	if got := rt.NumField(); got != 3 {
		t.Fatalf("ValidationError must have exactly 3 stable fields (Kind/Field/Err), got %d", got)
	}
	for _, name := range []string{"cause", "Cause", "detail", "CauseErr"} {
		if _, ok := rt.FieldByName(name); ok {
			t.Fatalf("ValidationError must not retain a detail field %q", name)
		}
	}
}

// TestValidationErrorDataFreeAcrossAllSurfaces drives attacker markers through
// every validation surface — unknown member key, invalid digest, media type,
// conflicting digest, stored blob media type, and a staged SwarmRef — and
// asserts the marker is absent from Error(), %+v, every recursively unwrapped
// error, every exported string field, and every exported accessor, while
// errors.As/kind classification still works.
func TestValidationErrorDataFreeAcrossAllSurfaces(t *testing.T) {
	const marker = "SECRETMARKERDEADBEEF"

	parseCases := []struct {
		name      string
		mediaType string
		body      string
		wantKind  ValidationErrorKind
	}{
		{
			name:      "unknown member key",
			mediaType: ociManifestMT,
			body:      fmt.Sprintf(`{"schemaVersion":2,"%s":1,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[]}`, marker, ociConfigMT, dig('c')),
			wantKind:  ErrKindUnknownMember,
		},
		{
			name:      "invalid digest value",
			mediaType: ociManifestMT,
			body:      fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[]}`, ociConfigMT, "sha256:"+marker),
			wantKind:  ErrKindInvalidDigest,
		},
		{
			name:      "embedded media type marker",
			mediaType: ociManifestMT,
			body:      fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[]}`, "application/"+marker, ociConfigMT, dig('c')),
			wantKind:  ErrKindMediaTypeMismatch,
		},
		{
			name:      "conflicting digest never becomes the field path",
			mediaType: ociManifestMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[{"mediaType":%q,"size":99,"digest":%q}]}`,
				ociConfigMT, dig('c'), ociLayerMT, dig('c')),
			wantKind: ErrKindConflictingDescriptors,
		},
	}

	for _, tc := range parseCases {
		t.Run("parse/"+tc.name, func(t *testing.T) {
			_, err := ParseArtifact(tc.mediaType, []byte(tc.body))
			assertValidationErrorDataFree(t, err, marker, tc.wantKind)
			if tc.wantKind == ErrKindConflictingDescriptors {
				// The conflicting digest is canonical-but-attacker-controlled; it
				// must NOT surface as the structural Field path.
				var ve *ValidationError
				if !errors.As(err, &ve) {
					t.Fatalf("expected typed ValidationError, got %T", err)
				}
				if ve.Field != conflictMarker {
					t.Fatalf("conflicting-digest Field must be the fixed marker %q, got %q", conflictMarker, ve.Field)
				}
			}
		})
	}

	// Publish-path markers: stored blob media type and staged SwarmRef.
	ctx := context.Background()
	publishCases := []struct {
		name     string
		mut      func(input BuildInput) BuildInput
		wantKind ValidationErrorKind
	}{
		{
			name: "stored media marker",
			mut: func(input BuildInput) BuildInput {
				s := input.StagedBlobs[dig('a')]
				s.SwarmRef = marker
				s.MediaType = marker
				input.StagedBlobs[dig('a')] = s
				return input
			},
			wantKind: ErrKindMediaTypeMismatch,
		},
		{
			name: "swarm ref marker on size mismatch",
			mut: func(input BuildInput) BuildInput {
				s := input.StagedBlobs[dig('c')]
				s.SwarmRef = marker
				s.Size = 999
				input.StagedBlobs[dig('c')] = s
				return input
			},
			wantKind: ErrKindSizeMismatch,
		},
		{
			name: "manifest digest marker",
			mut: func(input BuildInput) BuildInput {
				input.ManifestDigest = marker
				return input
			},
			wantKind: ErrKindDigestMismatch,
		},
	}

	for _, tc := range publishCases {
		t.Run("publish/"+tc.name, func(t *testing.T) {
			objs := &countingObjects{}
			feeds := &countingFeeds{}
			p := Publisher{Builder: DefaultBuilder{}, Objects: objs, Feeds: feeds}
			input := tc.mut(validBuildInput(t))
			_, err := p.Publish(ctx, "feed://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", spec.RepoStateDocument{}, input, "batch-1")
			assertValidationErrorDataFree(t, err, marker, tc.wantKind)
			if objs.puts != 0 || feeds.updates != 0 {
				t.Fatalf("validation failure caused writes: puts=%d feeds=%d", objs.puts, feeds.updates)
			}
		})
	}
}
