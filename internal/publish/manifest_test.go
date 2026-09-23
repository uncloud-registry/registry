package publish

import (
	"context"
	"errors"
	"fmt"
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
			wantErrKind: ErrKindSchemaVersion,
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
			wantErrKind: ErrKindMissingField,
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
			wantErrKind: ErrKindInvalidDigest,
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
			wantErrKind: ErrKindMissingField,
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
			wantErrKind: ErrKindInvalidDigest,
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
			wantErrKind: ErrKindMissingField,
		},
		{
			name:        "index empty manifests rejected",
			mediaType:   ociIndexMT,
			body:        fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[]}`, ociIndexMT),
			wantErr:     true,
			wantErrKind: ErrKindInvalidShape,
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
			wantErrKind: ErrKindInvalidPlatform,
		},
		{
			name:      "platform null rejected",
			mediaType: ociIndexMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":512,"digest":%q,"platform":null}]}`,
				ociIndexMT, ociManifestMT, dig('b')),
			wantErr:     true,
			wantErrKind: ErrKindInvalidPlatform,
		},
		{
			name:      "unknown platform member rejected",
			mediaType: ociIndexMT,
			body: fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":512,"digest":%q,"platform":{"architecture":"amd64","os":"linux","kube":"x"}}]}`,
				ociIndexMT, ociManifestMT, dig('b')),
			wantErr:     true,
			wantErrKind: ErrKindInvalidPlatform,
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
		// Unknown field carrying the marker in its value.
		fmt.Sprintf(`{"schemaVersion":2,"subject":%q,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[]}`, marker, ociConfigMT, dig('c')),
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
			name: "index child manifest unavailable (deferred to Task 19)",
			mut: func(input BuildInput) BuildInput {
				body := []byte(ociIndex())
				input.ManifestJSON = body
				input.ManifestDigest = ComputeDigest(body)
				input.Manifest.MediaType = ociIndexMT
				input.Manifest.Size = int64(len(body))
				input.StagedBlobs = map[string]spec.BlobDescriptor{}
				return input
			},
			wantKind: ErrKindMissingReference,
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
