package staging

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/uncloud-registry/registry/internal/spec"
)

// The in-memory dev/test store and the registry-facing RegistryStore contract
// live in memory.go (formerly here as the byte-buffer Store/MemoryStore API).

// ---------------------------------------------------------------------------
// Durable staging service: shared types, sentinel errors, and validators.
//
// These definitions are shared by the durable Service (Task 15) and are kept
// compatible with the in-memory store in memory.go: nothing here changes the
// RegistryStore contract used by the registry handler.
// ---------------------------------------------------------------------------

// State is the durable session lifecycle state persisted in SQLite.
type State string

const (
	// StateActive accepts streaming appends.
	StateActive State = "active"
	// StateCreating is the durable pre-activation state committed BEFORE a
	// session's file is created: an interrupted create is attributable at
	// startup (finished if the empty file is durable, rolled back
	// otherwise) and is never visible to callers. Only startup
	// reconciliation and Create itself transition out of it.
	StateCreating State = "creating"
	// StateFinalizing is the durable finalization CLAIM: committed by the
	// single upload winner (ClaimFinalize) BEFORE any external object-store
	// write, atomically freezing the exact staged snapshot (state == active,
	// size == offset, bytes immutable thereafter). Appends are rejected while
	// finalizing; delete/expire fail closed; publication never lists it. Only
	// the claim winner streams to the object store and then either completes
	// to StateFinalized (MarkFinalized) or — on a CONCLUSIVELY pre-side-effect
	// uploader failure — returns to StateActive (ReleaseClaim). A session left
	// in finalizing after an AMBIGUOUS uploader failure or a process crash is
	// retained fail-closed: every retry makes ZERO object-store writes and
	// receives a fixed response until an explicit reconciliation path exists.
	StateFinalizing State = "finalizing"
	// StateFinalized carries complete validated blob metadata; appends are
	// rejected and the file bytes are frozen.
	StateFinalized State = "finalized"
	// StateDeleting is a durable tombstone set before a session's file is
	// removed, so an interrupted deletion is completed by a later delete or by
	// startup reconciliation instead of stranding an unknown file.
	StateDeleting State = "deleting"
)

// RegistryStore is the narrow registry-facing staging contract the HTTP
// handler needs. Both the durable Service (Task 15) and the in-memory
// dev/test store implement it, so the handler never branches on durability.
// Every upload operation is repo+actor bound; ownership mismatches surface
// as the identical ErrNotFound (never an existence oracle). Publication uses
// ListStagedBlobs + ClearStagedBlobsByDigest for referenced-only consumption.
type RegistryStore interface {
	Create(ctx context.Context, repo, actor string, ttl time.Duration) (Session, error)
	Status(ctx context.Context, id, repo, actor string) (Session, error)
	Append(ctx context.Context, id, repo, actor string, expectedOffset int64, src io.Reader, maxBytes int64) (Session, error)
	Open(ctx context.Context, id, repo, actor string) (io.ReadCloser, Session, error)
	// ClaimFinalize durably reserves THIS session for external finalization
	// BEFORE any object-store write. It atomically authenticates repo+actor,
	// requires an active + unexpired session, compares the exact frozen
	// staged snapshot (the current durable offset MUST equal size, the byte
	// count the caller just hashed), and transitions active -> finalizing.
	// Exactly one concurrent caller wins per session; a loser sees the change
	// reflected (finalizing / finalized) and performs ZERO object-store
	// writes. While finalizing the bytes are immutable and delete/expire fail
	// closed. It returns ErrOffsetMismatch when a concurrent append advanced
	// the offset after the caller's hash, so no Bee write ever occurs on
	// stale bytes.
	ClaimFinalize(ctx context.Context, id, repo, actor string, size int64) (Session, error)
	// ReleaseClaim returns a finalizing session to active. It is legal ONLY
	// for a CONCLUSIVELY pre-side-effect uploader failure (no external bytes
	// were ever sent); it is never used to paper over ambiguous failures or
	// metadata-receipt faults, which must retain the claim fail-closed. Only
	// the claim winner — the sole holder of the session's unforgeable claim
	// token (the Token returned by ClaimFinalize) — may release; a foreign
	// instance without the token gets the same ownership-indistinguishable
	// result and can never reset a foreign claim to active (no duplicate or
	// orphaned write is therefore possible across processes).
	ReleaseClaim(ctx context.Context, id, repo, actor, token string) error
	// MarkFinalized completes a session with exact finalize metadata (the
	// digest/Bee ref/media type the winner already wrote). From finalizing it
	// requires the winning claim token; from active (plain service-level
	// finalize) no token is required. An already-finalized byte-identical
	// retry is idempotently nil; differing metadata is ErrFinalizeConflict.
	MarkFinalized(ctx context.Context, id, repo, actor, token, digest, beeRef, mediaType string, size int64) error
	Delete(ctx context.Context, id, repo, actor string) error
	ListStagedBlobs(ctx context.Context, repo, actor string) ([]spec.StagedBlob, error)
	ClearStagedBlobsByDigest(ctx context.Context, repo, actor string, digests []string) error
}

// Limits configures the atomic durable staging quotas enforced INSIDE the
// Append BEGIN IMMEDIATE transaction (never handler-side status checks), so
// independent service processes admit only valid winners at every boundary
// and a rejected append performs zero file/offset/state change. Zero means
// that kind of quota is unbounded. Usage counts every byte-bearing row whose
// physical bytes may still occupy the spool: active and finalized sessions
// (including already-expired ones — expiry alone never removes bytes) AND
// deleting tombstones whose durable unlink has not yet been completed (the
// documented policy: the row is removed only after the file is durably gone,
// so a restart or a failed cleanup can never bypass a quota by releasing bytes
// that still occupy the disk); creating rows carry offset 0. A rejected append
// is decided BEFORE the spool file is opened or any source byte is read, so an
// attacker with tiny remaining quota cannot stream payload bytes into the
// spool first.
type Limits struct {
	// MaxUploadBytes bounds a single session's cumulative durable offset.
	MaxUploadBytes int64
	// MaxRepositoryBytes bounds the sum of byte-bearing offsets for one
	// repository across concurrent and restarted processes.
	MaxRepositoryBytes int64
	// MaxTotalStagingBytes bounds the sum of byte-bearing offsets across
	// every repository.
	MaxTotalStagingBytes int64
}

// Session is the durable upload-session snapshot returned by Service
// methods. Timestamps are native time.Time values derived from signed Unix
// nanoseconds persisted in SQLite.
type Session struct {
	ID        string
	Repo      string
	Actor     string
	State     State
	Offset    int64
	Size      int64
	Digest    string
	BeeRef    string
	MediaType string
	// The unforgeable claim identity handed ONLY to the single finalization
	// winner (see Token). Only the winner may ReleaseClaim or complete
	// (MarkFinalized) its claim; it is never surfaced by any read path and
	// never appears in any error surface.
	Token     string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Sentinel errors. Every sentinel has fixed, data-free text: no root or
// database paths, no DSNs, no session IDs / repo / actor / digest / ref
// values, no SQL, and no raw dependency detail ever appear in Error() output
// or in any exported accessor.
var (
	// ErrNotFound reports that no session exists for the caller. It is also
	// the ONE observable identity for owner/repo mismatch: a caller can never
	// distinguish "no such upload" from "exists but not yours" by any error
	// surface (value, text, Is/As/Unwrap, formatting, or JSON).
	ErrNotFound = errors.New("staging upload not found")
	// ErrExpired reports a session whose canonical expiry has passed.
	ErrExpired = errors.New("staging upload expired")
	// ErrOffsetMismatch reports an append whose expected offset does not
	// equal the durable committed offset.
	ErrOffsetMismatch = errors.New("staging upload offset mismatch")
	// ErrInvalidInput reports a caller-supplied value that fails the bounded
	// canonical grammar (ID, repo, actor, digest, Bee ref, media type, TTL,
	// or size), or an impossible arithmetic request.
	ErrInvalidInput = errors.New("staging invalid input")
	// ErrInvalidState reports an operation impossible in the session's
	// current lifecycle state.
	ErrInvalidState = errors.New("staging invalid upload state")
	// ErrTooLarge reports an append that would exceed the caller's maximum
	// byte bound or overflow the durable offset.
	ErrTooLarge = errors.New("staging upload exceeds maximum size")
	// ErrDependency reports a filesystem or database failure. The raw cause
	// is retained privately for server-side diagnosis and never surfaces.
	ErrDependency = errors.New("staging backend unavailable")
	// ErrSourceRead reports a failure of the caller-supplied reader during a
	// streaming append; no partial bytes are ever accepted.
	ErrSourceRead = errors.New("staging source read failed")
	// ErrFinalizeConflict reports a second finalization whose metadata
	// differs from the already-finalized row.
	ErrFinalizeConflict = errors.New("staging upload already finalized with different metadata")
)

// typedError reports a fixed-text sentinel. Error() and Unwrap() expose only
// the sentinel; the private cause survives only behind a closure so that no
// formatting or reflection surface (%v, %+v, %#v, JSON) can ever print
// paths, DSNs, SQL, or raw causes. causeOf recovers it for package-internal
// diagnosis.
type typedError struct {
	sentinel error
	cause    func() error
}

func (e *typedError) Error() string { return e.sentinel.Error() }

func (e *typedError) Unwrap() error { return e.sentinel }

func typed(sentinel, cause error) error {
	if cause == nil {
		return sentinel
	}
	return &typedError{sentinel: sentinel, cause: func() error { return cause }}
}

// causeOf returns the private diagnostic cause of a typed error, or nil.
// The returned value must never be rendered into a caller-visible error.
func causeOf(err error) error {
	var te *typedError
	if errors.As(err, &te) && te.cause != nil {
		return te.cause()
	}
	return nil
}

// ctxOr is the context-authority gate for every context-capable call: when
// the live context is done, the EXACT context error (context.Canceled or
// context.DeadlineExceeded) is the only sanctioned result — the raw driver
// error is dropped and never wrapped or echoed. When the context is alive
// the raw error is returned unchanged (callers wrap it with their sentinel
// after this gate). Attacker-controlled sentinels carried inside a raw
// error can therefore never masquerade as a context result: only ctx.Err()
// of the actual request context decides.
func ctxOr(err error, ctx context.Context) error {
	if cerr := ctx.Err(); cerr != nil {
		return cerr
	}
	return err
}

// depErr is ctxOr followed by the data-free ErrDependency wrap: a canceled
// context surfaces as the exact context error, everything else becomes the
// fixed dependency sentinel with the raw cause retained privately.
func depErr(err error, ctx context.Context) error {
	if cerr := ctx.Err(); cerr != nil {
		return cerr
	}
	return typed(ErrDependency, err)
}

// copyBufSize is the fixed streaming-copy buffer used by Append. Bounded
// memory by construction: no production read path allocates by body size.
const copyBufSize = 32 * 1024

// validID reports whether id is a canonical unpredictable server-side
// identifier: exactly 64 lowercase ASCII hex characters (32 bytes of
// crypto/rand), containing no separators, dots, NUL, Unicode, or alternate
// separators. This is the ONLY form ever accepted; any caller-supplied
// deviation is rejected before database or filesystem access.
func validateID(id string) error {
	return validateHex(id, 64)
}

func validateHex(s string, n int) error {
	if len(s) != n {
		return ErrInvalidInput
	}
	for i := 0; i < n; i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return ErrInvalidInput
		}
	}
	return nil
}

// validateRepo enforces the bounded canonical repository grammar: lowercase
// ASCII alphanumerics, dots, underscores, and hyphens separated by single
// slashes; no empty or dot segments (so no ".."), no "//", no leading or
// trailing slash; at most 200 bytes.
func validateRepo(repo string) error {
	if len(repo) == 0 || len(repo) > 200 {
		return ErrInvalidInput
	}
	segStart := true
	for i := 0; i < len(repo); i++ {
		c := repo[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			segStart = false
		case c == '.':
			if segStart || (i > 0 && repo[i-1] == '.') {
				return ErrInvalidInput
			}
		case c == '_' || c == '-':
			if segStart {
				return ErrInvalidInput
			}
		case c == '/':
			if segStart {
				return ErrInvalidInput
			}
			segStart = true
		default:
			return ErrInvalidInput
		}
	}
	if segStart {
		return ErrInvalidInput
	}
	return nil
}

// validateActor enforces the bounded canonical actor grammar: an ASCII
// alphanumeric first character, then ASCII alphanumerics plus ':', '_', '@',
// '.', '-'; no separators or dot-only segments; at most 200 bytes.
func validateActor(actor string) error {
	if len(actor) == 0 || len(actor) > 200 {
		return ErrInvalidInput
	}
	if !isAlnum(actor[0]) {
		return ErrInvalidInput
	}
	for i := 0; i < len(actor); i++ {
		c := actor[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == ':' || c == '_' || c == '@' || c == '.' || c == '-':
		default:
			return ErrInvalidInput
		}
	}
	return nil
}

func isAlnum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// validateDigest enforces the canonical sha256 digest grammar:
// "sha256:" followed by exactly 64 lowercase hex bytes.
func validateDigest(digest string) error {
	if len(digest) != len("sha256:")+64 || digest[:7] != "sha256:" {
		return ErrInvalidInput
	}
	return validateHex(digest[7:], 64)
}

// validateBeeRef enforces the canonical Bee reference grammar: exactly 64
// lowercase hex bytes (a 32-byte swarm reference).
func validateBeeRef(ref string) error {
	return validateHex(ref, 64)
}

// validateMediaType enforces the bounded canonical media-type grammar used
// for finalized blobs: lowercase ASCII alphanumerics, '.', '+', '-', '_',
// '/' separators; at most 200 bytes.
func validateMediaType(media string) error {
	if len(media) == 0 || len(media) > 200 {
		return ErrInvalidInput
	}
	for i := 0; i < len(media); i++ {
		c := media[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '.' || c == '+' || c == '-' || c == '_' || c == '/':
		default:
			return ErrInvalidInput
		}
	}
	return nil
}
