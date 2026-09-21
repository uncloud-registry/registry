package controlplane

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

// Invite tokens are single-use, recipient-bound credentials. The server
// persists ONLY a one-way SHA-256 digest of the canonical raw token; the raw
// token itself exists exactly twice: in the invite-creation response and in the
// principal/registry-bound one-time UI flash page (see invite_flash.go). No
// other path — listing, detail, restart, or error — can ever reconstruct it.
//
// Canonical token syntax is strict: exactly 24 random bytes encoded with
// base64.RawURLEncoding (32 characters, no padding). Acceptance rejects any
// token that is malformed or non-canonical BEFORE hashing or querying, so
// garbage input never touches the database.

const (
	// inviteTokenBytes is the entropy of every invite token (192 bits).
	inviteTokenBytes = 24

	// inviteDefaultTTL is how long a created invite stays acceptable.
	inviteDefaultTTL = 7 * 24 * time.Hour

	// inviteMaxTTL bounds how far into the future an invite may expire, so
	// creation cannot mint effectively permanent credentials.
	inviteMaxTTL = 30 * 24 * time.Hour
)

// errInviteNotFound is the STABLE GENERIC sentinel for every acceptance and
// inspection failure: unknown invite, malformed token, wrong recipient,
// expired, revoked, accepted by someone else, or any other terminal state.
// Callers must map it to a single generic response and must never leak the
// cause text (which can distinguish invite states) to the wire.
var errInviteNotFound = errors.New("invite not found or no longer valid")

// errInviteCannotRevoke is returned when a revocation targets a non-pending
// (terminal) invite. It is deliberately not informative: outside callers map
// it to the same generic not-found response as errInviteNotFound.
var errInviteCannotRevoke = errors.New("invite cannot be revoked")

// errInviteRecipientRequired is returned when an invite is created without a
// recipient address. It is an inviter-input validation error (safe to show),
// unlike errInviteNotFound.
var errInviteRecipientRequired = errors.New("recipient email is required")

// NormalizeEmail is the single canonical email form used for identity
// semantics across account creation, login, invite creation, and invite
// acceptance binding: surrounding ASCII whitespace trimmed, then full
// lowercase. Provider-specific alias rewriting is deliberately NOT performed,
// so identity matching is purely textual and deterministic.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// isCanonicalInviteTokenText reports whether text is a canonical invite token:
// exactly 32 base64url characters that decode to exactly 24 bytes with zero
// trailing pad bits (re-encoding reproduces the input).
func isCanonicalInviteTokenText(text string) bool {
	if len(text) != 32 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil || len(decoded) != inviteTokenBytes {
		return false
	}
	return base64.RawURLEncoding.EncodeToString(decoded) == text
}

// ParseInviteToken validates that raw is a canonical invite token and returns
// the canonical form. It MUST be called before DigestInviteToken on any
// caller-supplied token: malformed or non-canonical input is rejected here,
// before any hashing or database query.
func ParseInviteToken(raw string) (string, error) {
	if !isCanonicalInviteTokenText(raw) {
		return "", errInviteNotFound
	}
	return raw, nil
}

// NewInviteToken generates a fresh raw invite token (24 cryptographically
// random bytes, canonical base64url text) and its one-way SHA-256 digest over
// the canonical token text. The digest is what gets persisted; the raw token
// is returned to the caller exactly once (invite-creation response / flash).
func NewInviteToken() (string, []byte, error) {
	raw := make([]byte, inviteTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	return token, sum[:], nil
}

// DigestInviteToken computes the persisted digest for a CANONICAL token text:
// SHA-256 over the canonical token bytes. It is irreversible — the digest can
// never be decoded back into the token, and callers must treat it as opaque
// secret material (never render it, log it, or put it in a DTO/error).
func DigestInviteToken(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}
