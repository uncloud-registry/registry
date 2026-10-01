package publish

import (
	"errors"
	"strings"
)

// Canonical full-feed wire form.
//
// The ONLY accepted canonical wire format for a repository-state feed is
//
//	feed://<40 lowercase hex owner>/<64 lowercase hex topic>
//
// with exactly:
//   - the literal prefix "feed://",
//   - a 40-character owner address in lowercase hexadecimal (no "0x", no
//     checksum casing, no leading/trailing whitespace, no escaping),
//   - exactly one "/" separator,
//   - a 64-character topic digest in lowercase hexadecimal,
//   - nothing else (no query, no fragment, no extra slash, no empty segments).
//
// Any other form — shorter/longer owner, uppercase hex, a "0x" prefix, extra
// or absent slashes, whitespace, escaping, or a misplaced separator — is
// invalid and is REJECTED before hashing or reservation. In particular an
// invalid topic must never be silently lowered/collapsed into a valid hash.

const (
	feedOwnerHexLen  = 40
	feedTopicHexLen  = 64
	canonicalFeedLen = len("feed://") + feedOwnerHexLen + 1 + feedTopicHexLen // 7 + 40 + 1 + 64 = 112
)

// ErrNotCanonicalFeed is returned by ParseCanonicalFeed for any input that is
// not exactly the canonical full-feed wire form. It is data-free.
var ErrNotCanonicalFeed = errors.New("topic is not a canonical full feed reference")

// CanonicalFeedPrefix is the literal canonical feed scheme+authority prefix.
const CanonicalFeedPrefix = "feed://"

// ParseCanonicalFeed validates that s is EXACTLY the canonical full-feed wire
// form and returns the canonical owner (40 lowercase hex) and topic (64
// lowercase hex) segments. Any deviation is errors.Is(ErrNotCanonicalFeed).
// It is the single strict parser shared by ValidateCommitRequest, the request
// hash, stored-result validation, the signer, and the DB-contract tests.
func ParseCanonicalFeed(s string) (owner, topic string, err error) {
	if len(s) != canonicalFeedLen {
		return "", "", ErrNotCanonicalFeed
	}
	if !strings.HasPrefix(s, CanonicalFeedPrefix) {
		return "", "", ErrNotCanonicalFeed
	}
	// rest is "<40 hex owner>/<64 hex topic>", total 40+1+64 = 105 chars.
	rest := s[len(CanonicalFeedPrefix):]
	if rest[feedOwnerHexLen] != '/' {
		return "", "", ErrNotCanonicalFeed
	}
	owner = rest[:feedOwnerHexLen]
	topic = rest[feedOwnerHexLen+1:]
	if !isLowerHex(owner, feedOwnerHexLen) {
		return "", "", ErrNotCanonicalFeed
	}
	if !isLowerHex(topic, feedTopicHexLen) {
		return "", "", ErrNotCanonicalFeed
	}
	return owner, topic, nil
}

// IsCanonicalFeed reports whether s is exactly the canonical full-feed wire
// form (a cheap wrapper over ParseCanonicalFeed).
func IsCanonicalFeed(s string) bool {
	_, _, err := ParseCanonicalFeed(s)
	return err == nil
}

// CanonicalTopic returns the canonical byte-identical form of a valid topic.
//
// Callers MUST validate the topic with ParseCanonicalFeed/ValidateCommitRequest
// BEFORE invoking this; the signer, request hash, and stored-result
// validation all operate on already-canonical wire values. For such inputs the
// canonical form is the input itself, O(1) with no re-encoding. (It never
// invents a canonical form from an invalid topic.)
func CanonicalTopic(topic string) string {
	if IsCanonicalFeed(topic) {
		return topic
	}
	// Preserve the previous lenient lowercasing for the tiny set of legacy
	// call sites that fed a non-wire value into comparisons; validation gates
	// reject such topics before they reach a hash or reservation, so this
	// branch never affects identity decisions made by the signer.
	return strings.ToLower(topic)
}

// isLowerHex reports whether b has exactly n lowercase hexadecimal characters.
func isLowerHex(b string, n int) bool {
	if len(b) != n {
		return false
	}
	for i := 0; i < n; i++ {
		c := b[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// CanonicalReference returns the canonical lowercase form of a 64-hex object
// reference. Uppercase hex is accepted as input and canonicalized to
// lowercase (the hash and stored result always use the lowercase form).
func CanonicalReference(ref string) string {
	return strings.ToLower(ref)
}
