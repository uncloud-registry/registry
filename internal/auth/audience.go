package auth

import (
	"errors"
	"fmt"
	"strings"
)

// ParseAudienceAllowlist parses the REGISTRY_TOKEN_AUDIENCE value as a STRICT
// comma-separated allowlist of exact registry hosts. Every element must be a
// nonblank literal hostname: no surrounding or interior whitespace (elements
// are never trimmed or normalized), no wildcard, no scheme/path characters, no
// empty labels, no duplicate entries, and the whole value must not be blank.
// Hosts may carry a numeric port. The returned slice preserves the configured
// order and exact spelling; each element becomes an exact-match allowlist
// entry for verifier selection.
func ParseAudienceAllowlist(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("REGISTRY_TOKEN_AUDIENCE must not be empty")
	}
	parts := strings.Split(raw, ",")
	seen := make(map[string]struct{}, len(parts))
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			return nil, errors.New("REGISTRY_TOKEN_AUDIENCE contains a blank element")
		}
		if part != strings.TrimSpace(part) {
			return nil, fmt.Errorf("REGISTRY_TOKEN_AUDIENCE element %q must not contain surrounding whitespace", part)
		}
		if err := validateAudienceHost(part); err != nil {
			return nil, fmt.Errorf("REGISTRY_TOKEN_AUDIENCE element %q: %w", part, err)
		}
		if _, dup := seen[part]; dup {
			return nil, fmt.Errorf("REGISTRY_TOKEN_AUDIENCE contains duplicate host %q", part)
		}
		seen[part] = struct{}{}
		out = append(out, part)
	}
	return out, nil
}

// validateAudienceHost enforces the exact registry-host grammar: a lowercase
// DNS-style hostname (labels of [a-z0-9-], no leading/trailing hyphen, no
// empty label) with an optional numeric port. Uppercase is rejected so that
// allowlist membership and token service claims cannot diverge through case
// folding.
func validateAudienceHost(host string) error {
	if strings.ContainsAny(host, " \t\r\n/\\@*") {
		return fmt.Errorf("invalid registry host: contains forbidden characters")
	}
	h, port, hasPort := strings.Cut(host, ":")
	if hasPort {
		if port == "" {
			return fmt.Errorf("invalid registry host: empty port")
		}
		for _, r := range port {
			if r < '0' || r > '9' {
				return fmt.Errorf("invalid registry host: port must be numeric")
			}
		}
	}
	if h == "" {
		return fmt.Errorf("invalid registry host: empty host part")
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" {
			return fmt.Errorf("invalid registry host: empty label")
		}
		if len(label) > 63 {
			return fmt.Errorf("invalid registry host: label exceeds 63 characters")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("invalid registry host: label %q starts or ends with a hyphen", label)
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return fmt.Errorf("invalid registry host %q: hostnames must be lowercase alphanumeric with hyphens", host)
			}
		}
	}
	return nil
}
