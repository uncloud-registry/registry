package registry

import (
	"strings"
)

// Accept (RFC 9110 §12.5.1) negotiation for manifest pulls.
//
// The stored media type this registry serves is always a plain type/subtype
// (e.g. "application/vnd.oci.image.index.v1+json") with NO media type
// parameters. Per RFC 9110 §12.5.1 a media-range matches a media type when the
// type and subtype match (with HTTP wildcards) AND every non-q parameter of
// the range equals a parameter of the media type; a range carrying a parameter
// the representation lacks therefore does NOT match an unparameterized stored
// type.

// mediaRange is one well-formed RFC 9110 media-range: type/subtype (lowercased,
// with "*" wildcards) plus its non-q parameters (as parsed, lowercased names)
// and its weight (default 1).
type mediaRange struct {
	rType  string
	rSub   string
	params map[string]string
	q      float64
}

// acceptAcceptsValues reports whether the request's Accept header field (ALL
// field lines, in order) permits serving the exact stored media type, per RFC
// 9110 §5.3 field-combining semantics: an Accept field is a list-based field
// whose multiple field lines combine into one comma-separated list in order.
// An ABSENT field (no field lines) accepts any representation; a PRESENT field
// that is empty or wholly malformed does not.
func acceptAcceptsValues(values []string, storedMediaType string) bool {
	if len(values) == 0 {
		return true
	}
	return acceptAccepts(strings.Join(values, ","), storedMediaType)
}

// acceptAccepts reports whether the given (already combined) Accept header
// value permits serving the exact stored media type, per RFC 9110 §12.5.1 and
// §12.4.2:
//
//   - a header that is empty, whitespace-only, or yields ZERO well-formed
//     media ranges must NOT serve — a present-but-empty or all-malformed Accept
//     expresses a preference and, per the documented negotiation contract,
//     insists on a representation that nothing matches;
//   - a malformed media range (syntax that does not satisfy the media-range
//     ABNF, or a parameter that is not a token "=" (token/quoted-string)) is
//     REJECTED rather than having its malformed parameters dropped to broaden
//     the match; it never matches a broader type;
//   - each well-formed media-range matches the stored type by exact type/
//     subtype (with HTTP wildcards) AND by parameters: every non-q parameter
//     in the range must equal a parameter of the stored type, so an
//     unparameterized stored type never matches a range carrying a non-q
//     parameter;
//   - among the matching ranges the MOST SPECIFIC governs: an exact type/
//     subtype beats a type wildcard beats the global wildcard, and MORE
//     matching parameters raise precedence (RFC 9110 §12.5.1); the governing
//     range's q is then applied — q==0 excludes, q>0 serves — regardless of
//     header order;
//   - if NO well-formed range matches, the representation is refused.
//
// "q" is parsed against the EXACT RFC 9110 §12.4.2 qvalue ABNF (see
// parseQvalue); a malformed or out-of-range q makes that range malformed.
// This function is data-free — it never echoes any Accept value.
func acceptAccepts(header, storedMediaType string) bool {
	ranges := parseMediaRanges(header)
	if len(ranges) == 0 {
		// Present-but-empty or all-malformed: nothing acceptable is expressed.
		return false
	}
	sType, sSub, sParams, ok := parseMediaType(storedMediaType)
	if !ok {
		return false
	}
	bestBase := -1
	bestParams := -1
	excluded := false
	for _, r := range ranges {
		base, matchedParams := mediaRangeMatches(r, sType, sSub, sParams)
		if base < 0 {
			continue
		}
		// (baseSpecificity, matchedParamCount) lexicographic precedence.
		if base > bestBase || (base == bestBase && matchedParams > bestParams) {
			bestBase, bestParams = base, matchedParams
			excluded = r.q <= 0
		} else if base == bestBase && matchedParams == bestParams && r.q <= 0 {
			excluded = true
		}
	}
	if bestBase < 0 {
		return false
	}
	return !excluded
}

// parseMediaRanges parses a combined Accept header value into its well-formed
// media ranges in order. Empty comma segments are tolerated (HTTP #rule list
// elements may be empty); a range whose grammar does not satisfy the
// media-range ABNF is REJECTED (dropped, never broadened). The returned slice
// is therefore only the well-formed subset; an empty returned slice means the
// header was empty, whitespace-only, or wholly malformed.
func parseMediaRanges(header string) []mediaRange {
	var out []mediaRange
	for _, seg := range splitQuoted(header, ',') {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		if r, ok := parseMediaRange(seg); ok {
			out = append(out, r)
		}
	}
	return out
}

// parseMediaRange parses one media-range, returning ok=false when it does not
// satisfy the RFC 9110 media-range ABNF (or its q does not satisfy the exact
// qvalue ABNF, or a parameter is duplicated or malformed).
func parseMediaRange(item string) (mediaRange, bool) {
	base, paramPart, _ := strings.Cut(item, ";")
	t, sub, ok := splitTypeSubtype(base)
	if !ok {
		return mediaRange{}, false
	}
	if t == "*" && sub != "*" {
		// "*/subtype" is not a valid media range.
		return mediaRange{}, false
	}
	var params map[string]string
	if strings.TrimSpace(paramPart) != "" {
		p, ok := parseParams(paramPart)
		if !ok {
			return mediaRange{}, false
		}
		params = p
	}
	q := 1.0
	if raw, present := params["q"]; present {
		v, valid := parseQvalue(raw)
		if !valid {
			return mediaRange{}, false
		}
		q = v
		delete(params, "q")
	}
	return mediaRange{rType: t, rSub: sub, params: params, q: q}, true
}

// parseParams parses the ";"-separated parameter part of a media range into a
// name→value map (parameter names lowercased), rejecting malformed or
// duplicated parameters. Each parameter must be `token "=" ( token /
// quoted-string )`; an empty segment (the ABNF's optional [ parameter ]) is
// tolerated. The map includes the weight parameter "q", which the caller
// extracts and validates against the qvalue grammar. ok=false means the
// parameter list is malformed.
func parseParams(paramPart string) (map[string]string, bool) {
	params := make(map[string]string)
	for _, raw := range splitQuoted(paramPart, ';') {
		seg := strings.TrimSpace(raw)
		if seg == "" {
			continue
		}
		eq := indexOfUnquotedEq(seg)
		if eq < 0 {
			return nil, false
		}
		name := strings.TrimSpace(seg[:eq])
		if !isToken(name) {
			return nil, false
		}
		valRaw := strings.TrimSpace(seg[eq+1:])
		var val string
		if strings.HasPrefix(valRaw, `"`) {
			v, ok := parseQuotedString(valRaw)
			if !ok {
				return nil, false
			}
			val = v
		} else {
			if !isToken(valRaw) {
				return nil, false
			}
			val = valRaw
		}
		lname := strings.ToLower(name)
		if _, dup := params[lname]; dup {
			return nil, false
		}
		params[lname] = val
	}
	return params, true
}

// indexOfUnquotedEq returns the index of the first '=' that is outside a
// quoted-string, or -1 if none (a parameter requires exactly one such '=').
func indexOfUnquotedEq(s string) int {
	inQuote := false
	escaped := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			escaped = false
			continue
		}
		if inQuote {
			if c == '\\' {
				escaped = true
			} else if c == '"' {
				inQuote = false
			}
			continue
		}
		if c == '"' {
			inQuote = true
		} else if c == '=' {
			return i
		}
	}
	return -1
}

// parseQuotedString parses a quoted-string (RFC 9110 §5.6.4): it must start
// with '"', end with a terminating '"' as the final character, and support
// quoted-pair escapes `\X`. ok=false for an unterminated string or for
// trailing content after the closing quote.
func parseQuotedString(s string) (string, bool) {
	if len(s) < 2 || s[0] != '"' {
		return "", false
	}
	var b strings.Builder
	i := 1
	escaped := false
	for ; i < len(s); i++ {
		c := s[i]
		if escaped {
			// quoted-pair allows HTAB, SP, VCHAR, obs-text; a buildable byte
			// here is accepted (the source already passed walkStrict JSON
			// parsing, so the input is a valid header byte scan).
			b.WriteByte(c)
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if c == '"' {
			if i != len(s)-1 {
				// Trailing content after the closing quote is malformed.
				return "", false
			}
			return b.String(), true
		}
		b.WriteByte(c)
	}
	return "", false
}

// splitQuoted splits s on sep, ignoring separators inside quoted-strings and
// quoted-pair escapes.
func splitQuoted(s string, sep byte) []string {
	var parts []string
	start := 0
	inQuote := false
	escaped := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			escaped = false
			continue
		}
		if inQuote {
			if c == '\\' {
				escaped = true
			} else if c == '"' {
				inQuote = false
			}
			continue
		}
		if c == '"' {
			inQuote = true
		} else if c == sep {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// splitTypeSubtype splits a `type "/" subtype` media type/range base into its
// two token parts (subtype may itself contain no further "/"). ok=false on any
// malformed shape or non-token part. Wildcards ("*") are allowed as tokens and
// validated by the caller.
func splitTypeSubtype(base string) (t, sub string, ok bool) {
	base = strings.TrimSpace(base)
	slash := strings.IndexByte(base, '/')
	if slash <= 0 || slash == len(base)-1 || strings.IndexByte(base[slash+1:], '/') >= 0 {
		return "", "", false
	}
	t = base[:slash]
	sub = base[slash+1:]
	if !isTokenOrWildcard(t) || !isTokenOrWildcard(sub) {
		return "", "", false
	}
	return strings.ToLower(t), strings.ToLower(sub), true
}

func isTokenOrWildcard(s string) bool {
	if s == "*" {
		return true
	}
	return isToken(s)
}

// isToken reports whether s is exactly an RFC 9110 token (one or more tchar).
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isTChar(s[i]) {
			return false
		}
	}
	return true
}

// isTChar reports whether c is an RFC 9110 tchar.
func isTChar(c byte) bool {
	switch {
	case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

// parseMediaType parses a concrete (server-controlled) stored media type into
// its lowercased type/subtype and parameter map. No wildcards are permitted
// because this is a real representation type, not a range.
func parseMediaType(s string) (t, sub string, params map[string]string, ok bool) {
	base, paramPart, _ := strings.Cut(strings.TrimSpace(s), ";")
	t, sub, ok = splitTypeSubtype(base)
	if !ok || t == "*" || sub == "*" {
		return "", "", nil, false
	}
	params = map[string]string{}
	if strings.TrimSpace(paramPart) != "" {
		p, ok := parseParams(paramPart)
		if !ok {
			return "", "", nil, false
		}
		params = p
	}
	return t, sub, params, true
}

// mediaRangeMatches reports whether r matches a stored media type under RFC
// 9110 §12.5.1, returning the base specificity (2 exact, 1 type wildcard,
// 0 global wildcard) and the number of matching non-q parameters, or
// base<0 when it does NOT match. A range's non-q parameters must ALL be
// present and equal in the stored type; a stored type lacking a range
// parameter (the usual unparameterized case) does not match.
func mediaRangeMatches(r mediaRange, sType, sSub string, sParams map[string]string) (base int, matched int) {
	switch {
	case r.rType == "*" && r.rSub == "*":
		base = 0
	case r.rType == "*":
		return -1, 0
	case r.rType != sType:
		return -1, 0
	case r.rSub == "*":
		base = 1
	case r.rSub == sSub:
		base = 2
	default:
		return -1, 0
	}
	for name, val := range r.params {
		sv, ok := sParams[name]
		if !ok || sv != val {
			return -1, 0
		}
		matched++
	}
	return base, matched
}

// parseQvalue parses ONE HTTP qvalue against the exact RFC 9110 §12.4.2 ABNF:
//
//	qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )
//
// So an integral digit of 0 or 1, optionally followed by "." and AT MOST three
// fractional digits; after a "1." ONLY zeros are allowed (a weight never
// exceeds 1). The whole token must match — NaN, ".5", "+0.5", "-1", "2",
// "1e0", ".", a fourth fractional digit ("1.0000", "0.1234"), surplus
// precision, trailing garbage, an empty/malformed value, or a quoted-string q
// are all rejected. Leading/trailing whitespace is tolerated (the caller
// already trims the value). The returned weight is always in [0,1].
func parseQvalue(raw string) (float64, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, false
	}
	var weight float64
	switch s[0] {
	case '0':
	case '1':
		weight = 1
	default:
		// NaN, ".5", "+0.5", "-1", "2", "1e0", letters, symbols.
		return 0, false
	}
	whole := s[0]
	i := 1
	if i < len(s) && s[i] == '.' {
		i++
		fraction := 0
		place := 10.0
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			fraction++
			if fraction > 3 {
				return 0, false
			}
			if whole == '1' {
				// After "1." only zeros keep the weight at exactly 1.
				if s[i] != '0' {
					return 0, false
				}
			} else {
				weight += float64(s[i]-'0') / place
				place *= 10
			}
			i++
		}
	}
	if i != len(s) {
		// Trailing garbage: exponent, extra '.', sign, whitespace inside, etc.
		return 0, false
	}
	return weight, true
}
