package resolve

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// NormalizeRegistryHost canonicalizes a registry hostname AT THE REQUEST
// BOUNDARY so registry resolution and token-service comparison always use the
// canonical service name, regardless of client casing, port spelling, IPv6
// bracketing, or a fully-qualified trailing root dot:
//
//   - the hostname is lowercased and a single trailing root dot is stripped
//     ("Example.COM." -> "example.com"),
//   - a port is preserved exactly ("example.com:5000" stays "example.com:5000"),
//   - IPv6 literals are bracketed whenever a port is present ("[2001:db8::1]:5000")
//     and also when bare, because the bracketed form is the only unambiguous
//     HTTP Host form for IPv6,
//   - IPv4 literals are canonicalized ("192.168.1.10" stays as-is),
//   - empty, whitespace, or structurally invalid hosts are rejected.
//
// Operators configure canonical hosts (lowercase hostname, explicit port);
// after this normalization the configured-map lookup is exact. A malformed
// host never reaches a resolver — it fails here, before any network or
// configured lookup.
func NormalizeRegistryHost(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("registry host is empty")
	}
	// Whitespace or control characters anywhere disqualify the value; the
	// surrounding trim above already removed leading/trailing space.
	if strings.ContainsAny(s, " \t\r\n\x00") {
		return "", fmt.Errorf("registry host contains whitespace")
	}

	// A bracketed literal ("[2001:db8::1]" or "[2001:db8::1]:5000") is
	// handled explicitly: brackets wrap ONLY an IP literal, never a hostname,
	// and SplitHostPort alone cannot parse a bracketed value without a port.
	if strings.HasPrefix(s, "[") {
		closeIdx := strings.Index(s, "]")
		if closeIdx < 0 {
			return "", fmt.Errorf("registry host has an unbalanced bracket")
		}
		inner := s[1:closeIdx]
		if strings.Contains(inner, "]") || strings.Contains(inner, "[") {
			return "", fmt.Errorf("registry host has an unbalanced bracket")
		}
		ip := net.ParseIP(inner)
		if ip == nil {
			return "", fmt.Errorf("registry host brackets a non-IP literal")
		}
		rest := s[closeIdx+1:]
		if rest == "" {
			// "[2001:db8::1]": bracketed with no port.
			if ip.To4() != nil {
				return "", fmt.Errorf("registry host brackets an IPv4 literal without a port")
			}
			return "[" + ip.String() + "]", nil
		}
		if !strings.HasPrefix(rest, ":") || rest == ":" {
			return "", fmt.Errorf("registry host brackets a literal with a malformed port")
		}
		return canonicalHostPort(inner, rest[1:])
	}

	if host, port, err := net.SplitHostPort(s); err == nil {
		return canonicalHostPort(host, port)
	}

	// No port. The whole value is a host: hostname, IPv4, or bare IPv6.
	if ip := net.ParseIP(s); ip != nil {
		if ip.To4() != nil {
			return ip.String(), nil
		}
		return "[" + ip.String() + "]", nil
	}

	return normalizeHostname(s)
}

// canonicalHostPort joins a validated host and port into the canonical
// registry-host form: lowercase hostname with trailing dot stripped, IPv6
// bracketed. It rejects structurally invalid ports (non-numeric, empty,
// zero, or above 65535) before any resolver sees them.
func canonicalHostPort(host string, port string) (string, error) {
	if port == "" {
		return "", fmt.Errorf("registry host port is empty")
	}
	if port[0] < '0' || port[0] > '9' {
		return "", fmt.Errorf("registry host port is not numeric")
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return "", fmt.Errorf("registry host port is not numeric")
	}
	if n < 1 || n > 65535 {
		return "", fmt.Errorf("registry host port %d is out of range", n)
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			return ip.String() + ":" + port, nil
		}
		return "[" + ip.String() + "]:" + port, nil
	}
	h, err := normalizeHostname(host)
	if err != nil {
		return "", err
	}
	return h + ":" + port, nil
}

// normalizeHostname validates and canonicalizes a bare hostname: lowercase,
// trailing root dot stripped, labels non-empty and RFC-1123 shaped
// (alphanumerics and hyphens, no leading/trailing hyphen), all other
// characters rejected.
func normalizeHostname(host string) (string, error) {
	h := strings.ToLower(host)
	for strings.HasSuffix(h, ".") {
		h = strings.TrimSuffix(h, ".")
	}
	if h == "" {
		return "", fmt.Errorf("registry host is empty after normalization")
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" {
			return "", fmt.Errorf("registry host contains an empty label")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("registry host label %q has a leading or trailing hyphen", label)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return "", fmt.Errorf("registry host contains an invalid character %q", c)
			}
		}
	}
	return h, nil
}
