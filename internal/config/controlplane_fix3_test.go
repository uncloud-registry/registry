package config

import (
	"testing"
)

// ---------------------------------------------------------------------------
// Fix round 3/5: scoped IPv6 external origins
// ---------------------------------------------------------------------------
//
// A public ExternalURL must never carry an IPv6 zone identifier: a zone (e.g.
// fe80::1%eth0, arriving as %25eth0) scopes an address to a local interface,
// which is not a canonical public origin and must not be accepted as one. The
// encoded form decodes to a literal '%' in the host during URL parsing, so
// validation rejects any host containing '%' (and the raw non-encoded form
// fails URL parsing outright at Load).

func TestExternalURLRejectsIPv6ZoneIdentifiers(t *testing.T) {
	// Every entry carries an IPv6 zone identifier and must be REJECTED, in
	// whatever encoding reaches the URL/validation layer.
	zoneURLs := []string{
		"https://[fe80::1%25eth0]:8080",   // canonical encoded zone
		"https://[fe80::1%25eth0]",        // encoded zone, no port
		"https://[fe80::1%2525eth0]:8080", // double-encoded zone (still '%' after one decode)
		"http://[fe80::a%25wlan0]:8080",   // another zone on http
		"https://[2001:db8::1%25vlan1]",   // zone even on a global-style address
		"https://[fe80::1%eth0]:8080",     // raw non-encoded escape -> url.Parse rejects
	}
	for _, u := range zoneURLs {
		if _, err := loadValidated(t, prodEnv(map[string]string{envExternalURL: u})); err == nil {
			t.Errorf("scoped IPv6 external URL %q must be rejected", u)
		}
	}
}

// TestExternalURLAcceptsZoneFreeIPv6 ensures genuinely zone-free global IPv6
// origins still load, validate, and round-trip as bracketed origins.
func TestExternalURLAcceptsZoneFreeIPv6(t *testing.T) {
	for _, u := range []string{
		"https://[2001:db8::1]",
		"https://[2606:4700:4700::1111]:8443",
		"https://[2001:db8::1]:443",
		"https://[::1]:8443",
	} {
		cfg, err := loadValidated(t, prodEnv(map[string]string{envExternalURL: u}))
		if err != nil {
			t.Errorf("zone-free IPv6 external URL %q must be accepted: %v", u, err)
			continue
		}
		if cfg.ExternalURL == nil {
			t.Errorf("zone-free IPv6 external URL %q not parsed", u)
		}
	}
}

// TestExternalOriginScopedIPv6RoundTrip verifies ExternalOrigin builds valid
// bracketed zone-free IPv6 origins (never hand-constructing a host) while
// dropping only the scheme-default port and keeping non-default ports.
func TestExternalOriginScopedIPv6RoundTrip(t *testing.T) {
	cases := map[string]string{
		"https://[2001:db8::1]":               "https://[2001:db8::1]",
		"https://[2001:db8::1]:8443":          "https://[2001:db8::1]:8443",
		"https://[2001:db8::1]:443":           "https://[2001:db8::1]",
		"http://[2001:db8::1]:80":             "http://[2001:db8::1]",
		"http://[::1]:80":                     "http://[::1]",
		"https://[2606:4700:4700::1111]:9443": "https://[2606:4700:4700::1111]:9443",
		"https://[::ffff:10.0.0.1]:9443":      "https://[::ffff:10.0.0.1]:9443",
	}
	for raw, want := range cases {
		cfg := &ControlPlaneConfig{Mode: ModeProduction, ExternalURL: mustURL(raw)}
		if got := cfg.ExternalOrigin(); got != want {
			t.Errorf("ExternalOrigin(%q) = %q, want %q", raw, got, want)
		}
	}
}
