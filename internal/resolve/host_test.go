package resolve

import (
	"context"
	"testing"
)

// TestNormalizeRegistryHost covers the canonical service-name contract at the
// request boundary: lowercase hostname, preserved port, bracketed IPv6 with
// port, bare IPv6 bracketed, single trailing root dot stripped, and malformed
// or empty hosts rejected.
func TestNormalizeRegistryHost(t *testing.T) {
	t.Parallel()

	valid := []struct {
		raw  string
		want string
	}{
		{"Example.COM", "example.com"},
		{"Example.COM:5000", "example.com:5000"},
		{"alice.example.com.", "alice.example.com"},
		{"ALICE.Example.COM.:5000", "alice.example.com:5000"},
		{"registry.example.com", "registry.example.com"},
		{"registry.example.com:443", "registry.example.com:443"},
		{"[2001:db8::1]:5000", "[2001:db8::1]:5000"},
		{"[2001:DB8::1]:5000", "[2001:db8::1]:5000"},
		{"2001:db8::1", "[2001:db8::1]"},
		{"[2001:db8::1]", "[2001:db8::1]"},
		{"192.168.1.10", "192.168.1.10"},
		{"192.168.1.10:5000", "192.168.1.10:5000"},
		{"localhost", "localhost"},
	}
	for _, c := range valid {
		got, err := NormalizeRegistryHost(c.raw)
		if err != nil {
			t.Errorf("NormalizeRegistryHost(%q) unexpected error: %v", c.raw, err)
			continue
		}
		if got != c.want {
			t.Errorf("NormalizeRegistryHost(%q) = %q, want %q", c.raw, got, c.want)
		}
	}

	invalid := []string{
		"",
		"   ",
		"exa mple.com",
		"exa\tmple.com",
		"exa\nmple.com",
		"example.com:abc",
		"example.com:99999",
		"example.com:0",
		"example.com:",
		"example..com",
		".example.com",
		"example.com:5000:6000",
		"exa[mple.com",
		"[not-an-ip]:5000",
		"-example.com",
		"example-.com",
		"example.com:12a4",
	}
	for _, raw := range invalid {
		if got, err := NormalizeRegistryHost(raw); err == nil {
			t.Errorf("NormalizeRegistryHost(%q) = %q, want error", raw, got)
		}
	}
}

// TestStaticRegistryResolveUsesNormalizedHost proves a configured static host
// lookup succeeds for a raw request host that is uppercase or carries a
// trailing root dot: normalization happens at the request boundary BEFORE the
// configured-map lookup, so operator-configured canonical hosts match
// regardless of client casing or dot suffixes.
func TestStaticRegistryResolveUsesNormalizedHost(t *testing.T) {
	t.Parallel()

	resolver := RegistryResolver{
		Registries: StaticRegistryIdentityResolver{
			Hosts: map[string]RegistryIdentity{
				"alice.example.com:5000": {Host: "alice.example.com:5000", Owner: "0xalice", RegistryID: 7},
				"bob.example.com":        {Host: "bob.example.com", Owner: "0xbob", RegistryID: 8},
				"2001:db8::1":            {Host: "[2001:db8::1]", Owner: "0xipv6", RegistryID: 9},
			},
		},
	}

	cases := []struct {
		raw      string
		wantHost string
	}{
		{"ALICE.Example.COM:5000", "alice.example.com:5000"},
		{"ALICE.Example.COM.:5000", "alice.example.com:5000"},
		{"BOB.example.com.", "bob.example.com"},
		{"bob.example.com", "bob.example.com"},
		{"[2001:db8::1]:5000x", ""}, // malformed port: must NOT resolve
	}
	for _, c := range cases {
		id, err := resolver.ResolveRegistry(context.Background(), c.raw)
		if c.wantHost == "" {
			if err == nil {
				t.Errorf("ResolveRegistry(%q) = %+v, want error", c.raw, id)
			}
			continue
		}
		if err != nil {
			t.Errorf("ResolveRegistry(%q) unexpected error: %v", c.raw, err)
			continue
		}
		if id.Host != c.wantHost {
			t.Errorf("ResolveRegistry(%q).Host = %q, want %q", c.raw, id.Host, c.wantHost)
		}
	}
}

// TestStaticRegistryResolveStripsTrailingDotFromConfiguredHost proves that a
// request host ending in a dot still lands on the canonical configured key.
func TestStaticRegistryResolveStripsTrailingDotFromConfiguredHost(t *testing.T) {
	t.Parallel()

	resolver := RegistryResolver{
		Registries: StaticRegistryIdentityResolver{
			Hosts: map[string]RegistryIdentity{
				"cd.example.com": {Host: "cd.example.com", Owner: "0xcd", RegistryID: 10},
			},
		},
	}
	id, err := resolver.ResolveRegistry(context.Background(), "CD.EXAMPLE.COM.")
	if err != nil {
		t.Fatalf("trailing-dot uppercase host must resolve: %v", err)
	}
	if id.Host != "cd.example.com" {
		t.Fatalf("Host = %q, want %q", id.Host, "cd.example.com")
	}
}
