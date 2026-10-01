package auth

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseAudienceAllowlistValid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw  string
		want []string
	}{
		{"alice.uncloud-registry.com", []string{"alice.uncloud-registry.com"}},
		{"alice.uncloud-registry.com,bob.uncloud-registry.com", []string{"alice.uncloud-registry.com", "bob.uncloud-registry.com"}},
		{"localhost:8080", []string{"localhost:8080"}},
		{"a.example.test,b.example.test,c.example.test", []string{"a.example.test", "b.example.test", "c.example.test"}},
	}
	for _, tc := range cases {
		got, err := ParseAudienceAllowlist(tc.raw)
		if err != nil {
			t.Errorf("ParseAudienceAllowlist(%q): %v", tc.raw, err)
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("ParseAudienceAllowlist(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}

func TestParseAudienceAllowlistRejectsMalformed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw  string
		want string
	}{
		{"", "empty"},
		{"   ", "empty"},
		{",", "blank"},
		{"a,,b", "blank"},
		{",a", "blank"},
		{"a,", "blank"},
		{" a", "whitespace"},
		{"a ", "whitespace"},
		{"a, b", "whitespace"},
		{"a,b,a", "duplicate"},
		{"a,a", "duplicate"},
		{"*", "forbidden"},
		{"a,*", "forbidden"},
		{"a://evil", "forbidden"},
		{"bad host", "forbidden"},
		{"a/b", "forbidden"},
		{"a@b", "forbidden"},
		{"Evil.Example", "lowercase"},
		{"a..b", "empty label"},
		{".a", "empty label"},
		{"a.", "empty label"},
		{"-a", "hyphen"},
		{"a-", "hyphen"},
		{"a:b:c", "numeric"},
		{"a:", "empty port"},
		{"a:80x", "numeric"},
		{"a:b:80", "numeric"},
		{"A", "lowercase"},
		{"a b.com", "forbidden"},
	}
	for _, tc := range cases {
		_, err := ParseAudienceAllowlist(tc.raw)
		if err == nil {
			t.Errorf("ParseAudienceAllowlist(%q) must be rejected", tc.raw)
			continue
		}
		if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
			t.Errorf("ParseAudienceAllowlist(%q) error %q does not contain %q", tc.raw, err, tc.want)
		}
	}
}
