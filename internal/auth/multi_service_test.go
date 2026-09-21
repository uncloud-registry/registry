package auth

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

const (
	multiHostA = "alice.uncloud-registry.com"
	multiHostB = "bob.uncloud-registry.com"
	multiKeyID = "multi-key-1"
)

type countingKeySet struct {
	pub   ed25519.PublicKey
	calls int
}

func (c *countingKeySet) Key(_ context.Context, keyID string) (ed25519.PublicKey, error) {
	c.calls++
	if keyID != multiKeyID {
		return nil, errors.New("unknown kid")
	}
	return c.pub, nil
}

func newMultiTestPair(t *testing.T) (*countingKeySet, *RegistryTokenIssuer, *MultiServiceVerifier) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keys := &countingKeySet{pub: pub}
	issuer, err := NewRegistryTokenIssuer(priv, RegistryIssuer, multiKeyID)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}
	verifier, err := NewMultiServiceVerifier(keys, RegistryIssuer, []string{multiHostA, multiHostB})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	return keys, issuer, verifier
}

func issueForHost(t *testing.T, issuer *RegistryTokenIssuer, host, repo string, actions []Action) string {
	t.Helper()
	raw, err := issuer.Issue(context.Background(), RegistryTokenRequest{
		Subject:    "user:alice",
		Service:    host,
		Repository: repo,
		Actions:    actions,
		TTL:        time.Hour,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return raw
}

// TestMultiServiceVerifierHostSpecificTokens pins that each allowed host gets
// exact singleton audience validation: a token minted for host A verifies at
// host A, a token minted for host B verifies at host B, and cross-presenting a
// host A token at host B (or vice versa) fails even though both hosts are in
// the same process's allowlist.
func TestMultiServiceVerifierHostSpecificTokens(t *testing.T) {
	t.Parallel()
	keys, issuer, verifier := newMultiTestPair(t)

	repo := "backend/api"
	tokenA := issueForHost(t, issuer, multiHostA, repo, []Action{ActionPull})
	tokenB := issueForHost(t, issuer, multiHostB, repo, []Action{ActionPull})

	if _, err := verifier.Verify(tokenA, multiHostA, repo, ActionPull); err != nil {
		t.Fatalf("host A token at host A must verify: %v", err)
	}
	if _, err := verifier.Verify(tokenB, multiHostB, repo, ActionPull); err != nil {
		t.Fatalf("host B token at host B must verify: %v", err)
	}
	if _, err := verifier.Verify(tokenA, multiHostB, repo, ActionPull); !errors.Is(err, ErrServiceNotAllowed) && err == nil {
		t.Fatal("host A token at host B must fail")
	}
	if _, err := verifier.Verify(tokenB, multiHostA, repo, ActionPull); err == nil {
		t.Fatal("host B token at host A must fail")
	}

	// A token minted for a host that is NOT in the allowlist fails at every
	// allowed host (exact service-claim mismatch in the shared core).
	raw := issueForHost(t, issuer, "evil.example.test", repo, []Action{ActionPull})
	if _, err := verifier.Verify(raw, multiHostA, repo, ActionPull); err == nil {
		t.Fatal("token for an unlisted host must fail at allowed hosts")
	}
	// Presenting ANY token at the unlisted host ITSELF fails before verification.
	if _, err := verifier.Verify(raw, "evil.example.test", repo, ActionPull); !errors.Is(err, ErrServiceNotAllowed) {
		t.Fatalf("request to an unlisted host must fail with ErrServiceNotAllowed, got %v", err)
	}

	_ = keys
}

// TestMultiServiceVerifierFailsBeforeKeyLookup pins the fail-before-verify
// contract: a service outside the allowlist is rejected WITHOUT any token
// parsing or key resolution (the key set is never consulted).
func TestMultiServiceVerifierFailsBeforeKeyLookup(t *testing.T) {
	t.Parallel()
	keys, _, verifier := newMultiTestPair(t)

	if _, err := verifier.Verify("not-even-a-token", "outside.example.test", "repo", ActionPull); !errors.Is(err, ErrServiceNotAllowed) {
		t.Fatalf("outside-host request must fail with ErrServiceNotAllowed, got %v", err)
	}
	if keys.calls != 0 {
		t.Fatalf("key set consulted %d times for an outside-host request; want 0", keys.calls)
	}

	// Same for an inside-host request carrying garbage: key lookup happens, then
	// verification fails (the token is malformed) — but the allowlist itself is
	// not the denial.
	if _, err := verifier.Verify("not-even-a-token", multiHostA, "repo", ActionPull); err == nil {
		t.Fatal("garbage token at an allowed host must fail")
	}
}

// TestNewMultiServiceVerifierRejectsInvalidPins the constructor contract: nil
// keys, blank issuer, empty allowlist, and non-literal elements are refused.
func TestNewMultiServiceVerifierRejectsInvalid(t *testing.T) {
	t.Parallel()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	keys := testKeySet{"k": pub}

	if _, err := NewMultiServiceVerifier(nil, RegistryIssuer, []string{"a.example.test"}); err == nil {
		t.Fatal("nil key set must fail")
	}
	if _, err := NewMultiServiceVerifier(keys, "  ", []string{"a.example.test"}); err == nil {
		t.Fatal("blank issuer must fail")
	}
	if _, err := NewMultiServiceVerifier(keys, RegistryIssuer, nil); err == nil {
		t.Fatal("empty allowlist must fail")
	}
	if _, err := NewMultiServiceVerifier(keys, RegistryIssuer, []string{}); err == nil {
		t.Fatal("empty allowlist must fail")
	}
	if _, err := NewMultiServiceVerifier(keys, RegistryIssuer, []string{" a.example.test"}); err == nil {
		t.Fatal("whitespace-padded element must fail")
	}
	if _, err := NewMultiServiceVerifier(keys, RegistryIssuer, []string{""}); err == nil {
		t.Fatal("blank element must fail")
	}
}

// TestMultiServiceVerifierKeepsExactAudienceSemantics pins that the shared
// core still enforces the Task 4 exact-audience/service rules per host: wrong
// issuer, wrong service claim, and scope denial all fail.
func TestMultiServiceVerifierKeepsExactAudienceSemantics(t *testing.T) {
	t.Parallel()
	// Build a second issuer over the SAME private key but a different issuer
	// name, so the token is signature-valid yet issuer-invalid.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	keys := &countingKeySet{pub: pub}
	goodIssuer, err := NewRegistryTokenIssuer(priv, RegistryIssuer, multiKeyID)
	if err != nil {
		t.Fatalf("good issuer: %v", err)
	}
	wrongIssuer, err := NewRegistryTokenIssuer(priv, "someone-else", multiKeyID)
	if err != nil {
		t.Fatalf("wrong issuer: %v", err)
	}
	verifier, err := NewMultiServiceVerifier(keys, RegistryIssuer, []string{multiHostA, multiHostB})
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	repo := "backend/api"

	if _, err := verifier.Verify(issueForHost(t, goodIssuer, multiHostA, repo, []Action{ActionPull}), multiHostA, repo, ActionPull); err != nil {
		t.Fatalf("good token at its host must verify: %v", err)
	}
	if _, err := verifier.Verify(issueForHost(t, wrongIssuer, multiHostA, repo, []Action{ActionPull}), multiHostA, repo, ActionPull); err == nil {
		t.Fatal("wrong issuer must fail")
	}
	if _, err := verifier.Verify(issueForHost(t, goodIssuer, multiHostA, repo, []Action{ActionPull}), multiHostA, repo, ActionPush); !errors.Is(err, ErrScopeDenied) {
		t.Fatalf("pull-only token on push must be scope denied, got %v", err)
	}
	// Expired token at an allowed host.
	expired, err := goodIssuer.Issue(context.Background(), RegistryTokenRequest{
		Subject: "user:alice", Service: multiHostA, Repository: repo, Actions: []Action{ActionPull}, TTL: -time.Hour,
	})
	if err != nil {
		t.Fatalf("issue expired: %v", err)
	}
	if _, err := verifier.Verify(expired, multiHostA, repo, ActionPull); err == nil {
		t.Fatal("expired token must fail")
	}
	// Token signed for a DIFFERENT service claim than the request service.
	if _, err := verifier.Verify(issueForHost(t, goodIssuer, multiHostB, repo, []Action{ActionPull}), multiHostA, repo, ActionPull); err == nil {
		t.Fatal("service-claim mismatch at an allowed host must fail")
	}
}
