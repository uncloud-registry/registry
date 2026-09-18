package auth

import (
	"testing"
	"time"
)

func TestTokenManagerIssueAndParse(t *testing.T) {
	t.Parallel()

	manager, err := NewTokenManager("secret")
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	token, err := manager.IssueRegistryToken("user:alice", "alice.uncloud-registry.com", "repository:backend/api:push", time.Hour)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	claims, err := manager.Parse(token)
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}

	if claims.Subject != "user:alice" || claims.TokenType != "registry" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}
