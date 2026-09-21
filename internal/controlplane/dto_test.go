package controlplane

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestPublicRegistryJSONHasNoSecretFields(t *testing.T) {
	t.Parallel()

	raw, err := json.Marshal(NewPublicRegistry(Registry{
		ID: 1, Slug: "alice", Host: "alice.example.test",
		FeedKey: EncryptedFeedKey{Ciphertext: []byte("ciphertext")},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("ciphertext")) || bytes.Contains(raw, []byte("EncryptedFeedPrivateKey")) {
		t.Fatalf("secret leaked: %s", raw)
	}
}

func TestPublicUserJSONHasNoSecretFields(t *testing.T) {
	t.Parallel()

	raw, err := json.Marshal(NewPublicUser(User{
		ID: 7, Email: "alice@example.com",
		PasswordHash: "$2a$hash-of-very-secret-password",
		CreatedAt:    time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("hash-of-very-secret-password")) ||
		bytes.Contains(raw, []byte("PasswordHash")) ||
		bytes.Contains(raw, []byte("passwordHash")) {
		t.Fatalf("secret leaked: %s", raw)
	}
}

func TestPublicMembershipJSONPreservesPublicFields(t *testing.T) {
	t.Parallel()

	raw, err := json.Marshal(NewPublicMembership(Membership{
		ID: 3, RegistryID: 1, UserID: 7, Email: "bob@example.com",
		Role: "member", CanPull: true, CanPush: true,
		CreatedAt: time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC),
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"id":3`, `"registryID":1`, `"userID":7`, `"email":"bob@example.com"`,
		`"role":"member"`, `"canPull":true`, `"canPush":true`,
	} {
		if !bytes.Contains(raw, []byte(want)) {
			t.Fatalf("missing public field %s in %s", want, raw)
		}
	}
}

func TestPublicInviteJSONHasNoTokenHash(t *testing.T) {
	t.Parallel()

	raw, err := json.Marshal(NewPublicInvite(Invite{
		ID: 5, RegistryID: 1, Email: "carol@example.com", Role: "member",
		CanPull: true, CanPush: true, TokenHash: "raw-token-hex", Status: "pending",
		ExpiresAt: time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC),
		CreatedAt: time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("raw-token-hex")) ||
		bytes.Contains(raw, []byte("TokenHash")) ||
		bytes.Contains(raw, []byte("tokenHash")) {
		t.Fatalf("token hash leaked: %s", raw)
	}
}
