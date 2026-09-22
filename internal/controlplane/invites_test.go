package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/auth"
)

// openInviteMigDB opens a UNIQUE shared-memory sqlite DB per caller so
// parallel migration subtests never collide on a fixed DSN (openRawTestDB's
// shared name is fine for the pre-existing sequential-ish suite but not for
// concurrent migration fixtures). Each call also gets a unique suffix so
// repeated in-process runs (-count=N) start from an empty database.
func openInviteMigDB(t *testing.T, name string) *sql.DB {
	t.Helper()
	n := atomic.AddInt64(&inviteStoreSeq, 1)
	db, err := sql.Open("sqlite", fmt.Sprintf("file:invite_mig_%s_%d?mode=memory&cache=shared&_pragma=foreign_keys(1)", name, n))
	if err != nil {
		t.Fatalf("open invite mig db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// inviteStoreSeq makes every newInviteTestStore/openInviteMigDB DB name
// unique per CALL, so repeated package runs (-count=N, re-runs in one
// process) and parallel tests never collide on a shared in-memory database.
var inviteStoreSeq int64

// newInviteTestStore opens an isolated in-memory store for invite tests.
func newInviteTestStore(t *testing.T, name string) *Store {
	t.Helper()
	n := atomic.AddInt64(&inviteStoreSeq, 1)
	store, err := OpenSQLite(fmt.Sprintf("file:%s_%d?mode=memory&cache=shared", name, n))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	return store
}

// newInviteTestService wires a store + session manager (UI cookie sessions).
func newInviteTestService(t *testing.T, name string) (*Store, *Service) {
	t.Helper()
	store := newInviteTestStore(t, name)
	return store, &Service{Store: store, Tokens: newTestSessionManager(t), RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t), Publisher: newMemPublisher()}
}

// TestInviteTokenGenerationAndDigest pins the token format: exactly 24 random
// bytes under canonical base64.RawURLEncoding (32 chars), a 32-byte one-way
// SHA-256 digest over the canonical token text, and uniqueness across draws.
func TestInviteTokenGenerationAndDigest(t *testing.T) {
	t.Parallel()

	token, digest, err := NewInviteToken()
	if err != nil {
		t.Fatalf("new invite token: %v", err)
	}
	if len(token) != 32 {
		t.Fatalf("expected 32-char canonical token, got %q (len %d)", token, len(token))
	}
	if _, err := ParseInviteToken(token); err != nil {
		t.Fatalf("generated token must be canonical: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 24 {
		t.Fatalf("token must decode to 24 bytes, got len=%d err=%v", len(raw), err)
	}
	if len(digest) != 32 {
		t.Fatalf("expected 32-byte digest, got %d", len(digest))
	}
	if !bytes.Equal(digest, DigestInviteToken(token)) {
		t.Fatal("digest must be SHA-256 over the canonical token text")
	}

	second, _, err := NewInviteToken()
	if err != nil {
		t.Fatalf("second token: %v", err)
	}
	if second == token {
		t.Fatal("two draws must not collide")
	}
}

// TestInviteTokenSyntaxRejectedBeforeQuery pins the strict syntax gate: every
// malformed or non-canonical token is rejected (generic) BEFORE any hashing or
// database query, and never disturbs invite or membership state.
func TestInviteTokenSyntaxRejectedBeforeQuery(t *testing.T) {
	t.Parallel()

	store, service := newInviteTestService(t, "controlplane_invite_syntax_test")
	ctx := context.Background()
	alice, _, err := service.RegisterUser(ctx, "alice@example.com", "password123")
	if err != nil {
		t.Fatalf("register alice: %v", err)
	}
	created, err := service.CreateRegistry(ctx, alice.ID, "alice", "alice.eth", true, "batch-1")
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	bob, _, err := service.RegisterUser(ctx, "bob@example.com", "password123")
	if err != nil {
		t.Fatalf("register bob: %v", err)
	}
	_, realToken, err := service.CreateInvite(ctx, created.Registry.ID, alice.ID, "bob@example.com", true, true)
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}

	// Progressively malformed inputs: empty, wrong length, invalid characters,
	// base64 padding, non-canonical trailing pad bits, surrounding whitespace.
	bad := []string{
		"",
		"short",
		strings.Repeat("A", 31),
		strings.Repeat("A", 33),
		strings.Repeat("!", 32),
		strings.Repeat("A", 30) + "==",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB", // 31 As + B: non-canonical pad bits
		" " + realToken + " ",
		realToken + "\n",
	}
	for i, candidate := range bad {
		if _, err := store.AcceptInvite(ctx, candidate, bob); !errors.Is(err, errInviteNotFound) {
			t.Fatalf("case %d: expected generic rejection for %q, got %v", i, candidate, err)
		}
		if _, _, err := service.GetInvite(ctx, candidate); !errors.Is(err, errInviteNotFound) {
			t.Fatalf("case %d: GetInvite must reject %q generically, got %v", i, candidate, err)
		}
	}

	// Nothing was disturbed: the real invite is still pending and the only
	// membership is the owner's.
	invites, err := store.ListInvitesForRegistry(ctx, created.Registry.ID)
	if err != nil || len(invites) != 1 {
		t.Fatalf("expected exactly 1 invite, got %d (err %v)", len(invites), err)
	}
	if invites[0].Status != "pending" {
		t.Fatalf("invite must remain pending, got %s", invites[0].Status)
	}
	if _, err := store.AcceptInvite(ctx, realToken, bob); err != nil {
		t.Fatalf("real token must still be acceptable: %v", err)
	}
}

// TestInviteLifecycleRecipientBinding drives the full service lifecycle:
// creation normalizes the recipient; acceptance binds to the database-loaded
// user by ID with normalized email comparison; the same user's retry is an
// idempotent success with no duplicate membership; a wrong recipient always
// fails generically.
func TestInviteLifecycleRecipientBinding(t *testing.T) {
	t.Parallel()

	store, service := newInviteTestService(t, "controlplane_invite_lifecycle_test")
	ctx := context.Background()
	alice, _, err := service.RegisterUser(ctx, "alice@example.com", "password123")
	if err != nil {
		t.Fatalf("register alice: %v", err)
	}
	created, err := service.CreateRegistry(ctx, alice.ID, "alice", "alice.eth", false, "batch-1")
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}

	// Inviter with surrounding whitespace + mixed case: normalized at creation.
	invite, token, err := service.CreateInvite(ctx, created.Registry.ID, alice.ID, "  Bob@Example.COM  ", true, true)
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	if invite.Email != "bob@example.com" {
		t.Fatalf("recipient not normalized, got %q", invite.Email)
	}
	persisted, err := store.ListInvitesForRegistry(ctx, created.Registry.ID)
	if err != nil || len(persisted) != 1 {
		t.Fatalf("expected 1 persisted invite: %v", err)
	}
	if persisted[0].Email != "bob@example.com" {
		t.Fatalf("persisted recipient not normalized, got %q", persisted[0].Email)
	}

	// Recipient registers with equivalent-padded form; account identity is the
	// normalized email.
	bob, _, err := service.RegisterUser(ctx, "   bob@example.com ", "password123")
	if err != nil {
		t.Fatalf("register bob: %v", err)
	}
	if bob.Email != "bob@example.com" {
		t.Fatalf("account email not normalized, got %q", bob.Email)
	}

	// Wrong recipient (no account yet) must fail generically and create nothing.
	carol, _, err := service.RegisterUser(ctx, "carol@example.com", "password123")
	if err != nil {
		t.Fatalf("register carol: %v", err)
	}
	if _, err := service.AcceptInvite(ctx, token, carol.ID); !errors.Is(err, errInviteNotFound) {
		t.Fatalf("wrong recipient must fail generically, got %v", err)
	}
	if _, err := store.FindMembership(ctx, created.Registry.ID, carol.ID); err == nil {
		t.Fatal("wrong recipient must not create a membership")
	} else if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("unexpected membership lookup error: %v", err)
	}

	// Correct recipient accepts: membership carries the invite grant and the
	// invite records accepted_by.
	accepted, err := service.AcceptInvite(ctx, token, bob.ID)
	if err != nil {
		t.Fatalf("accept invite: %v", err)
	}
	if accepted.Status != "accepted" || accepted.AcceptedByUserID == nil || *accepted.AcceptedByUserID != bob.ID {
		t.Fatalf("unexpected accepted invite: %+v", accepted)
	}
	membership, err := store.FindMembership(ctx, created.Registry.ID, bob.ID)
	if err != nil {
		t.Fatalf("find membership: %v", err)
	}
	if !membership.CanPull || !membership.CanPush {
		t.Fatalf("membership must carry invite grant, got %+v", membership)
	}

	// Same-user idempotent retry: identical successful invite, no duplicate.
	retry, err := service.AcceptInvite(ctx, token, bob.ID)
	if err != nil {
		t.Fatalf("same-user retry must succeed: %v", err)
	}
	if retry.Status != "accepted" || retry.ID != accepted.ID {
		t.Fatalf("retry must return the same accepted invite, got %+v", retry)
	}
	memberships, err := store.ListMembershipsForRegistry(ctx, created.Registry.ID)
	if err != nil {
		t.Fatalf("list memberships: %v", err)
	}
	if len(memberships) != 2 { // owner + bob
		t.Fatalf("expected 2 memberships, got %d", len(memberships))
	}

	// Wrong-user retry AFTER acceptance: generic failure.
	if _, err := service.AcceptInvite(ctx, token, carol.ID); !errors.Is(err, errInviteNotFound) {
		t.Fatalf("wrong-user retry after acceptance must fail generically, got %v", err)
	}
}

// TestInviteMembershipMergeNeverDowngrades pins the permission-merge semantics:
// acceptance of a weaker invite never downgrades an existing stronger
// membership (permission-wise OR, senior role preserved), and a weaker
// existing membership is upgraded by a stronger invite.
func TestInviteMembershipMergeNeverDowngrades(t *testing.T) {
	t.Parallel()

	store, service := newInviteTestService(t, "controlplane_invite_merge_test")
	ctx := context.Background()
	alice, _, err := service.RegisterUser(ctx, "alice@example.com", "password123")
	if err != nil {
		t.Fatalf("register alice: %v", err)
	}
	created, err := service.CreateRegistry(ctx, alice.ID, "alice", "alice.eth", false, "batch-1")
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}

	// bob already holds OWNER-level access (stronger than any invite grant).
	bob, _, err := service.RegisterUser(ctx, "bob@example.com", "password123")
	if err != nil {
		t.Fatalf("register bob: %v", err)
	}
	if _, err := store.CreateMembership(ctx, Membership{
		RegistryID: created.Registry.ID, UserID: bob.ID, Role: "owner", CanPull: true, CanPush: true,
	}); err != nil {
		t.Fatalf("create owner membership: %v", err)
	}

	// A weak read-only invite must not downgrade him.
	_, token, err := service.CreateInvite(ctx, created.Registry.ID, alice.ID, "bob@example.com", true, false)
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	if _, err := service.AcceptInvite(ctx, token, bob.ID); err != nil {
		t.Fatalf("accept invite: %v", err)
	}
	membership, err := store.FindMembership(ctx, created.Registry.ID, bob.ID)
	if err != nil {
		t.Fatalf("find membership: %v", err)
	}
	if membership.Role != "owner" || !membership.CanPull || !membership.CanPush {
		t.Fatalf("stronger membership was downgraded: %+v", membership)
	}

	// carol is a pull-only member; a pull+push invite upgrades her to push.
	carol, _, err := service.RegisterUser(ctx, "carol@example.com", "password123")
	if err != nil {
		t.Fatalf("register carol: %v", err)
	}
	if _, err := store.CreateMembership(ctx, Membership{
		RegistryID: created.Registry.ID, UserID: carol.ID, Role: "member", CanPull: true, CanPush: false,
	}); err != nil {
		t.Fatalf("create carol membership: %v", err)
	}
	_, tokenC, err := service.CreateInvite(ctx, created.Registry.ID, alice.ID, "carol@example.com", true, true)
	if err != nil {
		t.Fatalf("create carol invite: %v", err)
	}
	if _, err := service.AcceptInvite(ctx, tokenC, carol.ID); err != nil {
		t.Fatalf("accept carol invite: %v", err)
	}
	membership, err = store.FindMembership(ctx, created.Registry.ID, carol.ID)
	if err != nil {
		t.Fatalf("find carol membership: %v", err)
	}
	if !membership.CanPush || membership.Role != "member" {
		t.Fatalf("weaker membership was not upgraded: %+v", membership)
	}
}

// TestInviteRevocationAuthorizationAndLifecycle covers the full revocation
// lifecycle: owner-authorized, pending-only, atomic, idempotent for the same
// authorized request, and terminal for acceptance afterwards.
func TestInviteRevocationAuthorizationAndLifecycle(t *testing.T) {
	t.Parallel()

	store, service := newInviteTestService(t, "controlplane_invite_revoke_test")
	ctx := context.Background()
	alice, _, err := service.RegisterUser(ctx, "alice@example.com", "password123")
	if err != nil {
		t.Fatalf("register alice: %v", err)
	}
	created, err := service.CreateRegistry(ctx, alice.ID, "alice", "alice.eth", false, "batch-1")
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	bob, _, err := service.RegisterUser(ctx, "bob@example.com", "password123")
	if err != nil {
		t.Fatalf("register bob: %v", err)
	}
	// bob is a plain collaborator on the registry (not owner/admin).
	if _, err := store.CreateMembership(ctx, Membership{
		RegistryID: created.Registry.ID, UserID: bob.ID, Role: "member", CanPull: true, CanPush: false,
	}); err != nil {
		t.Fatalf("create bob membership: %v", err)
	}

	invite, token, err := service.CreateInvite(ctx, created.Registry.ID, alice.ID, "mallory@example.com", true, true)
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	mallory, _, err := service.RegisterUser(ctx, "mallory@example.com", "password123")
	if err != nil {
		t.Fatalf("register mallory: %v", err)
	}

	// A non-owner member revoking must receive the generic not-found.
	if _, err := service.RevokeInvite(ctx, bob.ID, created.Registry.ID, invite.ID); !errors.Is(err, errInviteNotFound) {
		t.Fatalf("member revoke must fail generically, got %v", err)
	}
	// Unknown invite: generic not-found.
	if _, err := service.RevokeInvite(ctx, alice.ID, created.Registry.ID, 999999); !errors.Is(err, errInviteNotFound) {
		t.Fatalf("unknown invite revoke must fail generically, got %v", err)
	}

	// Owner revokes the pending invite.
	revoked, err := service.RevokeInvite(ctx, alice.ID, created.Registry.ID, invite.ID)
	if err != nil {
		t.Fatalf("revoke invite: %v", err)
	}
	if revoked.Status != "revoked" || revoked.RevokedAt == nil {
		t.Fatalf("unexpected revoked invite: %+v", revoked)
	}

	// Acceptance afterwards is impossible (and generically reported).
	if _, err := service.AcceptInvite(ctx, token, mallory.ID); !errors.Is(err, errInviteNotFound) {
		t.Fatalf("acceptance after revocation must fail generically, got %v", err)
	}
	if _, _, err := service.GetInvite(ctx, token); !errors.Is(err, errInviteNotFound) {
		t.Fatalf("GetInvite after revocation must fail generically, got %v", err)
	}
	if _, err := store.FindMembership(ctx, created.Registry.ID, mallory.ID); err == nil {
		t.Fatal("revoked invite must not create a membership")
	} else if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("unexpected membership error: %v", err)
	}

	// Idempotent: revoking the same invite again is a success (no state change).
	if again, err := service.RevokeInvite(ctx, alice.ID, created.Registry.ID, invite.ID); err != nil {
		t.Fatalf("idempotent re-revoke must succeed: %v", err)
	} else if again.Status != "revoked" {
		t.Fatalf("re-revoke must report revoked, got %+v", again)
	}

	// An ACCEPTED invite cannot be revoked.
	second, token2, err := service.CreateInvite(ctx, created.Registry.ID, alice.ID, "mallory@example.com", true, true)
	if err != nil {
		t.Fatalf("create second invite: %v", err)
	}
	if _, err := service.AcceptInvite(ctx, token2, mallory.ID); err != nil {
		t.Fatalf("accept second invite: %v", err)
	}
	if _, err := service.RevokeInvite(ctx, alice.ID, created.Registry.ID, second.ID); !errors.Is(err, errInviteCannotRevoke) {
		t.Fatalf("accepting invite must not be revocable, got %v", err)
	}
}

// TestInviteConcurrentAcceptanceExactlyOneTransition races multiple acceptors
// against one invite: only the recipient can ever win; the same-user retries
// are idempotent; wrong users all fail; exactly one membership is created.
func TestInviteConcurrentAcceptanceExactlyOneTransition(t *testing.T) {
	t.Parallel()

	store, service := newInviteTestService(t, "controlplane_invite_concurrent_test")
	ctx := context.Background()
	alice, _, err := service.RegisterUser(ctx, "alice@example.com", "password123")
	if err != nil {
		t.Fatalf("register alice: %v", err)
	}
	created, err := service.CreateRegistry(ctx, alice.ID, "alice", "alice.eth", false, "batch-1")
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	bob, _, err := service.RegisterUser(ctx, "bob@example.com", "password123")
	if err != nil {
		t.Fatalf("register bob: %v", err)
	}
	wrongUsers := make([]int64, 0, 4)
	for _, email := range []string{"c1@example.com", "c2@example.com", "c3@example.com", "c4@example.com"} {
		u, _, err := service.RegisterUser(ctx, email, "password123")
		if err != nil {
			t.Fatalf("register %s: %v", email, err)
		}
		wrongUsers = append(wrongUsers, u.ID)
	}

	_, token, err := service.CreateInvite(ctx, created.Registry.ID, alice.ID, "bob@example.com", true, true)
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}

	const attempts = 6
	var wg sync.WaitGroup
	var mu sync.Mutex
	bobOK, bobFail, wrongFail := 0, 0, 0
	// A start barrier synchronizes ALL workers so they contend for the same
	// invite transition from (nearly) the same instant — a true race, not a
	// sequential harness.
	start := make(chan struct{})
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := service.AcceptInvite(ctx, token, bob.ID); err != nil {
				mu.Lock()
				bobFail++
				mu.Unlock()
				return
			}
			mu.Lock()
			bobOK++
			mu.Unlock()
		}()
	}
	for _, uid := range wrongUsers {
		wg.Add(1)
		go func(uid int64) {
			defer wg.Done()
			<-start
			if _, err := service.AcceptInvite(ctx, token, uid); !errors.Is(err, errInviteNotFound) {
				t.Errorf("wrong user %d must fail generically, got %v", uid, err)
			}
			mu.Lock()
			wrongFail++
			mu.Unlock()
		}(uid)
	}
	close(start)
	wg.Wait()

	// Exactly one state transition and one (bob) membership; EVERY bob
	// attempt — winner or idempotent retry — must succeed, and every wrong
	// user must fail generically.
	if bobOK != attempts || bobFail != 0 {
		t.Fatalf("ALL same-user concurrent attempts must succeed (ok=%d fail=%d)", bobOK, bobFail)
	}
	if wrongFail != len(wrongUsers) {
		t.Fatalf("expected %d wrong-user failures, got %d", len(wrongUsers), wrongFail)
	}
	invites, err := store.ListInvitesForRegistry(ctx, created.Registry.ID)
	if err != nil || len(invites) != 1 {
		t.Fatalf("expected 1 invite: %v", err)
	}
	if invites[0].Status != "accepted" || invites[0].AcceptedByUserID == nil || *invites[0].AcceptedByUserID != bob.ID {
		t.Fatalf("invite must be accepted by bob exactly once: %+v", invites[0])
	}
	memberships, err := store.ListMembershipsForRegistry(ctx, created.Registry.ID)
	if err != nil {
		t.Fatalf("list memberships: %v", err)
	}
	if len(memberships) != 2 {
		t.Fatalf("expected exactly 2 memberships (owner + bob), got %d", len(memberships))
	}

	// Post-race same-user retry still idempotent.
	if _, err := service.AcceptInvite(ctx, token, bob.ID); err != nil {
		t.Fatalf("post-race same-user retry must succeed: %v", err)
	}
	memberships, err = store.ListMembershipsForRegistry(ctx, created.Registry.ID)
	if err != nil {
		t.Fatalf("list memberships: %v", err)
	}
	if len(memberships) != 2 {
		t.Fatalf("duplicate membership after retry: got %d", len(memberships))
	}
}

// TestInviteConcurrentAcceptanceAndRevocation races acceptance against
// revocation: whichever transition claims first wins, the other fails
// generically, and the final state is always internally consistent (accepted ⇒
// membership exists; revoked ⇒ no membership and acceptance impossible).
func TestInviteConcurrentAcceptanceAndRevocation(t *testing.T) {
	t.Parallel()

	for round := 0; round < 5; round++ {
		store := newInviteTestStore(t, fmt.Sprintf("controlplane_invite_acceptrevoke_%d", round))
		service := &Service{Store: store, Tokens: newTestSessionManager(t), RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t), Publisher: newMemPublisher()}
		ctx := context.Background()
		alice, _, err := service.RegisterUser(ctx, "alice@example.com", "password123")
		if err != nil {
			t.Fatalf("register alice: %v", err)
		}
		created, err := service.CreateRegistry(ctx, alice.ID, "alice", "alice.eth", false, "batch-1")
		if err != nil {
			t.Fatalf("create registry: %v", err)
		}
		bob, _, err := service.RegisterUser(ctx, "bob@example.com", "password123")
		if err != nil {
			t.Fatalf("register bob: %v", err)
		}
		invite, token, err := service.CreateInvite(ctx, created.Registry.ID, alice.ID, "bob@example.com", true, true)
		if err != nil {
			t.Fatalf("create invite: %v", err)
		}

		var acceptErr, revokeErr error
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, acceptErr = service.AcceptInvite(ctx, token, bob.ID)
		}()
		go func() {
			defer wg.Done()
			_, revokeErr = service.RevokeInvite(ctx, alice.ID, created.Registry.ID, invite.ID)
		}()
		wg.Wait()

		// Classify: acceptance won iff nil; revocation won iff nil or when the
		// invite was still pending (acceptance then lost).
		after, err := store.ListInvitesForRegistry(ctx, created.Registry.ID)
		if err != nil || len(after) != 1 {
			t.Fatalf("round %d: list invites: %v", round, err)
		}
		memberships, err := store.ListMembershipsForRegistry(ctx, created.Registry.ID)
		if err != nil {
			t.Fatalf("round %d: list memberships: %v", round, err)
		}
		switch after[0].Status {
		case "accepted":
			if acceptErr != nil {
				t.Fatalf("round %d: accepted but bob's accept failed: %v", round, acceptErr)
			}
			if !errors.Is(revokeErr, errInviteCannotRevoke) {
				t.Fatalf("round %d: accepted invite must refuse revocation, got %v", round, revokeErr)
			}
			if len(memberships) != 2 {
				t.Fatalf("round %d: accepted ⇒ membership must exist, got %d", round, len(memberships))
			}
		case "revoked":
			if revokeErr != nil {
				t.Fatalf("round %d: revoked but revoke failed: %v", round, revokeErr)
			}
			if !errors.Is(acceptErr, errInviteNotFound) {
				t.Fatalf("round %d: revoked invite must refuse acceptance, got %v", round, acceptErr)
			}
			if len(memberships) != 1 {
				t.Fatalf("round %d: revoked ⇒ no new membership, got %d", round, len(memberships))
			}
		default:
			t.Fatalf("round %d: unexpected terminal state %q", round, after[0].Status)
		}
	}
}

// TestInviteDigestNeverReconstructed proves the persisted credential is a
// 32-byte one-way digest: it can never be turned back into the token, and
// feeding the digest's own encodings into acceptance fails.
func TestInviteDigestNeverReconstructed(t *testing.T) {
	t.Parallel()

	store, service := newInviteTestService(t, "controlplane_invite_digest_test")
	ctx := context.Background()
	alice, _, err := service.RegisterUser(ctx, "alice@example.com", "password123")
	if err != nil {
		t.Fatalf("register alice: %v", err)
	}
	created, err := service.CreateRegistry(ctx, alice.ID, "alice", "alice.eth", false, "batch-1")
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	bob, _, err := service.RegisterUser(ctx, "bob@example.com", "password123")
	if err != nil {
		t.Fatalf("register bob: %v", err)
	}
	_, token, err := service.CreateInvite(ctx, created.Registry.ID, alice.ID, "bob@example.com", true, true)
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	invites, err := store.ListInvitesForRegistry(ctx, created.Registry.ID)
	if err != nil || len(invites) != 1 {
		t.Fatalf("list invites: %v", err)
	}
	digest := invites[0].TokenDigest
	if len(digest) != 32 {
		t.Fatalf("expected 32-byte digest BLOB, got %d bytes", len(digest))
	}
	// The historical reversible encoding of the token is hex(token text); the
	// digest must never BE that or contain it.
	if hex.EncodeToString(digest) == token || string(digest) == token {
		t.Fatal("persisted digest must not equal the raw token in any encoding")
	}
	// Trying to use the digest's encodings as the token fails generically.
	for _, guess := range []string{
		hex.EncodeToString(digest),
		base64.RawURLEncoding.EncodeToString(digest),
		base64.StdEncoding.EncodeToString(digest),
		string(digest),
	} {
		if _, err := store.AcceptInvite(ctx, guess, bob); !errors.Is(err, errInviteNotFound) {
			t.Fatalf("digest lookalike %q must be rejected, got %v", guess, err)
		}
	}
	// The invite is still pending and acceptable with the real token.
	invites, err = store.ListInvitesForRegistry(ctx, created.Registry.ID)
	if err != nil || invites[0].Status != "pending" {
		t.Fatalf("invite must still be pending: %v %+v", err, invites)
	}
	if _, err := service.AcceptInvite(ctx, token, bob.ID); err != nil {
		t.Fatalf("real token still acceptable: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Migration 4: digest schema conversion, corruption rejection, rollback.
// ---------------------------------------------------------------------------

// tokenTextA/B/C are three distinct canonical invite token texts (32 base64url
// chars decoding to 24 bytes with zero pad bits).
const (
	tokenTextA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	tokenTextB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	tokenTextC = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
)

func TestConvertLegacyInviteHash(t *testing.T) {
	t.Parallel()

	// Historical format: hex(token text) → SHA-256 over the text. tokenTextA
	// is exactly the 32-char canonical token TEXT the pre-Task-7 flow stored.
	legacy := hex.EncodeToString([]byte(tokenTextA))
	got, err := convertLegacyInviteHash(legacy)
	if err != nil {
		t.Fatalf("convert legacy: %v", err)
	}
	if !bytes.Equal(got, DigestInviteToken(tokenTextA)) {
		t.Fatal("legacy hex(token text) must convert to SHA-256 over the text")
	}

	// EXACT historical generation fixture: replicate the removed pre-Task-7
	// makeInviteToken/hashInviteToken code path byte-for-byte (24 random bytes
	// → canonical base64url text → hex.EncodeToString([]byte(token))) and
	// prove the conversion recovers the identical digest the acceptance path
	// would compute for that token.
	for i := 0; i < 8; i++ {
		raw := make([]byte, 24)
		if _, err := rand.Read(raw); err != nil {
			t.Fatalf("rand: %v", err)
		}
		token := base64.RawURLEncoding.EncodeToString(raw)
		if !isCanonicalInviteTokenText(token) {
			t.Fatalf("fixture error: generated token %q must be canonical", token)
		}
		stored := hex.EncodeToString([]byte(token)) // the ONLY historical representation
		converted, err := convertLegacyInviteHash(stored)
		if err != nil {
			t.Fatalf("convert exact historical fixture: %v", err)
		}
		if !bytes.Equal(converted, DigestInviteToken(token)) {
			t.Fatal("exact historical fixture must convert to SHA-256 over the token text")
		}
	}

	// Arbitrary digest hex — hex of a SHA-256 digest whose bytes are NOT a
	// canonical token text — is REJECTED: the pre-Task-7 code never stored a
	// digest format, so no "digest hex" value is a legitimate token_hash.
	digestHex := hex.EncodeToString(DigestInviteToken(tokenTextB))
	if _, err := convertLegacyInviteHash(digestHex); err == nil {
		t.Fatal("arbitrary 32-byte digest hex must be rejected (no legacy digest format exists)")
	}

	// Malformed values: plaintext tokens, wrong lengths, non-hex, uppercase,
	// and 32 decoded bytes that are not a canonical token text. Note that any
	// 32-char base64url-alphabet string IS a plausible historical token
	// (24 bytes encode to 32 chars with no pad bits), so rejection requires
	// characters outside the alphabet.
	for _, bad := range []string{
		tokenTextA, // the raw token itself, not an encoding
		"tokhash",  // garbage
		strings.Repeat("A", 63),
		strings.Repeat("A", 65),
		strings.ToUpper(hex.EncodeToString([]byte("JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ"))), // uppercase hex
		"zzzz" + strings.Repeat("0", 60),
		hex.EncodeToString([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==")), // padded: '=' outside rawurl alphabet
		hex.EncodeToString([]byte("a!aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")), // '!' outside the alphabet
	} {
		if _, err := convertLegacyInviteHash(bad); err == nil {
			t.Fatalf("malformed legacy hash %q must be rejected", bad)
		}
	}
}

// seedInvitesDigestFixture seeds a schema-current (v1+; token_hash still TEXT)
// database with the full invite fixture: legacy hex-of-text pending rows and a
// legacy hex-of-text accepted row (accepted history is preserved as
// legacy_unattributed — the historical accepter is unknowable and never
// inferred from the recipient email).
func seedInvitesDigestFixture(t *testing.T, db *sql.DB, expires string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)
	for _, email := range []string{"alice@example.com", "bob@example.com", "carol@example.com", "dave@example.com"} {
		if _, err := db.ExecContext(ctx, `insert into users (email, password_hash, created_at) values (?, ?, ?)`,
			email, "hash", now); err != nil {
			t.Fatalf("seed user %s: %v", email, err)
		}
	}
	if _, err := db.ExecContext(ctx, `insert into registries
		(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at)
		values ('alice', 'alice.example.test', 'alice.eth', 1, '0xfeed', '', 'batch-1', 1, ?)`, now); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	if _, err := db.ExecContext(ctx, `insert into registry_memberships
		(registry_id, user_id, role, can_pull, can_push, created_at) values (1, 1, 'owner', 1, 1, ?)`, now); err != nil {
		t.Fatalf("seed owner membership: %v", err)
	}
	// dave accepted his (now terminal) invite back in the legacy era: the
	// membership exists, but the migration must NOT attribute the acceptance
	// to dave — it is preserved as legacy_unattributed.
	if _, err := db.ExecContext(ctx, `insert into registry_memberships
		(registry_id, user_id, role, can_pull, can_push, created_at) values (1, 4, 'member', 1, 1, ?)`, now); err != nil {
		t.Fatalf("seed dave membership: %v", err)
	}

	insert := func(email string, tokenHash string, status string) {
		if _, err := db.ExecContext(ctx, `insert into registry_invites
			(registry_id, email, role, can_pull, can_push, token_hash, status, expires_at, created_at)
			values (1, ?, 'member', 1, 1, ?, ?, ?, ?)`, email, tokenHash, status, expires, now); err != nil {
			t.Fatalf("seed invite %s: %v", email, err)
		}
	}
	// bob and carol: pending invites in the historical reversible format
	// hex(token text); their raw tokens stay acceptable after the upgrade.
	insert("bob@example.com", hex.EncodeToString([]byte(tokenTextA)), "pending")
	insert("carol@example.com", hex.EncodeToString([]byte(tokenTextB)), "pending")
	// dave: accepted invite in the SAME historical format — there is no
	// digest-hex legacy format to preserve.
	insert("dave@example.com", hex.EncodeToString([]byte(tokenTextC)), "accepted")
}

// TestInviteDigestMigrationFromEverySupportedSchema upgrades databases at every
// supported schema version (0 legacy, 1, 2, 3) to v5 and proves: mixed legacy
// hash values convert deterministically (historical hex-of-token-text only),
// accepted history is preserved as legacy_unattributed with NO accepter
// attribution (the historical accepter is unknowable — token retries for these
// always fail generically), previously pending invites remain acceptable with
// their raw token, and the lifecycle schema is installed.
func TestInviteDigestMigrationFromEverySupportedSchema(t *testing.T) {
	t.Parallel()

	for _, version := range []int{0, 1, 2, 3} {
		version := version
		t.Run(fmt.Sprintf("from v%d", version), func(t *testing.T) {
			t.Parallel()
			db := openInviteMigDB(t, fmt.Sprintf("every_%d", version))
			ctx := context.Background()
			expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)

			if version == 0 {
				seedLegacyDBSchema(t, db)
			} else {
				if err := applyMigrationsThrough(ctx, db, version); err != nil {
					t.Fatalf("apply through v%d: %v", version, err)
				}
			}
			seedInvitesDigestFixture(t, db, expires)

			if err := ApplyMigrations(ctx, db); err != nil {
				t.Fatalf("apply migrations from v%d: %v", version, err)
			}
			got, err := CurrentSchemaVersion(ctx, db)
			if err != nil || got != 8 {
				t.Fatalf("expected schema version 8, got %d (err %v)", got, err)
			}
			assertInviteDigestSchema(t, db)

			store := &Store{DB: db}

			// bob's legacy-format invite converts and stays acceptable.
			bob := User{ID: 2, Email: "bob@example.com"}
			accepted, err := store.AcceptInvite(ctx, tokenTextA, bob)
			if err != nil {
				t.Fatalf("bob must accept converted invite: %v", err)
			}
			if accepted.Status != "accepted" || accepted.AcceptedByUserID == nil || *accepted.AcceptedByUserID != 2 {
				t.Fatalf("unexpected conversion acceptance: %+v", accepted)
			}
			if len(accepted.TokenDigest) != 32 {
				t.Fatalf("converted digest must be 32 bytes, got %d", len(accepted.TokenDigest))
			}

			// carol's legacy-format invite converts and stays acceptable.
			carol := User{ID: 3, Email: "carol@example.com"}
			if _, err := store.AcceptInvite(ctx, tokenTextB, carol); err != nil {
				t.Fatalf("carol must accept converted invite: %v", err)
			}

			// dave's accepted invite is preserved as legacy_unattributed: the
			// historical accepter is UNKNOWABLE, so no accepted_by is inferred
			// from the recipient email and the terminal token NEVER succeeds
			// again — for dave or anyone else.
			var acceptedBy sql.NullInt64
			var legacyFlag int
			if err := db.QueryRowContext(ctx, `select accepted_by_user_id, legacy_unattributed from registry_invites where id = 3`).Scan(&acceptedBy, &legacyFlag); err != nil {
				t.Fatalf("read legacy-unattributed invite: %v", err)
			}
			if acceptedBy.Valid {
				t.Fatalf("legacy accepted invite must NOT be attributed, got accepted_by %d", acceptedBy.Int64)
			}
			if legacyFlag != 1 {
				t.Fatalf("legacy accepted invite must carry legacy_unattributed=1, got %d", legacyFlag)
			}
			if _, err := store.AcceptInvite(ctx, tokenTextC, User{ID: 4, Email: "dave@example.com"}); !errors.Is(err, errInviteNotFound) {
				t.Fatalf("legacy accepted invite must refuse the recipient's retry, got %v", err)
			}
			if _, err := store.AcceptInvite(ctx, tokenTextC, User{ID: 2, Email: "bob@example.com"}); !errors.Is(err, errInviteNotFound) {
				t.Fatalf("legacy accepted invite must refuse a different user, got %v", err)
			}
			// The v5 forward-only migration installs the immutability trigger
			// on every upgrade path: dave's legacy_unattributed row is now a
			// frozen record that ordinary SQL can no longer rewrite.
			if _, err := db.ExecContext(ctx, `update registry_invites set legacy_unattributed = 0, accepted_by_user_id = 2 where id = 3`); err == nil {
				t.Fatal("upgrade to v5 must make legacy_unattributed rows immutable")
			}
			var afterRewriteFlag int
			if err := db.QueryRowContext(ctx, `select legacy_unattributed from registry_invites where id = 3`).Scan(&afterRewriteFlag); err != nil {
				t.Fatal(err)
			}
			if afterRewriteFlag != 1 {
				t.Fatalf("rejected rewrite must leave the legacy flag at 1, got %d", afterRewriteFlag)
			}
			memberships, err := store.ListMembershipsForRegistry(ctx, 1)
			if err != nil {
				t.Fatalf("list memberships: %v", err)
			}
			if len(memberships) != 4 { // owner + dave (legacy) + bob + carol (converted)
				t.Fatalf("expected 4 memberships after conversion, got %d", len(memberships))
			}
		})
	}
}

// TestInviteDigestMigrationRejectsCorruptRows proves the migration FAILS (with
// full rollback, version unchanged, legacy data untouched) on malformed
// token_hash values, plaintext-as-valid rows, and duplicate converted digests.
// Schema-valid accepted rows are never rejected for a missing membership: the
// historical accepter is unknowable, so they are PRESERVED (see
// TestInviteLegacyAcceptedPreservedWithoutRecipientMembership).
func TestInviteDigestMigrationRejectsCorruptRows(t *testing.T) {
	t.Parallel()

	// seedInviteParents satisfies the registry_invites foreign keys for the
	// corrupt-row fixtures (must run AFTER migrations created the tables).
	seedInviteParents := func(t *testing.T, db *sql.DB) {
		t.Helper()
		now := time.Now().UTC().Format(time.RFC3339)
		if _, err := db.ExecContext(context.Background(), `insert into users (email, password_hash, created_at) values ('bob@example.com','hash',?)`, now); err != nil {
			t.Fatalf("seed parent user: %v", err)
		}
		if _, err := db.ExecContext(context.Background(), `insert into registries
			(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at)
			values ('alice','alice.example.test','alice.eth',1,'0xfeed','','batch-1',1,?)`, now); err != nil {
			t.Fatalf("seed parent registry: %v", err)
		}
	}

	seedInvitesFixture := func(t *testing.T, db *sql.DB, corrupt func(ctx context.Context, db *sql.DB) error) {
		t.Helper()
		ctx := context.Background()
		if err := applyMigrationsThrough(ctx, db, 3); err != nil {
			t.Fatalf("apply through v3: %v", err)
		}
		seedInviteParents(t, db)
		if err := corrupt(ctx, db); err != nil {
			t.Fatalf("seed corrupt row: %v", err)
		}
	}

	assertFailed := func(t *testing.T, db *sql.DB) {
		t.Helper()
		ctx := context.Background()
		if err := ApplyMigrations(ctx, db); err == nil {
			t.Fatal("expected migration to fail on corrupt invite rows, got nil")
		}
		version, err := CurrentSchemaVersion(ctx, db)
		if err != nil || version != 3 {
			t.Fatalf("version must stay 3 after rejected migration, got %d (err %v)", version, err)
		}
		// Legacy table intact: token_hash still exists, rows preserved, no
		// rebuild artifacts.
		var hasTokenHash int
		if err := db.QueryRowContext(ctx, `select count(*) from pragma_table_info('registry_invites') where name = 'token_hash'`).Scan(&hasTokenHash); err != nil {
			t.Fatal(err)
		}
		if hasTokenHash != 1 {
			t.Fatal("legacy token_hash column must survive a rejected migration")
		}
		var leftovers int
		if err := db.QueryRowContext(ctx, `select count(*) from sqlite_master where type='table' and name like '%\_new%' escape '\'`).Scan(&leftovers); err != nil {
			t.Fatal(err)
		}
		if leftovers != 0 {
			t.Fatalf("expected no *_new rebuild artifacts after rollback, found %d", leftovers)
		}
	}

	t.Run("malformed non-hex token_hash", func(t *testing.T) {
		t.Parallel()
		db := openInviteMigDB(t, "corrupt_malformed")
		seedInvitesFixture(t, db, func(ctx context.Context, db *sql.DB) error {
			_, err := db.ExecContext(ctx, `insert into registry_invites
				(registry_id, email, role, can_pull, can_push, token_hash, status, expires_at, created_at)
				values (1, 'bob@example.com', 'member', 1, 0, 'tokhash-garbage', 'pending', ?, ?)`,
				time.Now().UTC().Add(time.Hour).Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339))
			return err
		})
		assertFailed(t, db)
	})

	t.Run("plaintext token stored as-is", func(t *testing.T) {
		t.Parallel()
		db := openInviteMigDB(t, "corrupt_plaintext")
		// Plaintext (the raw token itself, not an encoding) must NEVER be
		// treated as a valid digest.
		seedInvitesFixture(t, db, func(ctx context.Context, db *sql.DB) error {
			_, err := db.ExecContext(ctx, `insert into registry_invites
				(registry_id, email, role, can_pull, can_push, token_hash, status, expires_at, created_at)
				values (1, 'bob@example.com', 'member', 1, 0, ?, 'pending', ?, ?)`,
				tokenTextA, time.Now().UTC().Add(time.Hour).Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339))
			return err
		})
		assertFailed(t, db)
	})

	t.Run("arbitrary digest hex rejected", func(t *testing.T) {
		t.Parallel()
		db := openInviteMigDB(t, "corrupt_digesthex")
		// A 64-hex value that decodes to 32 bytes which are NOT a canonical
		// invite token text (hex of a real SHA-256 digest) has NO legitimate
		// historical representation: the pre-Task-7 code only ever stored
		// hex(token text), so this must fail the migration.
		seedInvitesFixture(t, db, func(ctx context.Context, db *sql.DB) error {
			_, err := db.ExecContext(ctx, `insert into registry_invites
				(registry_id, email, role, can_pull, can_push, token_hash, status, expires_at, created_at)
				values (1, 'bob@example.com', 'member', 1, 0, ?, 'pending', ?, ?)`,
				hex.EncodeToString(DigestInviteToken(tokenTextA)),
				time.Now().UTC().Add(time.Hour).Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339))
			return err
		})
		assertFailed(t, db)
	})

	t.Run("arbitrary digest hex on terminal accepted invite", func(t *testing.T) {
		t.Parallel()
		db := openInviteMigDB(t, "corrupt_digesthex_terminal")
		// Legacy accepted tokens are terminal, but their stored representation
		// is still validated before migration: an arbitrary 32-byte digest hex
		// is corrupt even on an accepted row and fails the upgrade.
		seedInvitesFixture(t, db, func(ctx context.Context, db *sql.DB) error {
			_, err := db.ExecContext(ctx, `insert into registry_invites
				(registry_id, email, role, can_pull, can_push, token_hash, status, expires_at, created_at)
				values (1, 'bob@example.com', 'member', 1, 0, ?, 'accepted', ?, ?)`,
				hex.EncodeToString(DigestInviteToken(tokenTextC)),
				time.Now().UTC().Add(time.Hour).Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339))
			return err
		})
		assertFailed(t, db)
	})

	t.Run("user email normalization collision", func(t *testing.T) {
		t.Parallel()
		db := openInviteMigDB(t, "corrupt_usercollision")
		ctx := context.Background()
		if err := applyMigrationsThrough(ctx, db, 3); err != nil {
			t.Fatalf("apply through v3: %v", err)
		}
		now := time.Now().UTC().Format(time.RFC3339)
		// Two legacy users whose normalized addresses collide: the migration
		// must detect the collision BEFORE updating anything and roll back
		// unchanged — no partial normalization, no version bump.
		for _, email := range []string{"A@Example.com", "a@example.com"} {
			if _, err := db.ExecContext(ctx, `insert into users (email, password_hash, created_at) values (?, ?, ?)`,
				email, "hash", now); err != nil {
				t.Fatalf("seed colliding user %s: %v", email, err)
			}
		}
		if _, err := db.ExecContext(ctx, `insert into registries
			(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at)
			values ('alice','alice.example.test','alice.eth',1,'0xfeed','','batch-1',1,?)`, now); err != nil {
			t.Fatalf("seed registry: %v", err)
		}
		if _, err := db.ExecContext(ctx, `insert into registry_memberships
			(registry_id, user_id, role, can_pull, can_push, created_at) values (1, 1, 'owner', 1, 1, ?)`, now); err != nil {
			t.Fatalf("seed membership: %v", err)
		}
		if err := ApplyMigrations(ctx, db); err == nil {
			t.Fatal("expected migration to fail on user email normalization collision")
		}
		version, err := CurrentSchemaVersion(ctx, db)
		if err != nil || version != 3 {
			t.Fatalf("version must stay 3 after rejected migration, got %d (err %v)", version, err)
		}
		// Rolled back unchanged: both users still carry their ORIGINAL emails
		// and the invites table was not rebuilt (no digest columns).
		var emails []string
		rows, err := db.QueryContext(ctx, `select email from users order by id`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var e string
			if err := rows.Scan(&e); err != nil {
				t.Fatal(err)
			}
			emails = append(emails, e)
		}
		rows.Close()
		if len(emails) != 2 || emails[0] != "A@Example.com" || emails[1] != "a@example.com" {
			t.Fatalf("user emails must be untouched after rollback, got %v", emails)
		}
		var hasDigest int
		if err := db.QueryRowContext(ctx, `select count(*) from pragma_table_info('registry_invites') where name = 'token_digest'`).Scan(&hasDigest); err != nil {
			t.Fatal(err)
		}
		if hasDigest != 0 {
			t.Fatal("invite rebuild must not survive a rejected migration")
		}
	})

	t.Run("invite recipient normalization collision is allowed", func(t *testing.T) {
		t.Parallel()
		db := openInviteMigDB(t, "ok_invitecollision")
		ctx := context.Background()
		if err := applyMigrationsThrough(ctx, db, 3); err != nil {
			t.Fatalf("apply through v3: %v", err)
		}
		now := time.Now().UTC().Format(time.RFC3339)
		expires := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
		if _, err := db.ExecContext(ctx, `insert into users (email, password_hash, created_at) values (?, ?, ?)`,
			"alice@example.com", "hash", now); err != nil {
			t.Fatalf("seed alice: %v", err)
		}
		if _, err := db.ExecContext(ctx, `insert into registries
			(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at)
			values ('alice','alice.example.test','alice.eth',1,'0xfeed','','batch-1',1,?)`, now); err != nil {
			t.Fatalf("seed registry: %v", err)
		}
		if _, err := db.ExecContext(ctx, `insert into registry_memberships
			(registry_id, user_id, role, can_pull, can_push, created_at) values (1, 1, 'owner', 1, 1, ?)`, now); err != nil {
			t.Fatalf("seed ownership: %v", err)
		}
		// Two invites whose recipients normalize to the same address: no
		// invariant forbids this (no unique invite-email constraint), so the
		// migration must normalize both and succeed.
		for j, email := range []string{"Bob@Example.com", "bob@example.com"} {
			tokenText := tokenTextA
			if j == 1 {
				tokenText = tokenTextB
			}
			if _, err := db.ExecContext(ctx, `insert into registry_invites
				(registry_id, email, role, can_pull, can_push, token_hash, status, expires_at, created_at)
				values (1, ?, 'member', 1, 1, ?, 'pending', ?, ?)`,
				email, hex.EncodeToString([]byte(tokenText)), expires, now); err != nil {
				t.Fatalf("seed invite %q: %v", email, err)
			}
		}
		if err := ApplyMigrations(ctx, db); err != nil {
			t.Fatalf("invite recipient normalization collision must not fail the migration: %v", err)
		}
		if got, err := CurrentSchemaVersion(ctx, db); err != nil || got != 8 {
			t.Fatalf("expected version 8, got %d (err %v)", got, err)
		}
		var emailA, emailB string
		if err := db.QueryRowContext(ctx, `select email from registry_invites where id = 1`).Scan(&emailA); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRowContext(ctx, `select email from registry_invites where id = 2`).Scan(&emailB); err != nil {
			t.Fatal(err)
		}
		if emailA != "bob@example.com" || emailB != "bob@example.com" {
			t.Fatalf("invite recipients must be normalized, got %q and %q", emailA, emailB)
		}
	})
}

// TestInviteSchemaTriggersEnforceLifecycle proves the migration-4 triggers
// close the direct-SQL gap: invites are born pending and terminal states are
// immutable.
func TestInviteSchemaTriggersEnforceLifecycle(t *testing.T) {
	t.Parallel()

	db := openInviteMigDB(t, "triggers")
	ctx := context.Background()
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := db.ExecContext(ctx, `insert into users (email, password_hash, created_at) values ('alice@example.com','hash',?)`, now); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.ExecContext(ctx, `insert into registries
		(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at)
		values ('alice','alice.example.test','alice.eth',1,'0xfeed','','batch-1',1,?)`, now); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	// Born pending only.
	if _, err := db.ExecContext(ctx, `insert into registry_invites
		(registry_id, email, role, can_pull, can_push, token_digest, status, expires_at, created_at)
		values (1, 'bob@example.com', 'member', 1, 0, zeroblob(32), 'accepted', ?, ?)`,
		now, now); err == nil {
		t.Fatal("expected born-pending trigger to reject non-pending insert")
	}
	// New inserts can never be legacy_unattributed: the flag is migration-only.
	if _, err := db.ExecContext(ctx, `insert into registry_invites
		(registry_id, email, role, can_pull, can_push, token_digest, status, accepted_by_user_id, legacy_unattributed, expires_at, created_at)
		values (1, 'bob@example.com', 'member', 1, 0, zeroblob(32), 'pending', NULL, 1, ?, ?)`,
		now, now); err == nil {
		t.Fatal("expected born-pending trigger to reject a legacy_unattributed insert")
	}
	if _, err := db.ExecContext(ctx, `insert into registry_invites
		(registry_id, email, role, can_pull, can_push, token_digest, status, expires_at, created_at)
		values (1, 'bob@example.com', 'member', 1, 0, zeroblob(32), 'pending', ?, ?)`,
		now, now); err != nil {
		t.Fatalf("pending insert must succeed: %v", err)
	}
	// The digest column is a strict 32-byte BLOB at the schema level: text,
	// short blobs, and oversized blobs are all rejected on insert AND update.
	for name, badDigest := range map[string]any{
		"text":       "short",
		"short blob": make([]byte, 16),
		"oversized":  make([]byte, 33),
	} {
		if _, err := db.ExecContext(ctx, `insert into registry_invites
			(registry_id, email, role, can_pull, can_push, token_digest, status, expires_at, created_at)
			values (1, 'x@example.com', 'member', 1, 0, ?, 'pending', ?, ?)`,
			badDigest, now, now); err == nil {
			t.Fatalf("expected token_digest CHECK to reject %s digest on insert", name)
		}
	}
	if _, err := db.ExecContext(ctx, `update registry_invites set token_digest = ? where id = 1`, make([]byte, 16)); err == nil {
		t.Fatal("expected token_digest CHECK to reject a short blob on update")
	}
	if _, err := db.ExecContext(ctx, `update registry_invites set token_digest = 'short' where id = 1`); err == nil {
		t.Fatal("expected token_digest CHECK to reject a text digest on update")
	}
	if _, err := db.ExecContext(ctx, `update registry_invites set token_digest = zeroblob(32) where id = 1`); err != nil {
		t.Fatalf("32-byte blob digest update must succeed: %v", err)
	}
	// Pending→accepted REQUIRES an attributed accepter; a row-level CHECK and
	// a trigger both reject an acceptance without one.
	if _, err := db.ExecContext(ctx, `update registry_invites set status = 'accepted' where id = 1`); err == nil {
		t.Fatal("expected acceptance without accepted_by to be rejected")
	}
	// Terminal states are immutable via direct SQL.
	if _, err := db.ExecContext(ctx, `update registry_invites set status = 'accepted', accepted_by_user_id = 1 where id = 1`); err != nil {
		t.Fatalf("pending→accepted with accepter must succeed: %v", err)
	}
	if _, err := db.ExecContext(ctx, `update registry_invites set status = 'pending' where id = 1`); err == nil {
		t.Fatal("expected terminal-status trigger to reject accepted→pending")
	}
	if _, err := db.ExecContext(ctx, `update registry_invites set status = 'revoked', revoked_at = ? where id = 1`, now); err == nil {
		t.Fatal("expected terminal-status trigger to reject accepted→revoked")
	}
	// The legacy_unattributed flag is migration-only: setting it to 1 on a
	// live row is always rejected.
	if _, err := db.ExecContext(ctx, `update registry_invites set legacy_unattributed = 1 where id = 1`); err == nil {
		t.Fatal("expected legacy-flag lock trigger to reject mutation into legacy_unattributed")
	}
}

// ---------------------------------------------------------------------------
// Legacy email normalization, unattributed acceptance, idempotent expiry, and
// ASCII-only identity semantics.
// ---------------------------------------------------------------------------

// TestInviteDigestMigrationNormalizesLegacyEmailsEveryVersion proves that at
// every supported starting schema version (0-3) the migration normalizes every
// existing user AND invite recipient with the production NormalizeEmail in the
// same transaction: post-upgrade logins and recipient acceptance work for
// whitespace/case legacy rows, and memberships/FKs survive untouched.
func TestInviteDigestMigrationNormalizesLegacyEmailsEveryVersion(t *testing.T) {
	t.Parallel()

	for _, version := range []int{0, 1, 2, 3} {
		version := version
		t.Run(fmt.Sprintf("from v%d", version), func(t *testing.T) {
			t.Parallel()
			db := openInviteMigDB(t, fmt.Sprintf("norm_%d", version))
			ctx := context.Background()
			if version == 0 {
				seedLegacyDBSchema(t, db)
			} else if err := applyMigrationsThrough(ctx, db, version); err != nil {
				t.Fatalf("apply through v%d: %v", version, err)
			}
			now := time.Now().UTC().Format(time.RFC3339)
			expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)

			seed := func(q string, args ...any) {
				t.Helper()
				if _, err := db.ExecContext(ctx, q, args...); err != nil {
					t.Fatalf("seed: %v", err)
				}
			}
			// Legacy rows carry surrounding whitespace + mixed case: the
			// pre-Task-7 flow stored strings.ToLower(email) only, no trim.
			seed(`insert into users (email, password_hash, created_at) values (?, ?, ?)`, "alice@example.com", "hash", now)
			seed(`insert into users (email, password_hash, created_at) values (?, ?, ?)`, "  Bob@Example.COM  ", "hash", now)
			seed(`insert into users (email, password_hash, created_at) values (?, ?, ?)`, "CAROL@example.com", "hash", now)
			seed(`insert into registries
				(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at)
				values ('alice', 'alice.example.test', 'alice.eth', 1, '0xfeed', '', 'batch-1', 1, ?)`, now)
			seed(`insert into registry_memberships (registry_id, user_id, role, can_pull, can_push, created_at) values (1, 1, 'owner', 1, 1, ?)`, now)
			seed(`insert into registry_memberships (registry_id, user_id, role, can_pull, can_push, created_at) values (1, 2, 'member', 1, 1, ?)`, now)
			seed(`insert into registry_invites (registry_id, email, role, can_pull, can_push, token_hash, status, expires_at, created_at)
				values (1, ?, 'member', 1, 1, ?, 'pending', ?, ?)`,
				"  Bob@Example.COM ", hex.EncodeToString([]byte(tokenTextA)), expires, now)
			seed(`insert into registry_invites (registry_id, email, role, can_pull, can_push, token_hash, status, expires_at, created_at)
				values (1, ?, 'member', 1, 1, ?, 'pending', ?, ?)`,
				"Carol@Example.com", hex.EncodeToString([]byte(tokenTextB)), expires, now)

			if err := ApplyMigrations(ctx, db); err != nil {
				t.Fatalf("apply migrations from v%d: %v", version, err)
			}
			if got, err := CurrentSchemaVersion(ctx, db); err != nil || got != 8 {
				t.Fatalf("expected schema version 8, got %d (err %v)", got, err)
			}

			// Users normalized to the canonical form.
			var bobEmail, carolEmail string
			if err := db.QueryRowContext(ctx, `select email from users where id = 2`).Scan(&bobEmail); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRowContext(ctx, `select email from users where id = 3`).Scan(&carolEmail); err != nil {
				t.Fatal(err)
			}
			if bobEmail != "bob@example.com" || carolEmail != "carol@example.com" {
				t.Fatalf("users must be normalized, got %q and %q", bobEmail, carolEmail)
			}
			// Invite recipients normalized too.
			var invBob, invCarol string
			if err := db.QueryRowContext(ctx, `select email from registry_invites where id = 1`).Scan(&invBob); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRowContext(ctx, `select email from registry_invites where id = 2`).Scan(&invCarol); err != nil {
				t.Fatal(err)
			}
			if invBob != "bob@example.com" || invCarol != "carol@example.com" {
				t.Fatalf("invite recipients must be normalized, got %q and %q", invBob, invCarol)
			}

			store := &Store{DB: db}
			// Post-upgrade login lookup works for the canonical address.
			user, err := store.FindUserByEmail(ctx, "bob@example.com")
			if err != nil || user.ID != 2 {
				t.Fatalf("post-upgrade login lookup for bob must resolve user 2, got %+v err %v", user, err)
			}
			// Recipient acceptance works: bob is already a member, so his
			// acceptance MERGES (no new membership); carol's inserts one.
			if _, err := store.AcceptInvite(ctx, tokenTextA, User{ID: 2, Email: "bob@example.com"}); err != nil {
				t.Fatalf("bob must accept his normalized invite: %v", err)
			}
			if _, err := store.AcceptInvite(ctx, tokenTextB, User{ID: 3, Email: "carol@example.com"}); err != nil {
				t.Fatalf("carol must accept her normalized invite: %v", err)
			}
			memberships, err := store.ListMembershipsForRegistry(ctx, 1)
			if err != nil {
				t.Fatalf("list memberships: %v", err)
			}
			if len(memberships) != 3 { // owner + bob (pre-seeded) + carol
				t.Fatalf("expected 3 memberships, got %d", len(memberships))
			}
			// Foreign keys are fully intact after the in-place normalization.
			var bad int
			fkRows, err := db.QueryContext(ctx, `PRAGMA foreign_key_check`)
			if err != nil {
				t.Fatal(err)
			}
			for fkRows.Next() {
				bad++
			}
			fkRows.Close()
			if bad != 0 {
				t.Fatalf("foreign_key_check reported %d violations after normalization", bad)
			}
		})
	}
}

// TestInviteLegacyAcceptedUnattributedNoFalseAttributionOrRetry pins the
// binding ruling: an accepted legacy invite whose recipient is ALREADY a
// member is preserved as legacy_unattributed with accepted_by_user_id NULL —
// the membership never becomes a false attribution, and the terminal token
// never succeeds again for the recipient or anyone else.
func TestInviteLegacyAcceptedUnattributedNoFalseAttributionOrRetry(t *testing.T) {
	t.Parallel()

	db := openInviteMigDB(t, "legacy_unattributed")
	ctx := context.Background()
	if err := applyMigrationsThrough(ctx, db, 3); err != nil {
		t.Fatalf("apply through v3: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	seed := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	seed(`insert into users (email, password_hash, created_at) values (?, ?, ?)`, "alice@example.com", "hash", now)
	seed(`insert into users (email, password_hash, created_at) values (?, ?, ?)`, "bob@example.com", "hash", now)
	seed(`insert into users (email, password_hash, created_at) values (?, ?, ?)`, "dave@example.com", "hash", now)
	seed(`insert into registries
		(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at)
		values ('alice', 'alice.example.test', 'alice.eth', 1, '0xfeed', '', 'batch-1', 1, ?)`, now)
	seed(`insert into registry_memberships (registry_id, user_id, role, can_pull, can_push, created_at) values (1, 1, 'owner', 1, 1, ?)`, now)
	// Exact old-behavior fixture: dave is the intended recipient AND already
	// a member; bob is a DIFFERENT user who historically accepted the invite
	// and got his own membership (the pre-Task-7 acceptance path took any
	// authenticated token holder and inserted their membership without a
	// recipient check). Attribution is impossible, so the invite must survive
	// unchanged as legacy_unattributed and neither user's retry can succeed.
	seed(`insert into registry_memberships (registry_id, user_id, role, can_pull, can_push, created_at) values (1, 3, 'member', 1, 1, ?)`, now)
	seed(`insert into registry_memberships (registry_id, user_id, role, can_pull, can_push, created_at) values (1, 2, 'member', 1, 1, ?)`, now)
	seed(`insert into registry_invites (registry_id, email, role, can_pull, can_push, token_hash, status, expires_at, created_at)
		values (1, 'dave@example.com', 'member', 1, 1, ?, 'accepted', ?, ?)`,
		hex.EncodeToString([]byte(tokenTextC)), expires, now)

	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	var acceptedBy sql.NullInt64
	var legacyFlag int
	if err := db.QueryRowContext(ctx, `select accepted_by_user_id, legacy_unattributed from registry_invites where id = 1`).Scan(&acceptedBy, &legacyFlag); err != nil {
		t.Fatal(err)
	}
	if acceptedBy.Valid {
		t.Fatalf("recipient membership must never become false attribution, got user %d", acceptedBy.Int64)
	}
	if legacyFlag != 1 {
		t.Fatalf("expected legacy_unattributed=1, got %d", legacyFlag)
	}

	store := &Store{DB: db}
	// No retry ever succeeds — not the recipient, not anyone else.
	if _, err := store.AcceptInvite(ctx, tokenTextC, User{ID: 3, Email: "dave@example.com"}); !errors.Is(err, errInviteNotFound) {
		t.Fatalf("recipient retry against legacy_unattributed invite must fail generically, got %v", err)
	}
	if _, err := store.AcceptInvite(ctx, tokenTextC, User{ID: 2, Email: "bob@example.com"}); !errors.Is(err, errInviteNotFound) {
		t.Fatalf("foreign retry against legacy_unattributed invite must fail generically, got %v", err)
	}
	// No state mutation: still accepted, no new membership, dave's
	// pre-existing membership untouched.
	var status string
	if err := db.QueryRowContext(ctx, `select status from registry_invites where id = 1`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "accepted" {
		t.Fatalf("legacy invite must stay accepted, got %q", status)
	}
	memberships, err := store.ListMembershipsForRegistry(ctx, 1)
	if err != nil {
		t.Fatalf("list memberships: %v", err)
	}
	if len(memberships) != 3 {
		t.Fatalf("no membership change allowed: expected 3, got %d", len(memberships))
	}
	for _, m := range memberships {
		if (m.UserID == 2 || m.UserID == 3) && (m.Role != "member" || !m.CanPull || !m.CanPush) {
			t.Fatalf("user %d's pre-existing membership must be untouched, got %+v", m.UserID, m)
		}
	}
}

// TestInviteLegacyAcceptedPreservedWithoutRecipientMembership proves every
// schema-valid accepted legacy invite migrates as legacy_unattributed with NO
// membership requirement: the historical accepter is unknowable (the
// pre-Task-7 acceptance path bound neither the recipient nor the accepter),
// and current membership state cannot establish attribution — the recipient's
// membership may never have existed or may have been removed later. Memberships
// are untouched and token retries always fail generically.
func TestInviteLegacyAcceptedPreservedWithoutRecipientMembership(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	seedBase := func(t *testing.T, db *sql.DB) (string, string) {
		t.Helper()
		now := time.Now().UTC().Format(time.RFC3339)
		expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
		seed := func(q string, args ...any) {
			t.Helper()
			if _, err := db.ExecContext(ctx, q, args...); err != nil {
				t.Fatalf("seed: %v", err)
			}
		}
		seed(`insert into users (email, password_hash, created_at) values (?, ?, ?)`, "alice@example.com", "hash", now)
		seed(`insert into users (email, password_hash, created_at) values (?, ?, ?)`, "bob@example.com", "hash", now)
		seed(`insert into registries
			(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at)
			values ('alice', 'alice.example.test', 'alice.eth', 1, '0xfeed', '', 'batch-1', 1, ?)`, now)
		seed(`insert into registry_memberships (registry_id, user_id, role, can_pull, can_push, created_at) values (1, 1, 'owner', 1, 1, ?)`, now)
		return now, expires
	}

	// assertPreserved checks the migrated row is accepted, unattributed, and
	// legacy-flagged, that memberships are byte-count untouched, and that the
	// token can never be replayed by anyone.
	assertPreserved := func(t *testing.T, db *sql.DB, wantMemberships int) {
		t.Helper()
		var status string
		var acceptedBy sql.NullInt64
		var legacyFlag int
		if err := db.QueryRowContext(ctx, `select status, accepted_by_user_id, legacy_unattributed from registry_invites where id = 1`).
			Scan(&status, &acceptedBy, &legacyFlag); err != nil {
			t.Fatal(err)
		}
		if status != "accepted" {
			t.Fatalf("expected preserved status accepted, got %q", status)
		}
		if acceptedBy.Valid {
			t.Fatalf("accepted history must never be attributed, got user %d", acceptedBy.Int64)
		}
		if legacyFlag != 1 {
			t.Fatalf("expected legacy_unattributed=1, got %d", legacyFlag)
		}
		var count int
		if err := db.QueryRowContext(ctx, `select count(*) from registry_memberships`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != wantMemberships {
			t.Fatalf("memberships must be untouched, got %d want %d", count, wantMemberships)
		}
		store := &Store{DB: db}
		if _, err := store.AcceptInvite(ctx, tokenTextC, User{ID: 2, Email: "bob@example.com"}); !errors.Is(err, errInviteNotFound) {
			t.Fatalf("token retry against the preserved invite must fail generically, got %v", err)
		}
	}

	t.Run("recipient never had a membership", func(t *testing.T) {
		t.Parallel()
		db := openInviteMigDB(t, "accepted_no_membership")
		if err := applyMigrationsThrough(ctx, db, 3); err != nil {
			t.Fatalf("apply through v3: %v", err)
		}
		now, expires := seedBase(t, db)
		// ghost@example.com is the registered recipient with NO account and NO
		// membership: a different authenticated user accepted in the legacy
		// era. The migration must preserve the accept, not reject it.
		if _, err := db.ExecContext(ctx, `insert into registry_invites
			(registry_id, email, role, can_pull, can_push, token_hash, status, expires_at, created_at)
			values (1, 'ghost@example.com', 'member', 1, 0, ?, 'accepted', ?, ?)`,
			hex.EncodeToString([]byte(tokenTextC)), expires, now); err != nil {
			t.Fatalf("seed accepted invite: %v", err)
		}
		if err := ApplyMigrations(ctx, db); err != nil {
			t.Fatalf("accepted invite without any membership must NOT fail the migration: %v", err)
		}
		assertPreserved(t, db, 1)
	})

	t.Run("recipient membership removed after acceptance", func(t *testing.T) {
		t.Parallel()
		db := openInviteMigDB(t, "accepted_membership_removed")
		if err := applyMigrationsThrough(ctx, db, 3); err != nil {
			t.Fatalf("apply through v3: %v", err)
		}
		now, expires := seedBase(t, db)
		if _, err := db.ExecContext(ctx, `insert into users (email, password_hash, created_at) values (?, ?, ?)`,
			"dave@example.com", "hash", now); err != nil {
			t.Fatalf("seed dave: %v", err)
		}
		// dave's membership was created atomically with the historical
		// acceptance and REMOVED later: current membership is not evidence of
		// anything and must not be required for preservation.
		if _, err := db.ExecContext(ctx, `insert into registry_memberships (registry_id, user_id, role, can_pull, can_push, created_at) values (1, 3, 'member', 1, 1, ?)`, now); err != nil {
			t.Fatalf("seed dave membership: %v", err)
		}
		if _, err := db.ExecContext(ctx, `delete from registry_memberships where registry_id = 1 and user_id = 3`); err != nil {
			t.Fatalf("remove dave membership: %v", err)
		}
		if _, err := db.ExecContext(ctx, `insert into registry_invites
			(registry_id, email, role, can_pull, can_push, token_hash, status, expires_at, created_at)
			values (1, 'dave@example.com', 'member', 1, 1, ?, 'accepted', ?, ?)`,
			hex.EncodeToString([]byte(tokenTextC)), expires, now); err != nil {
			t.Fatalf("seed accepted invite: %v", err)
		}
		if err := ApplyMigrations(ctx, db); err != nil {
			t.Fatalf("accepted invite whose membership was removed later must NOT fail the migration: %v", err)
		}
		assertPreserved(t, db, 1)
	})
}

// TestInviteLegacyUnattributedRowsImmutable proves that after migration,
// legacy_unattributed accepted invites are FULLY immutable: ordinary SQL
// cannot clear the flag, assign an accepter, change status or timestamps, or
// otherwise turn the row into an attributed acceptance. A BEFORE UPDATE
// trigger rejects EVERY update to such a row, and the row is unchanged after
// each rejected attempt. Non-legacy rows stay fully updatable, and a fresh
// pending→accepted transition records accepted_by with legacy_unattributed=0.
func TestInviteLegacyUnattributedRowsImmutable(t *testing.T) {
	t.Parallel()

	db := openInviteMigDB(t, "legacy_immutable")
	ctx := context.Background()
	if err := applyMigrationsThrough(ctx, db, 3); err != nil {
		t.Fatalf("apply through v3: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	seed := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	seed(`insert into users (email, password_hash, created_at) values (?, ?, ?)`, "alice@example.com", "hash", now)
	seed(`insert into users (email, password_hash, created_at) values (?, ?, ?)`, "bob@example.com", "hash", now)
	seed(`insert into registries
		(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at)
		values ('alice', 'alice.example.test', 'alice.eth', 1, '0xfeed', '', 'batch-1', 1, ?)`, now)
	seed(`insert into registry_memberships (registry_id, user_id, role, can_pull, can_push, created_at) values (1, 1, 'owner', 1, 1, ?)`, now)
	seed(`insert into registry_invites (registry_id, email, role, can_pull, can_push, token_hash, status, expires_at, created_at)
		values (1, 'dave@example.com', 'member', 1, 1, ?, 'accepted', ?, ?)`,
		hex.EncodeToString([]byte(tokenTextC)), expires, now)

	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	type inviteRow struct {
		status           string
		acceptedBy       sql.NullInt64
		legacy           int
		acceptedAt       sql.NullString
		revokedAt        sql.NullString
		expiresAt        string
		canPull, canPush int
	}
	readRow := func() inviteRow {
		t.Helper()
		var r inviteRow
		if err := db.QueryRowContext(ctx, `select status, accepted_by_user_id, legacy_unattributed, accepted_at, revoked_at, expires_at, can_pull, can_push from registry_invites where id = 1`).
			Scan(&r.status, &r.acceptedBy, &r.legacy, &r.acceptedAt, &r.revokedAt, &r.expiresAt, &r.canPull, &r.canPush); err != nil {
			t.Fatal(err)
		}
		return r
	}
	before := readRow()
	if before.legacy != 1 {
		t.Fatalf("fixture must be a legacy_unattributed row, got legacy=%d", before.legacy)
	}

	attempts := []struct {
		name string
		sql  string
		args []any
	}{
		{"clear legacy flag", `update registry_invites set legacy_unattributed = 0 where id = 1`, nil},
		{"set accepted_by", `update registry_invites set accepted_by_user_id = 2 where id = 1`, nil},
		{"change status to revoked", `update registry_invites set status = 'revoked', revoked_at = ? where id = 1`, []any{now}},
		{"change accepted_at", `update registry_invites set accepted_at = ? where id = 1`, []any{now}},
		{"set revoked_at", `update registry_invites set revoked_at = ? where id = 1`, []any{now}},
		{"combined attribution rewrite", `update registry_invites set legacy_unattributed = 0, accepted_by_user_id = 2, status = 'accepted', accepted_at = ? where id = 1`, []any{now}},
		{"benign expires change", `update registry_invites set expires_at = ? where id = 1`, []any{now}},
		{"benign permission change", `update registry_invites set can_pull = 0 where id = 1`, nil},
		{"benign recipient change", `update registry_invites set email = 'x@example.com' where id = 1`, nil},
		{"digest replace", `update registry_invites set token_digest = ? where id = 1`, []any{make([]byte, 32)}},
	}
	for _, a := range attempts {
		if _, err := db.ExecContext(ctx, a.sql, a.args...); err == nil {
			t.Fatalf("%s: expected the legacy immutability trigger to reject the update, got nil error", a.name)
		}
		if after := readRow(); after != before {
			t.Fatalf("%s: row mutated despite rejection: %+v != %+v", a.name, after, before)
		}
	}

	// A live (non-legacy) row is still fully updatable: the immutability
	// trigger is scoped to legacy_unattributed rows only.
	seed(`insert into registry_invites (registry_id, email, role, can_pull, can_push, token_digest, status, expires_at, created_at)
		values (1, 'bob@example.com', 'member', 1, 1, zeroblob(32), 'pending', ?, ?)`, expires, now)
	if _, err := db.ExecContext(ctx, `update registry_invites set can_push = 0 where id = 2`); err != nil {
		t.Fatalf("benign update on a non-legacy row must still succeed: %v", err)
	}

	// A fresh pending→accepted transition records accepted_by and
	// legacy_unattributed=0: the application path can never enter legacy state.
	store := &Store{DB: db}
	created, token, err := store.CreateInvite(ctx, Invite{
		RegistryID: 1, Email: "bob@example.com", Role: "member",
		CanPull: true, CanPush: true, ExpiresAt: time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	if _, err := store.AcceptInvite(ctx, token, User{ID: 2, Email: "bob@example.com"}); err != nil {
		t.Fatalf("accept fresh invite: %v", err)
	}
	var newLegacy int
	var newAcceptedBy sql.NullInt64
	if err := db.QueryRowContext(ctx, `select legacy_unattributed, accepted_by_user_id from registry_invites where id = ?`, created.ID).
		Scan(&newLegacy, &newAcceptedBy); err != nil {
		t.Fatal(err)
	}
	if newLegacy != 0 {
		t.Fatalf("new acceptance must carry legacy_unattributed=0, got %d", newLegacy)
	}
	if !newAcceptedBy.Valid || newAcceptedBy.Int64 != 2 {
		t.Fatalf("new acceptance must record the attributed accepter, got %+v", newAcceptedBy)
	}
}

// ---------------------------------------------------------------------------
// Fix round 3: forward-only migration 5 — the immutable legacy-attribution
// trigger must be delivered by a NEW migration, never by editing an applied
// migration.
// ---------------------------------------------------------------------------

// seedPrefixV4DigestDB builds the EXACT schema state that migration 4 shipped
// at head 8178a82 (the pre-fix migration): the digest-schema registry_invites
// with the four state/attribution triggers (born_pending, terminal_status,
// no_unattributed_acceptance, legacy_flag_locked) and WITHOUT
// registry_invites_legacy_attribution_immutable. The immutability trigger was
// added later by EDITING migration 4 (ef48240), so any database that applied
// the pre-fix v4 records schema_migrations.version = 4 and skips the corrected
// code forever — that is the delivery flaw this round fixes.
//
// The fixture is reproduced by hand and deliberately NEVER calls the current
// migration 4: a call to the current (corrected) migration would silently
// absorb the fix and prove nothing. Ordering mirrors the real migration —
// tables, then the legacy backfill rows, then triggers, then the recorded
// version — because the born-pending trigger rejects non-pending inserts and
// must not be live during the backfill.
func seedPrefixV4DigestDB(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()

	// v1-constrained parents exactly as migrations 1-3 produced them.
	for _, stmt := range []string{
		`create table users (
			id integer primary key autoincrement,
			email text not null unique,
			password_hash text not null,
			created_at text not null
		)`,
		`create table registries (
			id integer primary key autoincrement,
			slug text not null unique,
			host text not null unique,
			ens_name text not null,
			owner_user_id integer not null references users(id),
			feed_owner_address text not null,
			encrypted_feed_private_key text not null,
			default_stamp_batch_id text not null,
			anonymous_pull integer not null,
			created_at text not null
		)`,
		`create table registry_memberships (
			id integer primary key autoincrement,
			registry_id integer not null references registries(id) on delete cascade,
			user_id integer not null references users(id) on delete cascade,
			role text not null,
			can_pull integer not null,
			can_push integer not null,
			created_at text not null,
			unique(registry_id, user_id)
		)`,
		// The digest-schema registry_invites exactly as the pre-fix migration
		// 4 rebuilt it (identical at 8178a82 and ef48240).
		`create table registry_invites (
			id integer primary key autoincrement,
			registry_id integer not null references registries(id) on delete cascade,
			email text not null,
			role text not null,
			can_pull integer not null,
			can_push integer not null,
			token_digest blob not null unique check (typeof(token_digest) = 'blob' and length(token_digest) = 32),
			status text not null check (status in ('pending','accepted','revoked')),
			accepted_by_user_id integer references users(id),
			legacy_unattributed integer not null default 0 check (legacy_unattributed in (0,1)),
			expires_at text not null,
			accepted_at text,
			revoked_at text,
			created_at text not null,
			check (can_pull = 1 or can_push = 1),
			check ((status = 'revoked') = (revoked_at is not null)),
			check (status <> 'accepted' or accepted_by_user_id is not null or legacy_unattributed = 1),
			check (accepted_at is null or status = 'accepted')
		)`,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("build pre-fix v4 schema: %v", err)
		}
	}

	now := time.Now().UTC().Format(time.RFC3339)
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	seed := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("seed pre-fix v4 row: %v", err)
		}
	}
	seed(`insert into users (email, password_hash, created_at) values (?, ?, ?)`, "alice@example.com", "hash", now)
	seed(`insert into users (email, password_hash, created_at) values (?, ?, ?)`, "bob@example.com", "hash", now)
	seed(`insert into users (email, password_hash, created_at) values (?, ?, ?)`, "carol@example.com", "hash", now)
	seed(`insert into registries
		(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at)
		values ('alice', 'alice.example.test', 'alice.eth', 1, '0xfeed', '', 'batch-1', 1, ?)`, now)
	seed(`insert into registry_memberships (registry_id, user_id, role, can_pull, can_push, created_at) values (1, 1, 'owner', 1, 1, ?)`, now)
	// Two valid legacy_unattributed accepted rows (migration-4 backfill shape:
	// status accepted, accepted_by NULL, legacy flag 1, no accepted_at). Row 1
	// is the pre-fix vulnerability victim; row 2 stays pristine for the
	// post-repair immutability battery.
	seed(`insert into registry_invites
		(registry_id, email, role, can_pull, can_push, token_digest, status, accepted_by_user_id, legacy_unattributed, expires_at, accepted_at, revoked_at, created_at)
		values (1, 'bob@example.com', 'member', 1, 1, ?, 'accepted', NULL, 1, ?, NULL, NULL, ?)`,
		DigestInviteToken(tokenTextA), expires, now)
	seed(`insert into registry_invites
		(registry_id, email, role, can_pull, can_push, token_digest, status, accepted_by_user_id, legacy_unattributed, expires_at, accepted_at, revoked_at, created_at)
		values (1, 'carol@example.com', 'member', 1, 1, ?, 'accepted', NULL, 1, ?, NULL, NULL, ?)`,
		DigestInviteToken(tokenTextB), expires, now)

	// The pre-fix (8178a82) trigger set — NO immutability trigger. The fixture
	// also self-verifies that the shipped state it reproduces really is the
	// vulnerable one: if a future edit sneaks the immutability trigger in
	// here, the regression silently stops regressing.
	for _, stmt := range []string{
		`create trigger registry_invites_born_pending before insert on registry_invites
			for each row when NEW.status != 'pending' or NEW.legacy_unattributed != 0
			begin select raise(abort, 'invites must be created pending and attributed'); end`,
		`create trigger registry_invites_terminal_status before update of status on registry_invites
			for each row when OLD.status != 'pending' and NEW.status != OLD.status
			begin select raise(abort, 'invite status is terminal and cannot be changed'); end`,
		`create trigger registry_invites_no_unattributed_acceptance before update of status on registry_invites
			for each row when NEW.status = 'accepted' and NEW.accepted_by_user_id is null
			begin select raise(abort, 'acceptance requires an attributed accepter'); end`,
		`create trigger registry_invites_legacy_flag_locked before update of legacy_unattributed on registry_invites
			for each row when NEW.legacy_unattributed != OLD.legacy_unattributed and NEW.legacy_unattributed = 1
			begin select raise(abort, 'legacy_unattributed is migration-only state and cannot be set'); end`,
		`create index idx_registry_invites_registry_status on registry_invites(registry_id, status)`,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("install pre-fix v4 triggers: %v", err)
		}
	}
	var n int
	if err := db.QueryRowContext(ctx, `select count(*) from sqlite_master where type = 'trigger' and name = 'registry_invites_legacy_attribution_immutable'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("fixture defect: the pre-fix v4 fixture must NOT carry the immutability trigger")
	}
	// Record the applied version exactly like the pre-fix migration did.
	if _, err := db.ExecContext(ctx, `create table schema_migrations (version integer primary key, applied_at text not null)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `insert into schema_migrations (version, applied_at) values (4, ?)`, now); err != nil {
		t.Fatal(err)
	}
}

// assertLegacyAttributionImmutableTrigger proves the immutability trigger is
// installed with the GUARDING SEMANTICS, not just its name: it must be a
// BEFORE UPDATE trigger on registry_invites that aborts every update to a row
// whose OLD.legacy_unattributed = 1. Reading the stored trigger SQL (rather
// than trusting the name) pins the behavior the pre-fix v4 lacked. The
// behavioral side is covered by the UPDATE batteries in the tests themselves.
func assertLegacyAttributionImmutableTrigger(t *testing.T, db *sql.DB) {
	t.Helper()
	var sql string
	if err := db.QueryRow(`select sql from sqlite_master where type = 'trigger' and name = 'registry_invites_legacy_attribution_immutable'`).Scan(&sql); err != nil {
		t.Fatalf("read immutability trigger SQL: %v", err)
	}
	lower := strings.ToLower(sql)
	for _, needle := range []string{"before update on registry_invites", "old.legacy_unattributed = 1"} {
		if !strings.Contains(lower, needle) {
			t.Fatalf("immutability trigger SQL missing guard %q: %s", needle, sql)
		}
	}
}

// TestInviteLegacyAttributionPrefixV4RepairedByMigrationV5 is the RED
// regression for the migration-delivery flaw: a database that applied the
// PRE-FIX migration 4 (head 8178a82) has schema_migrations.version = 4 and
// never runs the corrected code — its legacy_unattributed rows stay writable
// and ordinary SQL can turn frozen history into an attributed acceptance. The
// test reproduces that exact shipped state (never calling the current
// migration 4), proves the attribution rewrite SUCCEEDS pre-repair, applies
// the current migration chain so forward-only migration 5 runs, and proves the
// rewrite now FAILS with the row unchanged, application token retries are
// generic, and the new-attributed lifecycle is not weakened.
func TestInviteLegacyAttributionPrefixV4RepairedByMigrationV5(t *testing.T) {
	t.Parallel()

	db := openInviteMigDB(t, "v5_prefix_v4_repair")
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)
	seedPrefixV4DigestDB(t, db)

	// ---- Pre-repair: the hole is real. On the shipped v4 schema, clearing
	// the legacy flag, assigning an accepter, and stamping accepted_at all
	// succeed — the frozen record becomes an attributed acceptance.
	if _, err := db.ExecContext(ctx, `update registry_invites set legacy_unattributed = 0, accepted_by_user_id = 2, accepted_at = ? where id = 1`, now); err != nil {
		t.Fatalf("pre-fix v4 must permit the attribution rewrite of a legacy_unattributed row, got: %v", err)
	}
	// The rewrite is one-way (the pre-fix legacy_flag_locked trigger still
	// blocks 0->1 re-arming), so the damaged row stays attributed. Migration 5
	// must NOT retro-detect or rewrite it: attribution legitimacy is not
	// distinguishable once fabricated, so v5 closes FUTURE mutation only.
	// Row 2 remains pristine for the immutability battery below.

	// ---- Apply the current migration chain. Only migration 5 can run (v1-v4
	// are already recorded) and it must install the authoritative trigger.
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("apply migrations over pre-fix v4: %v", err)
	}
	version, err := CurrentSchemaVersion(ctx, db)
	if err != nil {
		t.Fatalf("schema version: %v", err)
	}
	if version != 8 {
		t.Fatalf("expected schema version 8 after repair, got %d", version)
	}
	var migCount int
	if err := db.QueryRowContext(ctx, `select count(*) from schema_migrations`).Scan(&migCount); err != nil {
		t.Fatal(err)
	}
	if migCount != 5 {
		t.Fatalf("expected exactly 5 recorded migrations (fixture's v4 + forward 5 + forward 6 + forward 7 + forward 8), got %d", migCount)
	}
	assertLegacyAttributionImmutableTrigger(t, db)

	// ---- The repaired trigger rejects every rewrite attempt on the pristine
	// legacy row and leaves it byte-identical after each rejection.
	type legacyRow struct {
		status           string
		acceptedBy       sql.NullInt64
		legacy           int
		acceptedAt       sql.NullString
		revokedAt        sql.NullString
		expiresAt        string
		canPull, canPush int
		email            string
		digest           string
	}
	readRow := func(id int64) legacyRow {
		t.Helper()
		var r legacyRow
		var digest []byte
		if err := db.QueryRowContext(ctx, `select status, accepted_by_user_id, legacy_unattributed, accepted_at, revoked_at, expires_at, can_pull, can_push, email, token_digest from registry_invites where id = ?`, id).
			Scan(&r.status, &r.acceptedBy, &r.legacy, &r.acceptedAt, &r.revokedAt, &r.expiresAt, &r.canPull, &r.canPush, &r.email, &digest); err != nil {
			t.Fatal(err)
		}
		r.digest = string(digest)
		return r
	}
	pristine := readRow(2)
	if pristine.legacy != 1 {
		t.Fatalf("fixture defect: row 2 must be legacy_unattributed, got legacy=%d", pristine.legacy)
	}
	attempts := []struct {
		name string
		sql  string
		args []any
	}{
		{"clear legacy flag", `update registry_invites set legacy_unattributed = 0 where id = 2`, nil},
		{"set accepted_by", `update registry_invites set accepted_by_user_id = 3 where id = 2`, nil},
		{"change status to revoked", `update registry_invites set status = 'revoked', revoked_at = ? where id = 2`, []any{now}},
		{"change accepted_at", `update registry_invites set accepted_at = ? where id = 2`, []any{now}},
		{"set revoked_at", `update registry_invites set revoked_at = ? where id = 2`, []any{now}},
		{"combined attribution rewrite", `update registry_invites set legacy_unattributed = 0, accepted_by_user_id = 3, status = 'accepted', accepted_at = ? where id = 2`, []any{now}},
		{"benign expires change", `update registry_invites set expires_at = ? where id = 2`, []any{now}},
		{"benign permission change", `update registry_invites set can_pull = 0 where id = 2`, nil},
		{"benign recipient change", `update registry_invites set email = 'x@example.com' where id = 2`, nil},
		{"digest replace", `update registry_invites set token_digest = ? where id = 2`, []any{make([]byte, 32)}},
	}
	for _, a := range attempts {
		if _, err := db.ExecContext(ctx, a.sql, a.args...); err == nil {
			t.Fatalf("%s: expected the repaired immutability trigger to reject the update, got nil error", a.name)
		}
		if after := readRow(2); after != pristine {
			t.Fatalf("%s: row mutated despite rejection: %+v != %+v", a.name, after, pristine)
		}
	}

	// ---- Migration 5 is data-free: the pre-repair-damaged row 1 stays
	// exactly as the rewrite left it (no retrospective detection/rewrite).
	row1 := readRow(1)
	if row1.legacy != 0 || !row1.acceptedBy.Valid || row1.acceptedBy.Int64 != 2 || !row1.acceptedAt.Valid {
		t.Fatalf("row 1 must remain as the pre-repair rewrite left it (v5 is data-free), got %+v", row1)
	}

	// ---- Application token retries fail generically against BOTH rows and
	// mutate nothing.
	store := &Store{DB: db}
	if _, err := store.AcceptInvite(ctx, tokenTextB, User{ID: 3, Email: "carol@example.com"}); !errors.Is(err, errInviteNotFound) {
		t.Fatalf("legacy_unattributed retry must fail generically after repair, got %v", err)
	}
	if _, err := store.AcceptInvite(ctx, tokenTextA, User{ID: 2, Email: "bob@example.com"}); !errors.Is(err, errInviteNotFound) {
		t.Fatalf("attribution-rewritten row retry must fail generically, got %v", err)
	}
	if after := readRow(2); after != pristine {
		t.Fatalf("row 2 mutated by a generic retry: %+v != %+v", after, pristine)
	}

	// ---- The fix does not weaken the new-attributed lifecycle: born-pending
	// still rejects direct non-pending inserts, non-legacy rows stay
	// updatable, and a fresh pending→accepted transition records the attributed
	// accepter with legacy_unattributed=0.
	if _, err := db.ExecContext(ctx, `insert into registry_invites
		(registry_id, email, role, can_pull, can_push, token_digest, status, expires_at, created_at)
		values (1, 'x@example.com', 'member', 1, 0, ?, 'accepted', ?, ?)`,
		DigestInviteToken(tokenTextC), now, now); err == nil {
		t.Fatal("expected born-pending trigger to reject a non-pending insert after repair")
	}
	if _, err := db.ExecContext(ctx, `insert into registry_invites
		(registry_id, email, role, can_pull, can_push, token_digest, status, expires_at, created_at)
		values (1, 'x@example.com', 'member', 1, 0, ?, 'pending', ?, ?)`,
		DigestInviteToken(tokenTextC), now, now); err != nil {
		t.Fatalf("pending insert must succeed: %v", err)
	}
	if _, err := db.ExecContext(ctx, `update registry_invites set can_push = 1 where id = 3`); err != nil {
		t.Fatalf("benign update on a non-legacy row must still succeed: %v", err)
	}
	created, token, err := store.CreateInvite(ctx, Invite{
		RegistryID: 1, Email: "bob@example.com", Role: "member",
		CanPull: true, CanPush: true, ExpiresAt: time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("create fresh invite: %v", err)
	}
	if _, err := store.AcceptInvite(ctx, token, User{ID: 2, Email: "bob@example.com"}); err != nil {
		t.Fatalf("accept fresh invite: %v", err)
	}
	var newLegacy int
	var newAcceptedBy sql.NullInt64
	if err := db.QueryRowContext(ctx, `select legacy_unattributed, accepted_by_user_id from registry_invites where id = ?`, created.ID).
		Scan(&newLegacy, &newAcceptedBy); err != nil {
		t.Fatal(err)
	}
	if newLegacy != 0 || !newAcceptedBy.Valid || newAcceptedBy.Int64 != 2 {
		t.Fatalf("fresh acceptance must record the attributed accepter with legacy_unattributed=0, got legacy=%d accepted_by=%+v", newLegacy, newAcceptedBy)
	}

	// ---- Re-applying migrations is a no-op at v5.
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("re-apply migrations after repair: %v", err)
	}
	if version, err := CurrentSchemaVersion(ctx, db); err != nil || version != 8 {
		t.Fatalf("version must stay 8 on re-apply, got %d (err %v)", version, err)
	}
	assertLegacyAttributionImmutableTrigger(t, db)
}

// TestInviteMigrationV5FromCleanV4Schema drives the forward-only repair bridge
// from a CLEAN current v4 schema (migration 4 already installed the immutable
// trigger): migration 5 must drop the same-named trigger and recreate the
// authoritative one idempotently, ending at version 5 with the same protection.
func TestInviteMigrationV5FromCleanV4Schema(t *testing.T) {
	t.Parallel()

	db := openInviteMigDB(t, "v5_clean_v4")
	ctx := context.Background()
	if err := applyMigrationsThrough(ctx, db, 3); err != nil {
		t.Fatalf("apply through v3: %v", err)
	}
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	seedInvitesDigestFixture(t, db, expires)
	// Current migration 4: converts the legacy rows and ALREADY installs the
	// immutability trigger (the corrected v4).
	if err := applyMigrationsThrough(ctx, db, 4); err != nil {
		t.Fatalf("apply through v4: %v", err)
	}
	assertLegacyAttributionImmutableTrigger(t, db)
	// dave's legacy_unattributed row is already protected at v4.
	if _, err := db.ExecContext(ctx, `update registry_invites set accepted_by_user_id = 2 where id = 3`); err == nil {
		t.Fatal("expected the v4-installed immutability trigger to reject the update")
	}

	// Migration 5: drop-if-exists + recreate, ending at version 5.
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("apply migrations from clean v4: %v", err)
	}
	version, err := CurrentSchemaVersion(ctx, db)
	if err != nil || version != 8 {
		t.Fatalf("expected schema version 8 from clean v4, got %d (err %v)", version, err)
	}
	var migCount int
	if err := db.QueryRowContext(ctx, `select count(*) from schema_migrations`).Scan(&migCount); err != nil {
		t.Fatal(err)
	}
	if migCount != 8 {
		t.Fatalf("expected 8 migration rows, got %d", migCount)
	}
	assertLegacyAttributionImmutableTrigger(t, db)
	// Still protected after the reinstall, row unchanged.
	var legacyFlag int
	if err := db.QueryRowContext(ctx, `select legacy_unattributed from registry_invites where id = 3`).Scan(&legacyFlag); err != nil {
		t.Fatal(err)
	}
	if legacyFlag != 1 {
		t.Fatalf("dave's row must stay legacy_unattributed, got %d", legacyFlag)
	}
	if _, err := db.ExecContext(ctx, `update registry_invites set legacy_unattributed = 0 where id = 3`); err == nil {
		t.Fatal("expected the reinstalled immutability trigger to reject the update")
	}

	// Re-apply is a no-op at v5.
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("re-apply at v5: %v", err)
	}
}

// seedV4RecordedBase builds a database that RECORDS schema version 4 but whose
// registry_invites state is malformed (the scenarios migration 5 must fail
// closed on rather than silently skip): version 4 recorded, constrained
// parents, and no invites table at all (or an invites table without the
// legacy_unattributed column — added by the caller via the addInvites hook).
func seedV4RecordedBase(t *testing.T, db *sql.DB, addInvites func(ctx context.Context, db *sql.DB) error) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)
	for _, stmt := range []string{
		`create table schema_migrations (version integer primary key, applied_at text not null)`,
		`create table users (
			id integer primary key autoincrement,
			email text not null unique,
			password_hash text not null,
			created_at text not null
		)`,
		`create table registries (
			id integer primary key autoincrement,
			slug text not null unique,
			host text not null unique,
			ens_name text not null,
			owner_user_id integer not null references users(id),
			feed_owner_address text not null,
			encrypted_feed_private_key text not null,
			default_stamp_batch_id text not null,
			anonymous_pull integer not null,
			created_at text not null
		)`,
		`create table registry_memberships (
			id integer primary key autoincrement,
			registry_id integer not null references registries(id) on delete cascade,
			user_id integer not null references users(id) on delete cascade,
			role text not null,
			can_pull integer not null,
			can_push integer not null,
			created_at text not null,
			unique(registry_id, user_id)
		)`,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("build v4-recorded base schema: %v", err)
		}
	}
	if _, err := db.ExecContext(ctx, `insert into users (email, password_hash, created_at) values (?, ?, ?)`, "alice@example.com", "hash", now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `insert into registries
		(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at)
		values ('alice', 'alice.example.test', 'alice.eth', 1, '0xfeed', '', 'batch-1', 1, ?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `insert into registry_memberships (registry_id, user_id, role, can_pull, can_push, created_at) values (1, 1, 'owner', 1, 1, ?)`, now); err != nil {
		t.Fatal(err)
	}
	if err := addInvites(ctx, db); err != nil {
		t.Fatalf("build malformed invites state: %v", err)
	}
	if _, err := db.ExecContext(ctx, `insert into schema_migrations (version, applied_at) values (4, ?)`, now); err != nil {
		t.Fatal(err)
	}
}

// TestInviteMigrationV5RejectsMalformedSchemaPrerequisite pins migration 5's
// fail-closed prerequisite: a database that RECORDS version 4 but whose
// registry_invites is not a digest schema with the legacy_unattributed column
// is malformed — the migration must fail, roll back (version stays 4, no v5
// row), and touch no data, instead of silently installing nothing.
func TestInviteMigrationV5RejectsMalformedSchemaPrerequisite(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	assertFailed := func(t *testing.T, db *sql.DB) {
		t.Helper()
		if err := ApplyMigrations(ctx, db); err == nil {
			t.Fatal("expected migration 5 to fail on the malformed prerequisite, got nil")
		}
		version, err := CurrentSchemaVersion(ctx, db)
		if err != nil || version != 4 {
			t.Fatalf("version must stay 4 after rejected migration 5, got %d (err %v)", version, err)
		}
		var migCount int
		if err := db.QueryRowContext(ctx, `select count(*) from schema_migrations`).Scan(&migCount); err != nil {
			t.Fatal(err)
		}
		if migCount != 1 {
			t.Fatalf("expected only the fixture's version-4 row, got %d rows", migCount)
		}
		var n int
		if err := db.QueryRowContext(ctx, `select count(*) from sqlite_master where type = 'trigger' and name = 'registry_invites_legacy_attribution_immutable'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("no immutability trigger may remain after the rejected migration, found %d", n)
		}
		// Data-free: parents survive untouched.
		var users, regs int
		if err := db.QueryRowContext(ctx, `select (select count(*) from users), (select count(*) from registries)`).Scan(&users, &regs); err != nil {
			t.Fatal(err)
		}
		if users != 1 || regs != 1 {
			t.Fatalf("parents must be untouched after the rejected migration, users=%d registries=%d", users, regs)
		}
	}

	t.Run("registry_invites table absent", func(t *testing.T) {
		t.Parallel()
		db := openInviteMigDB(t, "v5_malformed_absent")
		seedV4RecordedBase(t, db, func(ctx context.Context, db *sql.DB) error { return nil })
		assertFailed(t, db)
	})

	t.Run("legacy_unattributed column absent", func(t *testing.T) {
		t.Parallel()
		db := openInviteMigDB(t, "v5_malformed_nocol")
		seedV4RecordedBase(t, db, func(ctx context.Context, db *sql.DB) error {
			// A digest-ish invites table that carries NO legacy_unattributed
			// column (a partial/broken v4 install): the triggers that
			// reference the flag cannot exist on it either.
			_, err := db.ExecContext(ctx, `create table registry_invites (
				id integer primary key autoincrement,
				registry_id integer not null references registries(id) on delete cascade,
				email text not null,
				role text not null,
				can_pull integer not null,
				can_push integer not null,
				token_digest blob not null unique check (typeof(token_digest) = 'blob' and length(token_digest) = 32),
				status text not null check (status in ('pending','accepted','revoked')),
				accepted_by_user_id integer references users(id),
				expires_at text not null,
				accepted_at text,
				revoked_at text,
				created_at text not null,
				check (can_pull = 1 or can_push = 1),
				check ((status = 'revoked') = (revoked_at is not null)),
				check (accepted_at is null or status = 'accepted')
			)`)
			return err
		})
		assertFailed(t, db)
	})
}

// TestInviteMigrationV5RollsBackWhenTriggerInstallFails pins migration 5's
// failure path when the prerequisite PASSES but the CREATE itself is forced to
// fail: registry_invites is a VIEW carrying the legacy_unattributed column
// (pragma_table_info resolves view columns, so the prerequisite reads it as
// present), and SQLite rejects CREATE TRIGGER on a view. The migration must
// roll back atomically — version stays 4, no v5 row, no trigger, view intact.
func TestInviteMigrationV5RollsBackWhenTriggerInstallFails(t *testing.T) {
	t.Parallel()

	db := openInviteMigDB(t, "v5_install_fail")
	ctx := context.Background()
	seedV4RecordedBase(t, db, func(ctx context.Context, db *sql.DB) error {
		// A base table + a view that presents itself as the invites table with
		// the legacy_unattributed column the prerequisite checks for.
		if _, err := db.ExecContext(ctx, `create table invites_base (id integer primary key, legacy_unattributed integer)`); err != nil {
			return err
		}
		_, err := db.ExecContext(ctx, `create view registry_invites as select id, legacy_unattributed from invites_base`)
		return err
	})
	// Sanity: the prerequisite condition REALLY reads the view as carrying the
	// column — otherwise this subtest would exercise the prerequisite branch
	// instead of the install-failure branch.
	var present int
	if err := db.QueryRowContext(ctx, `select count(*) from pragma_table_info('registry_invites') where name = 'legacy_unattributed'`).Scan(&present); err != nil {
		t.Fatal(err)
	}
	if present != 1 {
		t.Fatalf("fixture defect: view must expose legacy_unattributed for the prerequisite, got %d", present)
	}

	if err := ApplyMigrations(ctx, db); err == nil {
		t.Fatal("expected migration 5 to fail when CREATE TRIGGER is rejected, got nil")
	}
	version, err := CurrentSchemaVersion(ctx, db)
	if err != nil || version != 4 {
		t.Fatalf("version must stay 4 after the failed trigger install, got %d (err %v)", version, err)
	}
	var migCount int
	if err := db.QueryRowContext(ctx, `select count(*) from schema_migrations`).Scan(&migCount); err != nil {
		t.Fatal(err)
	}
	if migCount != 1 {
		t.Fatalf("expected only the fixture's version-4 row, got %d rows", migCount)
	}
	var n int
	if err := db.QueryRowContext(ctx, `select count(*) from sqlite_master where type = 'trigger' and name = 'registry_invites_legacy_attribution_immutable'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("no immutability trigger may survive the rolled-back install, found %d", n)
	}
	// The drop (no-op here) and view DDL were rolled back with the transaction:
	// the view must still exist and hold its rows.
	var views int
	if err := db.QueryRowContext(ctx, `select count(*) from sqlite_master where type = 'view' and name = 'registry_invites'`).Scan(&views); err != nil {
		t.Fatal(err)
	}
	if views != 1 {
		t.Fatal("view must be untouched after the rolled-back migration")
	}
}

// The following test-local constants are a HAND-WRITTEN, independent copy of the
// version-4 registry_invites digest schema and its invariant objects. They are
// deliberately authored in the test rather than referencing the production DDL
// constants, so a defect in a production constant cannot masquerade as a
// "genuine" schema in these fixtures: a corrupt constant would make the
// immutable-trigger-repair tests below diverge from the independently-authored
// correct baseline and fail.

// testV4InvitesTable is the correct version-4 invite-digest table baseline the
// adversarial fixtures mutate (columns, types, nullability, PK, UNIQUE, and all
// CHECKs) to build malformed lookalikes.
const testV4InvitesTable = `CREATE TABLE registry_invites (
	id integer primary key autoincrement,
	registry_id integer not null references registries(id) on delete cascade,
	email text not null,
	role text not null,
	can_pull integer not null,
	can_push integer not null,
	token_digest blob not null unique check (typeof(token_digest) = 'blob' and length(token_digest) = 32),
	status text not null check (status in ('pending','accepted','revoked')),
	accepted_by_user_id integer references users(id),
	legacy_unattributed integer not null default 0 check (legacy_unattributed in (0,1)),
	expires_at text not null,
	accepted_at text,
	revoked_at text,
	created_at text not null,
	check (can_pull = 1 or can_push = 1),
	check ((status = 'revoked') = (revoked_at is not null)),
	check (status <> 'accepted' or accepted_by_user_id is not null or legacy_unattributed = 1),
	check (accepted_at is null or status = 'accepted')
)`

// testV4InvitesLifecycle lists the correct version-4 invariant objects (four
// lifecycle triggers + the supporting status index) as independent statements
// an adversarial fixture appends after its (possibly defective) table.
var testV4InvitesLifecycle = []string{
	`CREATE TRIGGER registry_invites_born_pending before insert on registry_invites
		for each row when NEW.status != 'pending' or NEW.legacy_unattributed != 0
		begin select raise(abort, 'invites must be created pending and attributed'); end`,
	`CREATE TRIGGER registry_invites_terminal_status before update of status on registry_invites
		for each row when OLD.status != 'pending' and NEW.status != OLD.status
		begin select raise(abort, 'invite status is terminal and cannot be changed'); end`,
	`CREATE TRIGGER registry_invites_no_unattributed_acceptance before update of status on registry_invites
		for each row when NEW.status = 'accepted' and NEW.accepted_by_user_id is null
		begin select raise(abort, 'acceptance requires an attributed accepter'); end`,
	`CREATE TRIGGER registry_invites_legacy_flag_locked before update of legacy_unattributed on registry_invites
		for each row when NEW.legacy_unattributed != OLD.legacy_unattributed and NEW.legacy_unattributed = 1
		begin select raise(abort, 'legacy_unattributed is migration-only state and cannot be set'); end`,
	`CREATE INDEX idx_registry_invites_registry_status on registry_invites(registry_id, status)`,
}

// assertMalformedV5DigestRejected proves migration 5's hardened prerequisite
// rejected a malformed registry_invites atomically and data-free: the single
// errInviteDigestSchemaMalformed sentinel is returned, version stays 4, only
// the fixture's version-4 row remains (no v5 row), no immutability trigger was
// ever created, and the parents survive untouched.
func assertMalformedV5DigestRejected(t *testing.T, db *sql.DB, wantRows int) {
	t.Helper()
	ctx := context.Background()
	if err := ApplyMigrations(ctx, db); err == nil {
		t.Fatal("expected migration 5 to reject the malformed digest schema, got nil")
	} else if !errors.Is(err, errInviteDigestSchemaMalformed) {
		t.Fatalf("expected the single data-free errInviteDigestSchemaMalformed sentinel, got: %v", err)
	}
	if ver, err := CurrentSchemaVersion(ctx, db); err != nil || ver != 4 {
		t.Fatalf("version must stay 4 after the rejected migration 5, got %d (err %v)", ver, err)
	}
	var migCount int
	if err := db.QueryRowContext(ctx, `select count(*) from schema_migrations`).Scan(&migCount); err != nil {
		t.Fatal(err)
	}
	if migCount != 1 {
		t.Fatalf("expected only the fixture's version-4 row, got %d rows", migCount)
	}
	var imm int
	if err := db.QueryRowContext(ctx, `select count(*) from sqlite_master where type = 'trigger' and name = 'registry_invites_legacy_attribution_immutable'`).Scan(&imm); err != nil {
		t.Fatal(err)
	}
	if imm != 0 {
		t.Fatalf("no immutability trigger may remain after the rejected migration, found %d", imm)
	}
	var users, regs int
	if err := db.QueryRowContext(ctx, `select (select count(*) from users), (select count(*) from registries)`).Scan(&users, &regs); err != nil {
		t.Fatal(err)
	}
	if users != 1 || regs != 1 {
		t.Fatalf("parents must be untouched after the rejected migration, users=%d registries=%d", users, regs)
	}
	if wantRows >= 0 {
		var rows int
		if err := db.QueryRowContext(ctx, `select count(*) from registry_invites`).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		if rows != wantRows {
			t.Fatalf("registry_invites rows must be untouched, want %d got %d", wantRows, rows)
		}
	}
}

// TestInviteMigrationV5RejectsMalformedDigestSchema is the round-4 adversarial
// regression for migration 5's hardened prerequisite. The previous weak check
// accepted ANY registry_invites exposing the legacy_unattributed column, so a
// malformed or hand-rolled "v4" that carried that column — but lacked the real
// digest columns/CHECKs, exact foreign keys, the token_digest uniqueness, the
// supporting index, or the lifecycle triggers — got stamped version 5 and
// received the immutable trigger on top of a broken schema. This test builds
// each such lookalike (all exposing legacy_unattributed) and proves migration 5
// fails closed with the single data-free sentinel, leaving version 4 recorded,
// no immutability trigger, and every row untouched. The GENUINE exact pre-fix
// and corrected v4 schemas still migrate to v5 (covered by
// TestInviteLegacyAttributionPrefixV4RepairedByMigrationV5 and
// TestInviteMigrationV5FromCleanV4Schema).
func TestInviteMigrationV5RejectsMalformedDigestSchema(t *testing.T) {
	t.Parallel()

	type fixture struct {
		name      string
		tableSQL  string
		lifecycle []string
		// seed inserts one row valid under THIS variant's (possibly defective)
		// schema, BEFORE the lifecycle triggers are installed (mirroring how a
		// real version-4 legacy backfill predates them), so the test can prove
		// the rejected migration is data-free. nil = seed nothing.
		seed func(ctx context.Context, db *sql.DB) error
		// wantRows is the expected registry_invites row count after rejection
		// (-1 = skip, e.g. when registry_invites is a view).
		wantRows int
	}

	var table = testV4InvitesTable
	var lifecycle = testV4InvitesLifecycle
	now := time.Now().UTC().Format(time.RFC3339)
	seedPending := func(ctx context.Context, db *sql.DB) error {
		_, err := db.ExecContext(ctx, `insert into registry_invites
			(registry_id, email, role, can_pull, can_push, token_digest, status, accepted_by_user_id, legacy_unattributed, expires_at, accepted_at, revoked_at, created_at)
			values (1, 'carol@example.com', 'member', 1, 0, ?, 'pending', NULL, 0, ?, NULL, NULL, ?)`,
			DigestInviteToken(tokenTextC), now, now)
		return err
	}

	fixtures := []fixture{
		{
			name:      "object is a view exposing legacy_unattributed",
			tableSQL:  "create view registry_invites as select 1 as id, zeroblob(32) as token_digest, 1 as legacy_unattributed",
			lifecycle: []string{},
			wantRows:  -1,
			seed: func(ctx context.Context, db *sql.DB) error {
				// registry_invites is a view over nothing; seed the parents only.
				return nil
			},
		},
		{
			name: "missing token_digest (legacy token_hash instead)",
			tableSQL: `CREATE TABLE registry_invites (
				id integer primary key autoincrement,
				registry_id integer not null references registries(id) on delete cascade,
				email text not null,
				role text not null,
				can_pull integer not null,
				can_push integer not null,
				token_hash text not null unique,
				status text not null check (status in ('pending','accepted','revoked')),
				accepted_by_user_id integer references users(id),
				legacy_unattributed integer not null default 0 check (legacy_unattributed in (0,1)),
				expires_at text not null,
				accepted_at text,
				revoked_at text,
				created_at text not null,
				check (can_pull = 1 or can_push = 1),
				check (accepted_at is null or status = 'accepted')
			)`,
			wantRows: 1,
			seed: func(ctx context.Context, db *sql.DB) error {
				_, err := db.ExecContext(ctx, `insert into registry_invites
					(registry_id, email, role, can_pull, can_push, token_hash, status, accepted_by_user_id, legacy_unattributed, expires_at, accepted_at, revoked_at, created_at)
					values (1, 'carol@example.com', 'member', 1, 0, 'deadbeef', 'pending', NULL, 0, ?, NULL, NULL, ?)`, now, now)
				return err
			},
		},
		{
			name: "token_digest wrong type (text not blob)",
			tableSQL: strings.Replace(table,
				`token_digest blob not null unique check (typeof(token_digest) = 'blob' and length(token_digest) = 32)`,
				`token_digest text not null unique check (typeof(token_digest) = 'text' and length(token_digest) = 32)`, 1),
			wantRows: 1,
			seed: func(ctx context.Context, db *sql.DB) error {
				_, err := db.ExecContext(ctx, `insert into registry_invites
					(registry_id, email, role, can_pull, can_push, token_digest, status, accepted_by_user_id, legacy_unattributed, expires_at, accepted_at, revoked_at, created_at)
					values (1, 'carol@example.com', 'member', 1, 0, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'pending', NULL, 0, ?, NULL, NULL, ?)`, now, now)
				return err
			},
		},
		{
			name: "token_digest wrongly nullable",
			tableSQL: strings.Replace(table,
				`token_digest blob not null unique check (typeof(token_digest) = 'blob' and length(token_digest) = 32)`,
				`token_digest blob unique check (typeof(token_digest) = 'blob' and length(token_digest) = 32)`, 1),
			seed:     seedPending,
			wantRows: 1,
		},
		{
			name: "missing strict token_digest length CHECK",
			tableSQL: strings.Replace(table,
				`token_digest blob not null unique check (typeof(token_digest) = 'blob' and length(token_digest) = 32)`,
				`token_digest blob not null unique`, 1),
			seed:     seedPending,
			wantRows: 1,
		},
		{
			name: "missing status-domain CHECK",
			tableSQL: strings.Replace(table,
				`status text not null check (status in ('pending','accepted','revoked'))`,
				`status text not null`, 1),
			seed:     seedPending,
			wantRows: 1,
		},
		{
			name: "missing registry_id foreign key",
			tableSQL: strings.Replace(table,
				`registry_id integer not null references registries(id) on delete cascade`,
				`registry_id integer not null`, 1),
			seed:     seedPending,
			wantRows: 1,
		},
		{
			name: "wrong accepted_by_user_id FK (on delete set null, not the exact v4 contract)",
			tableSQL: strings.Replace(table,
				`accepted_by_user_id integer references users(id)`,
				`accepted_by_user_id integer references users(id) on delete set null`, 1),
			seed:     seedPending,
			wantRows: 1,
		},
		{
			name: "missing accepted_by_user_id foreign key",
			tableSQL: strings.Replace(table,
				`accepted_by_user_id integer references users(id),`,
				`accepted_by_user_id integer,`, 1),
			seed:     seedPending,
			wantRows: 1,
		},
		{
			name: "missing token_digest uniqueness",
			tableSQL: strings.Replace(table,
				`token_digest blob not null unique check (typeof(token_digest) = 'blob' and length(token_digest) = 32)`,
				`token_digest blob not null check (typeof(token_digest) = 'blob' and length(token_digest) = 32)`, 1),
			seed:     seedPending,
			wantRows: 1,
		},
		{
			name:     "missing (registry_id,status) supporting index",
			tableSQL: table,
			lifecycle: []string{
				`CREATE TRIGGER registry_invites_born_pending before insert on registry_invites
					for each row when NEW.status != 'pending' or NEW.legacy_unattributed != 0
					begin select raise(abort, 'invites must be created pending and attributed'); end`,
				`CREATE TRIGGER registry_invites_terminal_status before update of status on registry_invites
					for each row when OLD.status != 'pending' and NEW.status != OLD.status
					begin select raise(abort, 'invite status is terminal and cannot be changed'); end`,
				`CREATE TRIGGER registry_invites_no_unattributed_acceptance before update of status on registry_invites
					for each row when NEW.status = 'accepted' and NEW.accepted_by_user_id is null
					begin select raise(abort, 'acceptance requires an attributed accepter'); end`,
				`CREATE TRIGGER registry_invites_legacy_flag_locked before update of legacy_unattributed on registry_invites
					for each row when NEW.legacy_unattributed != OLD.legacy_unattributed and NEW.legacy_unattributed = 1
					begin select raise(abort, 'legacy_unattributed is migration-only state and cannot be set'); end`,
			},
			seed:     seedPending,
			wantRows: 1,
		},
		{
			name:     "wrong (registry_id,status) index columns",
			tableSQL: table,
			lifecycle: []string{
				`CREATE TRIGGER registry_invites_born_pending before insert on registry_invites
					for each row when NEW.status != 'pending' or NEW.legacy_unattributed != 0
					begin select raise(abort, 'invites must be created pending and attributed'); end`,
				`CREATE TRIGGER registry_invites_terminal_status before update of status on registry_invites
					for each row when OLD.status != 'pending' and NEW.status != OLD.status
					begin select raise(abort, 'invite status is terminal and cannot be changed'); end`,
				`CREATE TRIGGER registry_invites_no_unattributed_acceptance before update of status on registry_invites
					for each row when NEW.status = 'accepted' and NEW.accepted_by_user_id is null
					begin select raise(abort, 'acceptance requires an attributed accepter'); end`,
				`CREATE TRIGGER registry_invites_legacy_flag_locked before update of legacy_unattributed on registry_invites
					for each row when NEW.legacy_unattributed != OLD.legacy_unattributed and NEW.legacy_unattributed = 1
					begin select raise(abort, 'legacy_unattributed is migration-only state and cannot be set'); end`,
				`CREATE INDEX idx_registry_invites_registry_status on registry_invites(registry_id, email)`,
			},
			seed:     seedPending,
			wantRows: 1,
		},
		{
			name:     "missing lifecycle trigger (born_pending absent)",
			tableSQL: table,
			lifecycle: []string{
				`CREATE TRIGGER registry_invites_terminal_status before update of status on registry_invites
					for each row when OLD.status != 'pending' and NEW.status != OLD.status
					begin select raise(abort, 'invite status is terminal and cannot be changed'); end`,
				`CREATE TRIGGER registry_invites_no_unattributed_acceptance before update of status on registry_invites
					for each row when NEW.status = 'accepted' and NEW.accepted_by_user_id is null
					begin select raise(abort, 'acceptance requires an attributed accepter'); end`,
				`CREATE TRIGGER registry_invites_legacy_flag_locked before update of legacy_unattributed on registry_invites
					for each row when NEW.legacy_unattributed != OLD.legacy_unattributed and NEW.legacy_unattributed = 1
					begin select raise(abort, 'legacy_unattributed is migration-only state and cannot be set'); end`,
				`CREATE INDEX idx_registry_invites_registry_status on registry_invites(registry_id, status)`,
			},
			seed:     seedPending,
			wantRows: 1,
		},
		{
			name:     "weakened born_pending trigger (legacy_unattributed guard dropped)",
			tableSQL: table,
			lifecycle: []string{
				`CREATE TRIGGER registry_invites_born_pending before insert on registry_invites
					for each row when NEW.status != 'pending'
					begin select raise(abort, 'invites must be created pending'); end`,
				`CREATE TRIGGER registry_invites_terminal_status before update of status on registry_invites
					for each row when OLD.status != 'pending' and NEW.status != OLD.status
					begin select raise(abort, 'invite status is terminal and cannot be changed'); end`,
				`CREATE TRIGGER registry_invites_no_unattributed_acceptance before update of status on registry_invites
					for each row when NEW.status = 'accepted' and NEW.accepted_by_user_id is null
					begin select raise(abort, 'acceptance requires an attributed accepter'); end`,
				`CREATE TRIGGER registry_invites_legacy_flag_locked before update of legacy_unattributed on registry_invites
					for each row when NEW.legacy_unattributed != OLD.legacy_unattributed and NEW.legacy_unattributed = 1
					begin select raise(abort, 'legacy_unattributed is migration-only state and cannot be set'); end`,
				`CREATE INDEX idx_registry_invites_registry_status on registry_invites(registry_id, status)`,
			},
			seed:     seedPending,
			wantRows: 1,
		},
		{
			name: "plausible hand-rolled lookalike that passed the old weak check",
			// A cleanly-formatted, confident-looking "v4" with every column the
			// application reads (including legacy_unattributed and a BLOB
			// token_digest) but NONE of the CHECK constraints, no unique index on
			// token_digest, no accepted_by FK, no lifecycle triggers, and no
			// supporting index. It exposed legacy_unattributed so the OLD
			// column-only prerequisite accepted it and would have installed the
			// immutable trigger on a broken schema.
			tableSQL: `CREATE TABLE registry_invites (
				id integer primary key autoincrement,
				registry_id integer not null references registries(id) on delete cascade,
				email text not null,
				role text not null,
				can_pull integer not null,
				can_push integer not null,
				token_digest blob not null,
				status text not null,
				accepted_by_user_id integer,
				legacy_unattributed integer not null default 0,
				expires_at text not null,
				accepted_at text,
				revoked_at text,
				created_at text not null
			)`,
			lifecycle: nil,
			seed:      seedPending,
			wantRows:  1,
		},
	}

	for _, f := range fixtures {
		f := f
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()
			db := openInviteMigDB(t, "v5_digest_lookalike")
			lc := f.lifecycle
			if lc == nil {
				lc = lifecycle
			}
			seedV4RecordedBase(t, db, func(ctx context.Context, db *sql.DB) error {
				if _, err := db.ExecContext(ctx, f.tableSQL); err != nil {
					return err
				}
				if f.seed != nil {
					if err := f.seed(ctx, db); err != nil {
						return err
					}
				}
				for _, s := range lc {
					if _, err := db.ExecContext(ctx, s); err != nil {
						return err
					}
				}
				return nil
			})
			assertMalformedV5DigestRejected(t, db, f.wantRows)
		})
	}
}

// ---------------------------------------------------------------------------
// Fix round 5, finding A: quote-aware, fail-closed SQL fingerprinting.
// normalizeSQL replaces the old strings.Fields-based foldSQL that collapsed
// whitespace INSIDE quoted literals (equating 'invites must be  created' with
// 'invites must be created'). The new scanner preserves every byte inside
// literals and quoted identifiers, collapses only insignificant outside
// whitespace, and rejects comments / unterminated quotes / NUL+control
// anomalies. These tests pin that behavior directly on the normalizer.
// ---------------------------------------------------------------------------

func TestNormalizeSQL(t *testing.T) {
	t.Parallel()

	eq := func(name, a, b string) {
		t.Helper()
		an, err := normalizeSQL(a)
		if err != nil {
			t.Fatalf("%s: normalize(%q): %v", name, a, err)
		}
		bn, err := normalizeSQL(b)
		if err != nil {
			t.Fatalf("%s: normalize(%q): %v", name, b, err)
		}
		if an != bn {
			t.Fatalf("%s: expected EQUAL normalized forms\n  a=%q → %q\n  b=%q → %q", name, a, an, b, bn)
		}
	}
	diff := func(name, a, b string) {
		t.Helper()
		an, err := normalizeSQL(a)
		if err != nil {
			t.Fatalf("%s: normalize(%q): %v", name, a, err)
		}
		bn, err := normalizeSQL(b)
		if err != nil {
			t.Fatalf("%s: normalize(%q): %v", name, b, err)
		}
		if an == bn {
			t.Fatalf("%s: expected DIFFERENT normalized forms, both=%q (a=%q b=%q)", name, an, a, b)
		}
	}
	reject := func(name, s string) {
		t.Helper()
		if _, err := normalizeSQL(s); err == nil {
			t.Fatalf("%s: expected normalizeSQL to reject %q, got nil", name, s)
		} else if !errors.Is(err, errSQLFingerprintLexical) {
			t.Fatalf("%s: expected errSQLFingerprintLexical for %q, got %v", name, s, err)
		}
	}
	pin := func(name, in, want string) {
		t.Helper()
		got, err := normalizeSQL(in)
		if err != nil {
			t.Fatalf("%s: normalize(%q): %v", name, in, err)
		}
		if got != want {
			t.Fatalf("%s: expected %q, got %q (in=%q)", name, want, got, in)
		}
	}

	// --- outside-whitespace equivalence: layout-only differences are equal.
	eq("double vs single outside space", "declare A  B", "declare A B")
	eq("tab/newline/CR collapse", "declare	A\nB\r\nC  D", "declare A B C D")
	eq("leading/trailing trimmed", "\n \n  declare A  \n 	", "declare A")
	eq("collapse across keywords", "check   status   in   (x)", "check status in (x)")
	eq("rename-quoted vs unquoted table name", `CREATE TABLE "reg" (a integer)`, "CREATE TABLE reg (a integer)")

	// --- whitespace INSIDE single-quoted literals is significant.
	diff("literal one vs two spaces", "select raise(abort, 'a b')", "select raise(abort, 'a  b')")
	diff("trigger RAISE one vs two spaces", "select raise(abort, 'invites must be created pending and attributed')", "select raise(abort, 'invites must be  created pending and attributed')")
	eq("literal identical content, identical punctuation, differing outer runs", "select x = 'it''s fine' and  y = 'ok'", "select x = 'it''s fine' and y = 'ok'")

	// --- whitespace INSIDE quoted identifiers is significant.
	diff("dquote inner whitespace", `"foo bar"`, `"foobar"`)
	diff("backtick inner whitespace", "`foo bar`", "`foobar`")
	diff("bracket inner whitespace", "[foo bar]", "[foobar]")
	eq("dquote inner whitespace preserved identically", `"foo bar"`, `"foo bar"`)

	// --- quoted identifier delimiters are insignificant; interior preserved.
	eq("dquote vs bare identifier", `SELECT "status" FROM t`, "SELECT status FROM t")
	pin("dquote identifier strips delimiters", `"registry_invites"`, "registry_invites")
	pin("backtick identifier strips delimiters", "`registry_invites`", "registry_invites")
	pin("bracket identifier strips delimiters", "[registry_invites]", "registry_invites")
	// Escaped-quote forms are deterministic.
	pin("literal doubled-quote escape preserved", "select 'it''s fine'", "select 'it''s fine'")
	eq("literal doubled-quote escape matches itself", "select x = 'it''s fine'", "select   x   =   'it''s fine'")
	diff("literal doubled-quote escape spacing differs", "select x = 'it''s fine'", "select x = 'it''s  fine'")
	pin("dquote identifier doubled-quote escape", `"a""b"`, `a"b`)
	pin("backtick identifier doubled-backtick escape", "`a``b`", "a`b")

	// --- comments are rejected (project DDL carries none; a commented/spoofed
	// lookalike must never normalize equal to it).
	reject("line comment", "select 1 -- note")
	reject("block comment", "select 1 /* note */")
	reject("line comment inside clause", "check (a = 1) -- spoof")
	reject("block comment between keywords", "select /* spoof */ 1")
	reject("unterminated block comment", "select 1 /* unfinished")

	// --- unterminated quotes are rejected.
	reject("unterminated single", "select 'abc")
	reject("unterminated dquote", `select "abc`)
	reject("unterminated backtick", "select `abc")
	reject("unterminated bracket", "select [abc")
	reject("bare single quote", "select '")

	// --- NUL / non-whitespace control anomalies are rejected.
	reject("NUL byte", "select 1\x00")
	reject("BEL byte", "select 1\x07")
	reject("NUL inside literal", "select 'a\x00b'")
	reject("NUL inside dquote", "select \"a\x00b\"")

	// --- keyword / identifier case remains strict (no lowercasing).
	diff("keyword case differs", "select 1", "SELECT 1")
	diff("CREATE TABLE keyword case differs", "create table t (a integer)", "CREATE TABLE t (a integer)")
	diff("identifier case differs", "select can_pull from t", "select Can_Pull from t")

	// --- punctuation behavior pinned.
	pin("collapsed run, structural spacing kept", "select   a, b  from t where ( x = 1 ) and y <> 2",
		"select a, b from t where ( x = 1 ) and y <> 2")
	pin("operators remain glued", "check(a=1 or b=2)", "check(a=1 or b=2)")
}

// ---------------------------------------------------------------------------
// Fix round 5, finding A: migration-level spoof fixtures. Each is the GENUINE
// v4 schema perturbed by exactly one lexical/semantic-indifference change that
// the OLD strings.Fields foldSQL would have folded away (doubled-space literal),
// or that the normalizer deliberately refuses (comment / identifier-case
// change). Each must FAIL migration 5 with the single data-free sentinel,
// version 4 stays recorded, no immutability trigger, data untouched.
// ---------------------------------------------------------------------------

func TestInviteMigrationV5RejectsSpoofedFingerprints(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Format(time.RFC3339)
	litDoubled := strings.Replace(testV4InvitesLifecycle[0],
		"'invites must be created pending and attributed'",
		"'invites must be  created pending and attributed'", 1)
	commented := strings.Replace(testV4InvitesLifecycle[0],
		"for each row when NEW.status != 'pending' or NEW.legacy_unattributed != 0",
		"for each row when NEW.status != 'pending' or NEW.legacy_unattributed != 0 -- spoof",
		1)
	caseChanged := strings.Replace(testV4InvitesTable, "can_pull integer not null,", "Can_Pull integer not null,", 1)

	type fixture struct {
		name      string
		tableSQL  string
		lifecycle []string
	}
	fixtures := []fixture{
		{
			name:      "doubled-space literal inside born_pending RAISE",
			tableSQL:  testV4InvitesTable,
			lifecycle: []string{litDoubled, testV4InvitesLifecycle[1], testV4InvitesLifecycle[2], testV4InvitesLifecycle[3], testV4InvitesLifecycle[4]},
		},
		{
			name:      "comment injected into born_pending trigger",
			tableSQL:  testV4InvitesTable,
			lifecycle: []string{commented, testV4InvitesLifecycle[1], testV4InvitesLifecycle[2], testV4InvitesLifecycle[3], testV4InvitesLifecycle[4]},
		},
		{
			name:      "identifier case change in can_pull column",
			tableSQL:  caseChanged,
			lifecycle: testV4InvitesLifecycle,
		},
	}

	for _, f := range fixtures {
		f := f
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()
			db := openInviteMigDB(t, "v5_spoof_fingerprint")
			seedV4RecordedBase(t, db, func(ctx context.Context, db *sql.DB) error {
				if _, err := db.ExecContext(ctx, f.tableSQL); err != nil {
					return err
				}
				// Seed one pending row before the lifecycle triggers exist so the
				// insert succeeds and the rejected migration can prove data-free.
				if _, err := db.ExecContext(ctx, `insert into registry_invites
					(registry_id, email, role, can_pull, can_push, token_digest, status, accepted_by_user_id, legacy_unattributed, expires_at, accepted_at, revoked_at, created_at)
					values (1, 'carol@example.com', 'member', 1, 0, zeroblob(32), 'pending', NULL, 0, ?, NULL, NULL, ?)`, now, now); err != nil {
					return err
				}
				for _, s := range f.lifecycle {
					if _, err := db.ExecContext(ctx, s); err != nil {
						return err
					}
				}
				return nil
			})
			assertMalformedV5DigestRejected(t, db, 1)
		})
	}
}

// ---------------------------------------------------------------------------
// Fix round 5, finding B: independent, hand-written adversarial coverage of
// EVERY migration-4 table CHECK clause and, separately, of EVERY lifecycle
// trigger. Each case is the otherwise-genuine version-4 schema (the 14-column
// digest table with all seven CHECKs, both exact FKs, the unique token_digest
// index, the (registry_id,status) index, and the four lifecycle triggers)
// perturbed by EXACTLY ONE weakened/removed invariant. All hand-composed from
// the test-local testV4InvitesTable / testV4InvitesLifecycle baseline — never
// from the production constants — so a defect in a production constant cannot
// masquerade as a genuine schema. Every case must fail migration 5 closed.
//
// The schema fingerprints prior rounds validated were approximate (counted as
// 13 columns); the genuine digest table has FOURTEEN declared columns: id,
// registry_id, email, role, can_pull, can_push, token_digest, status,
// accepted_by_user_id, legacy_unattributed, expires_at, accepted_at,
// revoked_at, created_at — see testV4InvitesTable.
// ---------------------------------------------------------------------------

func TestInviteMigrationV5RejectsEachCheckAndTriggerMutation(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Format(time.RFC3339)

	// Drop helper: returns the correct lifecycle minus element idx.
	drop := func(idx int) []string {
		out := make([]string, 0, len(testV4InvitesLifecycle)-1)
		for i, s := range testV4InvitesLifecycle {
			if i != idx {
				out = append(out, s)
			}
		}
		return out
	}
	// Weaken helper: returns the correct lifecycle with trigger idx's WHEN
	// clause replaced by the weakened form.
	weaken := func(idx int) []string {
		out := make([]string, len(testV4InvitesLifecycle))
		copy(out, testV4InvitesLifecycle)
		var oldWHEN, newWHEN string
		switch idx {
		case 0: // born_pending
			oldWHEN = "for each row when NEW.status != 'pending' or NEW.legacy_unattributed != 0"
			newWHEN = "for each row when NEW.status != 'pending'"
		case 1: // terminal_status
			oldWHEN = "for each row when OLD.status != 'pending' and NEW.status != OLD.status"
			newWHEN = "for each row when OLD.status != 'pending'"
		case 2: // no_unattributed_acceptance
			oldWHEN = "for each row when NEW.status = 'accepted' and NEW.accepted_by_user_id is null"
			newWHEN = "for each row when NEW.status = 'accepted'"
		case 3: // legacy_flag_locked
			oldWHEN = "for each row when NEW.legacy_unattributed != OLD.legacy_unattributed and NEW.legacy_unattributed = 1"
			newWHEN = "for each row when NEW.legacy_unattributed != OLD.legacy_unattributed"
		}
		out[idx] = strings.Replace(out[idx], oldWHEN, newWHEN, 1)
		return out
	}

	// The seven distinct migration-4 CHECK clauses, each weakened in isolation
	// (the can_pull / can_push domains are exercised by mutating their column
	// declarations, since the DDL combines them into one table-level CHECK that
	// does double duty for both permissions).
	type checkCase struct {
		name       string
		tableSQL   string
		seedDigest string // SQL expression used for token_digest so the seed
		// satisfies the WEAKENED schema (zeroblob(32) except where the length
		// CHECK itself is weakened to 31).
		seedRevokedAt string // SQL expression for revoked_at so the seed
		// satisfies a WEAKENED revoked_at/status CHECK ("" = leave NULL).
	}
	checkCases := []checkCase{
		{
			name:       "token_digest length CHECK weakened (32 -> 31)",
			tableSQL:   strings.Replace(testV4InvitesTable, "and length(token_digest) = 32", "and length(token_digest) = 31", 1),
			seedDigest: "zeroblob(31)",
		},
		{
			name:       "status domain CHECK weakened (revoked dropped from domain)",
			tableSQL:   strings.Replace(testV4InvitesTable, "status in ('pending','accepted','revoked')", "status in ('pending','accepted')", 1),
			seedDigest: "zeroblob(32)",
		},
		{
			name:       "can_pull domain weakened (integer -> text column)",
			tableSQL:   strings.Replace(testV4InvitesTable, "can_pull integer not null,", "can_pull text not null,", 1),
			seedDigest: "zeroblob(32)",
		},
		{
			name:       "can_push domain weakened (integer -> text column)",
			tableSQL:   strings.Replace(testV4InvitesTable, "can_push integer not null,", "can_push text not null,", 1),
			seedDigest: "zeroblob(32)",
		},
		{
			name:       "accepted_by/status CHECK weakened (legacy_unattributed escape removed)",
			tableSQL:   strings.Replace(testV4InvitesTable, "check (status <> 'accepted' or accepted_by_user_id is not null or legacy_unattributed = 1)", "check (status <> 'accepted' or accepted_by_user_id is not null)", 1),
			seedDigest: "zeroblob(32)",
		},
		{
			name:       "accepted_at/status CHECK weakened (acceptance no longer requires status)",
			tableSQL:   strings.Replace(testV4InvitesTable, "check (accepted_at is null or status = 'accepted')", "check (accepted_at is null or status = 'pending')", 1),
			seedDigest: "zeroblob(32)",
		},
		{
			name:       "revoked_at/status CHECK weakened (revoked no longer requires revoked_at)",
			tableSQL:   strings.Replace(testV4InvitesTable, "check ((status = 'revoked') = (revoked_at is not null))", "check ((status = 'revoked') = (revoked_at is null))", 1),
			seedDigest: "zeroblob(32)",
			// The weakened CHECK demands revoked_at be non-null whenever status
			// is not 'revoked' — seed a pending row WITH a revoked_at so the
			// weakened constraint is satisfied and only the fingerprint differs.
			seedRevokedAt: "'" + now + "'",
		},
		{
			name:       "legacy_unattributed domain CHECK weakened (bogus value 2 admitted)",
			tableSQL:   strings.Replace(testV4InvitesTable, "check (legacy_unattributed in (0,1))", "check (legacy_unattributed in (0,1,2))", 1),
			seedDigest: "zeroblob(32)",
		},
	}

	runV4Lookalike := func(t *testing.T, name, tableSQL string, seedDigest string, lifecycle []string, seedRevokedAt ...string) {
		t.Helper()
		revoked := "NULL"
		if len(seedRevokedAt) > 0 && seedRevokedAt[0] != "" {
			revoked = seedRevokedAt[0]
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			db := openInviteMigDB(t, "v5_check_trigger_mutation")
			seedV4RecordedBase(t, db, func(ctx context.Context, db *sql.DB) error {
				if _, err := db.ExecContext(ctx, tableSQL); err != nil {
					return err
				}
				if _, err := db.ExecContext(ctx, `insert into registry_invites
					(registry_id, email, role, can_pull, can_push, token_digest, status, accepted_by_user_id, legacy_unattributed, expires_at, accepted_at, revoked_at, created_at)
					values (1, 'carol@example.com', 'member', 1, 0, `+seedDigest+`, 'pending', NULL, 0, ?, NULL, `+revoked+`, ?)`, now, now); err != nil {
					return err
				}
				for _, s := range lifecycle {
					if _, err := db.ExecContext(ctx, s); err != nil {
						return err
					}
				}
				return nil
			})
			assertMalformedV5DigestRejected(t, db, 1)
		})
	}

	for _, c := range checkCases {
		runV4Lookalike(t, c.name, c.tableSQL, c.seedDigest, testV4InvitesLifecycle, c.seedRevokedAt)
	}

	// Each lifecycle trigger: independently removed AND independently weakened,
	// in every case on an otherwise fully genuine v4 schema.
	type triggerSet struct {
		name string
		lc   []string
	}
	var triggerCases []triggerSet
	for i := 0; i < 4; i++ {
		triggerCases = append(triggerCases, triggerSet{name: "lifecycle trigger dropped idx " + triggerName(i), lc: drop(i)})
		triggerCases = append(triggerCases, triggerSet{name: "lifecycle trigger weakened idx " + triggerName(i), lc: weaken(i)})
	}
	for _, tcase := range triggerCases {
		runV4Lookalike(t, tcase.name, testV4InvitesTable, "zeroblob(32)", tcase.lc)
	}
}

func triggerName(i int) string {
	switch i {
	case 0:
		return "born_pending"
	case 1:
		return "terminal_status"
	case 2:
		return "no_unattributed_acceptance"
	case 3:
		return "legacy_flag_locked"
	}
	return "?"
}

// TestInviteIdempotentRetryAfterExpiry pins the idempotency/expiry ordering:
// the load/status/accepted_by decision precedes the expiry gate, so an invite
// already accepted by the same database user with its atomic membership
// returns success even AFTER expiry; expiry only blocks pending→accepted; and
// revoked invites never succeed (before or after expiry).
func TestInviteIdempotentRetryAfterExpiry(t *testing.T) {
	t.Parallel()

	store, err := OpenSQLite(fmt.Sprintf("file:controlplane_invite_expiry_retry_%d?mode=memory&cache=shared", atomic.AddInt64(&inviteStoreSeq, 1)))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	ctx := context.Background()
	fixed := time.Date(2026, 9, 22, 9, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return fixed }

	alice, err := store.CreateUser(ctx, "alice@example.com", "hash")
	if err != nil {
		t.Fatalf("create alice: %v", err)
	}
	registry, err := store.CreateRegistry(ctx, Registry{
		Slug: "alice", Host: "alice.uncloud-registry.com", ENSName: "alice.eth",
		OwnerUserID: alice.ID, FeedOwnerAddress: "0xfeed", DefaultStampBatchID: "batch-1",
		AnonymousPull: true,
	}, nil, nil)
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	bob, err := store.CreateUser(ctx, "bob@example.com", "hash")
	if err != nil {
		t.Fatalf("create bob: %v", err)
	}
	mallory, err := store.CreateUser(ctx, "mallory@example.com", "hash")
	if err != nil {
		t.Fatalf("create mallory: %v", err)
	}

	// 1. Accepted BEFORE expiry, retried by the SAME user AFTER expiry:
	//    the idempotent retry must still succeed and add no membership.
	_, token, err := store.CreateInvite(ctx, Invite{
		RegistryID: registry.ID, Email: "bob@example.com", Role: "member",
		CanPull: true, CanPush: true, ExpiresAt: fixed.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	if _, err := store.AcceptInvite(ctx, token, bob); err != nil {
		t.Fatalf("accept before expiry: %v", err)
	}
	store.now = func() time.Time { return fixed.Add(25 * time.Hour) } // long past expiry
	accepted, err := store.AcceptInvite(ctx, token, bob)
	if err != nil {
		t.Fatalf("same-user idempotent retry after expiry must succeed: %v", err)
	}
	if accepted.Status != "accepted" {
		t.Fatalf("expected accepted status on post-expiry retry, got %s", accepted.Status)
	}
	if _, err := store.AcceptInvite(ctx, token, mallory); !errors.Is(err, errInviteNotFound) {
		t.Fatalf("different user after expiry must fail generically, got %v", err)
	}
	memberships, err := store.ListMembershipsForRegistry(ctx, registry.ID)
	if err != nil {
		t.Fatalf("list memberships: %v", err)
	}
	if len(memberships) != 1 { // store-created registry has no owner membership row; only bob's
		t.Fatalf("expected exactly 1 membership (bob), got %d", len(memberships))
	}

	// 2. Pending invite AT expiry: pending→accepted is blocked at the boundary.
	store.now = func() time.Time { return fixed }
	_, token2, err := store.CreateInvite(ctx, Invite{
		RegistryID: registry.ID, Email: "bob@example.com", Role: "member",
		CanPull: true, CanPush: true, ExpiresAt: fixed.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatalf("create second invite: %v", err)
	}
	store.now = func() time.Time { return fixed.Add(2 * time.Hour) } // now == expires_at
	if _, err := store.AcceptInvite(ctx, token2, bob); !errors.Is(err, errInviteNotFound) {
		t.Fatalf("pending acceptance exactly at expiry must fail, got %v", err)
	}

	// 3. Revoked never succeeds, before or after expiry.
	store.now = func() time.Time { return fixed }
	invite3, token3, err := store.CreateInvite(ctx, Invite{
		RegistryID: registry.ID, Email: "bob@example.com", Role: "member",
		CanPull: true, CanPush: true, ExpiresAt: fixed.Add(3 * time.Hour),
	})
	if err != nil {
		t.Fatalf("create third invite: %v", err)
	}
	if _, err := store.RevokeInvite(ctx, registry.ID, invite3.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := store.AcceptInvite(ctx, token3, bob); !errors.Is(err, errInviteNotFound) {
		t.Fatalf("revoked invite before expiry must fail, got %v", err)
	}
	store.now = func() time.Time { return fixed.Add(4 * time.Hour) }
	if _, err := store.AcceptInvite(ctx, token3, bob); !errors.Is(err, errInviteNotFound) {
		t.Fatalf("revoked invite after expiry must fail, got %v", err)
	}
}

// TestNormalizeEmailASCIIWhitespaceOnlyAcrossIdentityPaths pins the ASCII-only
// trim semantics: surrounding ASCII whitespace (space, HT, LF, VT, FF, CR) is
// trimmed then lowercased; Unicode whitespace (NBSP, em-space) is PART of the
// identity. Create, login, and invite binding all use the same canonical form.
func TestNormalizeEmailASCIIWhitespaceOnlyAcrossIdentityPaths(t *testing.T) {
	t.Parallel()

	asciiWS := " \t\n\v\f\r"
	if got := NormalizeEmail(asciiWS + "MiXeD@Example.COM" + asciiWS); got != "mixed@example.com" {
		t.Fatalf("expected full ASCII trim + lowercase, got %q", got)
	}
	// Every ASCII whitespace byte trims at either end, individually.
	for _, w := range []string{" ", "\t", "\n", "\v", "\f", "\r"} {
		if got := NormalizeEmail(w + "a@b.c" + w); got != "a@b.c" {
			t.Fatalf("ASCII whitespace %q must be trimmed, got %q", w, got)
		}
	}
	// Interior ASCII whitespace is preserved.
	if got := NormalizeEmail("a b@c.d"); got != "a b@c.d" {
		t.Fatalf("interior whitespace must be preserved, got %q", got)
	}
	// Unicode whitespace is preserved at the edges — never aliased to the
	// ASCII-trimmed form.
	for _, ws := range []string{"\u00a0", "\u2003", "\u2009", "\u3000"} {
		if got := NormalizeEmail(ws + "a@b.c"); got != ws+"a@b.c" {
			t.Fatalf("leading %q must stay part of identity, got %q", ws, got)
		}
		if got := NormalizeEmail("a@b.c" + ws); got != "a@b.c"+ws {
			t.Fatalf("trailing %q must stay part of identity, got %q", ws, got)
		}
	}
	if got := NormalizeEmail("\u00a0a@b.c\u2003"); got != "\u00a0a@b.c\u2003" {
		t.Fatalf("unicode-surrounded email must be preserved, got %q", got)
	}

	store, service := newInviteTestService(t, "controlplane_email_ascii_test")
	_ = store
	ctx := context.Background()

	// Create: ASCII-padded accounts are canonical; NBSP accounts are distinct.
	u1, _, err := service.RegisterUser(ctx, asciiWS+"DAVE@EXAMPLE.COM"+asciiWS, "password123")
	if err != nil {
		t.Fatalf("register ASCII-padded dave: %v", err)
	}
	if u1.Email != "dave@example.com" {
		t.Fatalf("expected canonical account email, got %q", u1.Email)
	}
	u2, _, err := service.RegisterUser(ctx, "\u00a0dave@example.com", "password123")
	if err != nil {
		t.Fatalf("register NBSP dave: %v", err)
	}
	if u2.ID == u1.ID {
		t.Fatal("NBSP-padded email must be a DISTINCT account, not an alias")
	}
	if u2.Email != "\u00a0dave@example.com" {
		t.Fatalf("NBSP account email must be preserved, got %q", u2.Email)
	}
	// Login: ASCII-padded lookup resolves the canonical account; the NBSP
	// account resolves only under its exact (Unicode-preserving) identity.
	login1, _, err := service.Login(ctx, "dave@example.com", "password123")
	if err != nil || login1.ID != u1.ID {
		t.Fatalf("plain login must resolve the ASCII account, got %+v err %v", login1, err)
	}
	login1b, _, err := service.Login(ctx, asciiWS+"dave@example.com"+asciiWS, "password123")
	if err != nil || login1b.ID != u1.ID {
		t.Fatalf("ASCII-padded login must resolve the same account, got %+v err %v", login1b, err)
	}
	login2, _, err := service.Login(ctx, "\u00a0dave@example.com", "password123")
	if err != nil || login2.ID != u2.ID {
		t.Fatalf("NBSP-padded login must resolve the NBSP account only, got %+v err %v", login2, err)
	}

	// Invite binding: ASCII recipient binds to the ASCII account; NBSP
	// recipient binds to the NBSP account; neither aliases the other.
	alice, _, err := service.RegisterUser(ctx, "alice@example.com", "password123")
	if err != nil {
		t.Fatalf("register alice: %v", err)
	}
	created, err := service.CreateRegistry(ctx, alice.ID, "alice", "alice.eth", true, "batch-1")
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	_, asciiTok, err := service.CreateInvite(ctx, created.Registry.ID, alice.ID, asciiWS+"bob@example.com"+asciiWS, true, true)
	if err != nil {
		t.Fatalf("create ascii invite: %v", err)
	}
	_, nbspTok, err := service.CreateInvite(ctx, created.Registry.ID, alice.ID, "\u00a0bob@example.com", true, true)
	if err != nil {
		t.Fatalf("create nbsp invite: %v", err)
	}
	bobASCII, _, err := service.RegisterUser(ctx, "bob@example.com", "password123")
	if err != nil {
		t.Fatalf("register bob: %v", err)
	}
	bobNBSP, _, err := service.RegisterUser(ctx, "\u00a0bob@example.com", "password123")
	if err != nil {
		t.Fatalf("register nbsp bob: %v", err)
	}
	// ASCII account accepts only the ASCII invite; NBSP account only the NBSP one.
	if _, err := service.AcceptInvite(ctx, asciiTok, bobNBSP.ID); !errors.Is(err, errInviteNotFound) {
		t.Fatalf("NBSP account must NOT alias the ASCII invite, got %v", err)
	}
	if _, err := service.AcceptInvite(ctx, asciiTok, bobASCII.ID); err != nil {
		t.Fatalf("ASCII account must accept the ASCII invite: %v", err)
	}
	if _, err := service.AcceptInvite(ctx, nbspTok, bobASCII.ID); !errors.Is(err, errInviteNotFound) {
		t.Fatalf("ASCII account must NOT alias the NBSP invite, got %v", err)
	}
	if _, err := service.AcceptInvite(ctx, nbspTok, bobNBSP.ID); err != nil {
		t.Fatalf("NBSP account must accept the NBSP invite: %v", err)
	}
}

// ---------------------------------------------------------------------------
// HTTP/UI integration & generic-error regression.
// ---------------------------------------------------------------------------

// TestAPIInviteAcceptGenericFailures proves every acceptance failure shares
// one generic 404 response (no invite-state enumeration) and never echoes the
// token or digest.
func TestAPIInviteAcceptGenericFailures(t *testing.T) {
	t.Parallel()

	store, service := newInviteTestService(t, "controlplane_invite_apigen_test")
	server := httptest.NewServer(NewHTTPServer(service, auth.SubjectResolver{Tokens: service.Tokens}))
	defer server.Close()
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	ctx := context.Background()

	alice, _ := mustRegisterAndLogin(t, service, "alice@example.com")
	created, err := service.CreateRegistry(ctx, alice.ID, "alice", "alice.eth", false, "batch-1")
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	_, token, err := service.CreateInvite(ctx, created.Registry.ID, alice.ID, "bob@example.com", true, true)
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	bobSession := mustRegisterAndLoginSession(t, service, "bob@example.com")
	carolSession := mustRegisterAndLoginSession(t, service, "carol@example.com")
	mallorySession := mustRegisterAndLoginSession(t, service, "mallory@example.com")

	// A second invite, revoked before anyone can accept it.
	_, revokedToken, err := service.CreateInvite(ctx, created.Registry.ID, alice.ID, "mallory@example.com", true, true)
	if err != nil {
		t.Fatalf("create second invite: %v", err)
	}
	invites, err := store.ListInvitesForRegistry(ctx, created.Registry.ID)
	if err != nil || len(invites) != 2 {
		t.Fatalf("list invites: %v", err)
	}
	var revokedID int64
	for _, inv := range invites {
		if inv.Email == "mallory@example.com" {
			revokedID = inv.ID
		}
	}
	if _, err := service.RevokeInvite(ctx, alice.ID, created.Registry.ID, revokedID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	postAccept := func(session, tok string) (int, []byte) {
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/invites/accept", bytes.NewReader([]byte(`{"token":"`+tok+`"}`)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+session)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("post accept: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, body
	}

	cases := []struct {
		name    string
		session string
		token   string
	}{
		{"malformed token", bobSession, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"},
		{"unknown digest", bobSession, tokenTextB},
		{"wrong recipient", carolSession, token},
		{"revoked invite", mallorySession, revokedToken},
	}
	for _, tc := range cases {
		status, body := postAccept(tc.session, tc.token)
		if status != http.StatusNotFound {
			t.Fatalf("%s: expected 404, got %d (%s)", tc.name, status, body)
		}
		if !bytes.Equal(body, []byte(`{"error":"invite is not valid or has expired"}`+"\n")) {
			t.Fatalf("%s: expected generic body, got %s", tc.name, body)
		}
		if bytes.Contains(body, []byte(tc.token)) || bytes.Contains(body, []byte("digest")) {
			t.Fatalf("%s: response leaks invite material: %s", tc.name, body)
		}
	}
}

// TestUIRevokeAndPendingList renders the detail page pending-invite list
// (recipient, permissions, state, expiry, revoke control — never a token or
// digest) and drives the UI revocation flow end-to-end: the revoked invite
// disappears from the list, the accept page becomes a generic 404, and a
// non-owner revoke is a generic redirect with no ownership signal.
func TestUIRevokeAndPendingList(t *testing.T) {
	t.Parallel()

	store, service := newInviteTestService(t, "controlplane_invite_ui_revoke_test")
	server := httptest.NewServer(NewHTTPServer(service, auth.SubjectResolver{Tokens: service.Tokens}))
	defer server.Close()
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	ctx := context.Background()

	aliceID, aliceSession := func() (int64, string) {
		u, s := mustRegisterAndLogin(t, service, "alice@example.com")
		return u.ID, s
	}()
	created, err := service.CreateRegistry(ctx, aliceID, "alice", "alice.eth", false, "batch-1")
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	bob, bobSession := mustRegisterAndLogin(t, service, "bob@example.com")
	if _, err := store.CreateMembership(ctx, Membership{
		RegistryID: created.Registry.ID, UserID: bob.ID, Role: "member", CanPull: true, CanPush: true,
	}); err != nil {
		t.Fatalf("create bob membership: %v", err)
	}

	_, token, err := service.CreateInvite(ctx, created.Registry.ID, aliceID, "carol@example.com", true, true)
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	pending, err := store.ListInvitesForRegistry(ctx, created.Registry.ID)
	if err != nil || len(pending) != 1 {
		t.Fatalf("list invites: %v", err)
	}
	invite := pending[0]
	digestHex := hex.EncodeToString(invite.TokenDigest)

	detailPath := "/ui/registries/" + strconv.FormatInt(created.Registry.ID, 10)

	// 1. Detail page: pending row shows recipient, permissions, status, expiry,
	//    and a revoke form — but never the raw token, digest, or accept link.
	detail := getRaw(t, client, server.URL, detailPath, aliceSession)
	if detail.status != http.StatusOK {
		t.Fatalf("detail status: %d", detail.status)
	}
	for _, want := range []string{"carol@example.com", "Write", "pending", "Expires (UTC)", "/invites/" + strconv.FormatInt(invite.ID, 10) + "/revoke", "Revoke"} {
		if !bytes.Contains(detail.body, []byte(want)) {
			t.Fatalf("detail page missing %q: %s", want, detail.body)
		}
	}
	for _, leak := range [][]byte{[]byte(token), []byte(digestHex), []byte("/ui/invites/accept")} {
		if bytes.Contains(detail.body, leak) {
			t.Fatalf("detail page leaks invite credential %q", leak)
		}
	}

	// 2. A NON-owner (plain member) revoke is a generic redirect: no signal.
	revokePath := fmt.Sprintf("%s/invites/%d/revoke", detailPath, invite.ID)
	status, location, body := postForm(t, client, server.URL, revokePath, url.Values{}, bobSession)
	if status != http.StatusSeeOther {
		t.Fatalf("non-owner revoke must redirect generically, got %d body=%s", status, body)
	}
	_ = location
	invitesAfter, err := store.ListInvitesForRegistry(ctx, created.Registry.ID)
	if err != nil || len(invitesAfter) != 1 || invitesAfter[0].Status != "pending" {
		t.Fatalf("non-owner revoke must not change state: %v %+v", err, invitesAfter)
	}

	// 3. Owner revokes via the UI form.
	status, location, body = postForm(t, client, server.URL, revokePath, url.Values{}, aliceSession)
	if status != http.StatusSeeOther || !strings.Contains(location, "invite_revoked=1") {
		t.Fatalf("owner revoke must redirect with invite_revoked, got %d %s body=%s", status, location, body)
	}
	invitesAfter, err = store.ListInvitesForRegistry(ctx, created.Registry.ID)
	if err != nil || len(invitesAfter) != 1 || invitesAfter[0].Status != "revoked" {
		t.Fatalf("owner revoke must revoke the invite: %v %+v", err, invitesAfter)
	}

	// 4. Detail page no longer lists it as pending.
	detail = getRaw(t, client, server.URL, detailPath, aliceSession)
	if bytes.Contains(detail.body, []byte("carol@example.com")) || !bytes.Contains(detail.body, []byte("No pending invites.")) {
		t.Fatalf("revoked invite must leave the pending list: %s", detail.body)
	}

	// 5. Accept page and API acceptance are generic 404s afterwards.
	getResp, err := client.Get(server.URL + "/ui/invites/accept?token=" + url.QueryEscape(token))
	if err != nil {
		t.Fatalf("get accept page: %v", err)
	}
	getResp.Body.Close()
	if getResp.StatusCode != http.StatusNotFound {
		t.Fatalf("accept page after revoke must be 404, got %d", getResp.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/invites/accept", strings.NewReader(`{"token":"`+token+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bobSession)
	acceptResp, err := client.Do(req)
	if err != nil {
		t.Fatalf("api accept: %v", err)
	}
	acceptBody, _ := io.ReadAll(acceptResp.Body)
	acceptResp.Body.Close()
	if acceptResp.StatusCode != http.StatusNotFound || !bytes.Contains(acceptBody, []byte("invite is not valid or has expired")) {
		t.Fatalf("api accept after revoke must be generic 404, got %d %s", acceptResp.StatusCode, acceptBody)
	}
}

// TestUIInviteAcceptRejectsWhitespacePaddedToken proves the UI passes the raw
// token EXACTLY as received — no TrimSpace or any other mutation before the
// strict canonical parse. Whitespace-padded query/form values are rejected
// with the generic 404 on GET and POST, produce no membership and no state
// change, and the exact token keeps working afterwards.
func TestUIInviteAcceptRejectsWhitespacePaddedToken(t *testing.T) {
	t.Parallel()

	store, service := newInviteTestService(t, "controlplane_invite_ui_ws_test")
	server := httptest.NewServer(NewHTTPServer(service, auth.SubjectResolver{Tokens: service.Tokens}))
	defer server.Close()
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	ctx := context.Background()

	alice, _ := mustRegisterAndLogin(t, service, "alice@example.com")
	created, err := service.CreateRegistry(ctx, alice.ID, "alice", "alice.eth", true, "batch-1")
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	_, token, err := service.CreateInvite(ctx, created.Registry.ID, alice.ID, "bob@example.com", true, true)
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	bob, bobSession := mustRegisterAndLogin(t, service, "bob@example.com")

	padded := []string{
		" " + token,
		token + " ",
		"\t" + token,
		token + "\t",
		token + "\n",
		" \t\n" + token + " \r",
	}
	for i, p := range padded {
		path := "/ui/invites/accept?token=" + url.QueryEscape(p)
		// GET: generic 404, never a rendered acceptance page.
		resp, err := client.Get(server.URL + path)
		if err != nil {
			t.Fatalf("case %d: get: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("case %d: GET with padded token %q must 404, got %d", i, p, resp.StatusCode)
		}
		if bytes.Contains(body, []byte(token)) {
			t.Fatalf("case %d: 404 body leaks the token", i)
		}
		// POST (signed in): generic 404, no membership, no state change.
		status, _, body := postForm(t, client, server.URL, path, url.Values{}, bobSession)
		if status != http.StatusNotFound {
			t.Fatalf("case %d: POST with padded token %q must 404, got %d", i, p, status)
		}
		if bytes.Contains(body, []byte(token)) {
			t.Fatalf("case %d: POST 404 body leaks the token", i)
		}
	}

	// No membership was created and the invite is still pending.
	invites, err := store.ListInvitesForRegistry(ctx, created.Registry.ID)
	if err != nil || len(invites) != 1 || invites[0].Status != "pending" {
		t.Fatalf("whitespace attempts must not change invite state: %v %+v", err, invites)
	}
	memberships, err := store.ListMembershipsForRegistry(ctx, created.Registry.ID)
	if err != nil {
		t.Fatalf("list memberships: %v", err)
	}
	if len(memberships) != 1 { // alice's owner membership only
		t.Fatalf("whitespace attempts must not create memberships, got %d", len(memberships))
	}

	// The exact token is unaffected.
	if _, err := store.AcceptInvite(ctx, token, bob); err != nil {
		t.Fatalf("exact token must still be acceptable after whitespace attempts: %v", err)
	}
}

func mustRegisterAndLogin(t *testing.T, service *Service, email string) (User, string) {
	t.Helper()
	user, _, err := service.RegisterUser(context.Background(), email, "password123")
	if err != nil {
		t.Fatalf("register %s: %v", email, err)
	}
	_, session, err := service.Login(context.Background(), email, "password123")
	if err != nil {
		t.Fatalf("login %s: %v", email, err)
	}
	return user, session
}

func mustRegisterAndLoginSession(t *testing.T, service *Service, email string) string {
	t.Helper()
	_, session := mustRegisterAndLogin(t, service, email)
	return session
}

// TestJSONEnsureInviteTokenDigestNotInResponses drives create/accept through
// the real API and asserts neither the raw token nor any digest encoding is
// ever present in the response payloads.
func TestJSONEnsureInviteTokenDigestNotInResponses(t *testing.T) {
	t.Parallel()

	store, service := newInviteTestService(t, "controlplane_invite_json_leak_test")
	server := httptest.NewServer(NewHTTPServer(service, auth.SubjectResolver{Tokens: service.Tokens}))
	defer server.Close()
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	ctx := context.Background()

	alice, aliceSession := mustRegisterAndLogin(t, service, "alice@example.com")
	created, err := service.CreateRegistry(ctx, alice.ID, "alice", "alice.eth", false, "batch-1")
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}

	body := postJSON(t, client, server.URL, "/api/registries/"+strconv.FormatInt(created.Registry.ID, 10)+"/invites",
		map[string]any{"email": "bob@example.com", "canPull": true, "canPush": true}, aliceSession)
	var resp map[string]any
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	token, _ := resp["token"].(string)
	if token == "" {
		t.Fatalf("expected one-time raw token in create response")
	}
	pending, err := store.ListInvitesForRegistry(ctx, created.Registry.ID)
	if err != nil || len(pending) != 1 {
		t.Fatalf("list invites: %v", err)
	}
	digestHex := hex.EncodeToString(pending[0].TokenDigest)
	digestB64 := base64.RawURLEncoding.EncodeToString(pending[0].TokenDigest)
	if bytes.Contains(body, []byte(digestHex)) || bytes.Contains(body, []byte(digestB64)) || bytes.Contains(body, []byte("TokenDigest")) {
		t.Fatalf("create response leaks digest: %s", body)
	}

	bobSession := mustRegisterAndLoginSession(t, service, "bob@example.com")
	acceptBody := postJSON(t, client, server.URL, "/api/invites/accept",
		map[string]string{"token": token}, bobSession)
	if bytes.Contains(acceptBody, []byte(digestHex)) || bytes.Contains(acceptBody, []byte(digestB64)) || bytes.Contains(acceptBody, []byte("TokenDigest")) {
		t.Fatalf("accept response leaks digest: %s", acceptBody)
	}
}
