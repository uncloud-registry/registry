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
	return store, &Service{Store: store, Tokens: newTestSessionManager(t), RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t)}
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
		service := &Service{Store: store, Tokens: newTestSessionManager(t), RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t)}
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
// supported schema version (0 legacy, 1, 2, 3) to v4 and proves: mixed legacy
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
			if err != nil || got != 4 {
				t.Fatalf("expected schema version 4, got %d (err %v)", got, err)
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
// token_hash values, plaintext-as-valid rows, duplicate converted digests, and
// accepted invites without a derivable acceptor.
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

	t.Run("accepted invite without membership", func(t *testing.T) {
		t.Parallel()
		db := openInviteMigDB(t, "corrupt_accepted")
		seedInvitesFixture(t, db, func(ctx context.Context, db *sql.DB) error {
			_, err := db.ExecContext(ctx, `insert into registry_invites
				(registry_id, email, role, can_pull, can_push, token_hash, status, expires_at, created_at)
				values (1, 'ghost@example.com', 'member', 1, 0, ?, 'accepted', ?, ?)`,
				hex.EncodeToString([]byte(tokenTextC)),
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
		if got, err := CurrentSchemaVersion(ctx, db); err != nil || got != 4 {
			t.Fatalf("expected version 4, got %d (err %v)", got, err)
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
			if got, err := CurrentSchemaVersion(ctx, db); err != nil || got != 4 {
				t.Fatalf("expected schema version 4, got %d (err %v)", got, err)
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
	// dave is the intended recipient AND already a member; the historical
	// accepter could have been anyone — attribution is impossible.
	seed(`insert into registry_memberships (registry_id, user_id, role, can_pull, can_push, created_at) values (1, 3, 'member', 1, 1, ?)`, now)
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
	if len(memberships) != 2 {
		t.Fatalf("no membership change allowed: expected 2, got %d", len(memberships))
	}
	for _, m := range memberships {
		if m.UserID == 3 && m.Role != "member" {
			t.Fatalf("dave's pre-existing membership must be untouched, got %+v", m)
		}
	}
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
