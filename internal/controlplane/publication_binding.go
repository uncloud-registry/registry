package controlplane

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"time"

	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/spec"
)

// PublicationBinding is one durable preflight reservation: an explicit
// caller operation key bound to EXACTLY ONE logical publication payload —
// registry + owner + repository + tag + manifest digest. Only the fixed-size
// domain-separated hash of the typed binding fields is stored — never a raw
// request field, and never any credential or key material. The row is
// permanent: it never expires into cross-request reuse, so a conflicting key
// reuse is rejected for the life of the operation identity.
type PublicationBinding struct {
	OperationID string
	RegistryID  int64
	BindingHash [32]byte
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// publicationBindingColumns is the canonical read column list.
const publicationBindingColumns = `operation_id, registry_id, binding_hash, created_at, updated_at`

// publicationBindingTableSQL is the migration-15 schema for the durable
// operation-key binding table. operation_id is the permanent single-winner
// primary key (two concurrent changed requests can never both bind one key),
// registry_id is the FK-scoped namespace, and binding_hash is the exact
// 32-byte domain-separated hash of the five typed binding fields. The
// operation-ID grammar is enforced per row by dedicated identity triggers
// (the same byte-exact predicate migration 14 installs on
// feed_signer_operations).
const publicationBindingTableSQL = `CREATE TABLE publication_bindings (
	operation_id text primary key
		check (typeof(operation_id) = 'text' and length(operation_id) between 1 and 128),
	registry_id integer not null
		check (typeof(registry_id) = 'integer' and registry_id > 0)
		references registries(id) on delete cascade,
	binding_hash blob not null
		check (typeof(binding_hash) = 'blob' and length(binding_hash) = 32),
	created_at integer not null check (typeof(created_at) = 'integer'),
	updated_at integer not null check (typeof(updated_at) = 'integer')
)`

// publicationBindingIdentityTriggerSQL returns the dedicated DB-level
// operation-ID identity triggers (BEFORE INSERT and BEFORE UPDATE on
// publication_bindings), applying the SAME byte-exact operation-ID grammar
// migration 14 established for feed_signer_operations (the shared
// feedSignerOperationIDGrammarCondV14 predicate, decided on raw stored bytes)
// so a direct-SQL write can never store a grammar-violating operation key.
// The trigger names are distinct from the feed-signer triggers because
// SQLite triggers are database-global.
func publicationBindingIdentityTriggerSQL() []string {
	return []string{
		`create trigger publication_binding_operation_id_ins
			before insert on publication_bindings for each row
			begin select raise(abort, 'publication binding operation id violates the byte-exact operation-ID grammar') where ` + feedSignerOperationIDGrammarCondV14 + `; end`,
		`create trigger publication_binding_operation_id_upd
			before update on publication_bindings for each row
			begin select raise(abort, 'publication binding operation id violates the byte-exact operation-ID grammar') where ` + feedSignerOperationIDGrammarCondV14 + `; end`,
	}
}

// installPublicationBindingStore is migration 15's body. It creates the
// durable publication_bindings table and installs its operation-ID identity
// triggers. It is pure forward DDL over a NEW table — it never reads,
// mutates, or drops any migration 1-14 state — so already-migrated and fresh
// databases converge on the same schema, and any statement failure aborts
// the migration transaction atomically (version stays 14, no schema object
// installed), which the rollback tests pin.
func installPublicationBindingStore(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, publicationBindingTableSQL); err != nil {
		return errors.New("migration 15: create publication bindings table")
	}
	for _, stmt := range publicationBindingIdentityTriggerSQL() {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return errors.New("migration 15: install publication binding operation-id identity trigger")
		}
	}
	return nil
}

func scanPublicationBinding(s scanRow, b *PublicationBinding) error {
	var (
		hash             []byte
		createdNs, updNs int64
	)
	if err := s.Scan(&b.OperationID, &b.RegistryID, &hash, &createdNs, &updNs); err != nil {
		return err
	}
	copy(b.BindingHash[:], hash)
	b.CreatedAt = nanosToTime(createdNs)
	b.UpdatedAt = nanosToTime(updNs)
	return nil
}

// ReservePublicationBinding atomically ensures a binding row exists for an
// operation ID + registry + binding hash. On a fresh ID it inserts the row;
// on an existing ID it leaves it untouched and returns the current row so
// the caller can apply the idempotency decision (identical hash -> pass;
// differing hash -> hard conflict). The insert-or-ignore is atomic under one
// write transaction, so concurrent changed requests have exactly one binding
// winner BEFORE any object write: the loser reads the winner's row, sees the
// hash mismatch, and conflicts without ever touching the data plane objects.
func (s *Store) ReservePublicationBinding(ctx context.Context, operationID string, registryID int64, bindingHash [32]byte) (PublicationBinding, error) {
	var b PublicationBinding
	err := s.withWriteTx(ctx, func(ctx context.Context, c *sql.Conn) error {
		now := time.Now().UTC()
		nowNanos := timeToNanos(now)
		if _, err := c.ExecContext(ctx, `insert or ignore into publication_bindings
			(operation_id, registry_id, binding_hash, created_at, updated_at)
			values (?, ?, ?, ?, ?)`,
			operationID, registryID, bindingHash[:], nowNanos, nowNanos); err != nil {
			return err
		}
		return scanPublicationBinding(c.QueryRowContext(ctx,
			`select `+publicationBindingColumns+` from publication_bindings where operation_id = ?`, operationID), &b)
	})
	if err != nil {
		return PublicationBinding{}, err
	}
	return b, nil
}

// NormalizePublicationBindingHash derives the deterministic domain-separated
// SHA-256 of the FIVE typed binding fields (registry, owner, repo, tag,
// manifest digest) with the same explicit binary framing
// (fixed-width/8-byte integers, length-prefixed strings) the feed-commit
// hash uses, so no NUL or separator byte inside a value can create a
// field-boundary collision. The owner is normalized (lowercase, 0x-trimmed)
// so equivalent owner spellings bind identically. It is a PURE function of
// the logical payload, so the same key+payload always derives the same hash
// and a changed payload always derives a different one.
func NormalizePublicationBindingHash(registryID int64, owner, repo, tag, manifestDigest string) [32]byte {
	h := sha256.New()
	h.Write([]byte("uncloud-registry-publication-binding:v1\x00"))
	writeHashInt(h, registryID)
	writeHashBytes(h, spec.NormalizeOwner(owner))
	writeHashBytes(h, repo)
	writeHashBytes(h, tag)
	writeHashBytes(h, manifestDigest)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// PublicationBinder is the control-plane side of the preflight operation-key
// binding: it validates the bounded request against the durable registries,
// derives the canonical binding hash, and atomically reserves the key for
// exactly one logical payload BEFORE the data plane writes any immutable
// object. The registry process never sends key material; nothing but the
// hash is ever stored. The signer's stable sentinels classify the outcomes
// (the internal server maps them to the same coarse statuses as feed
// commits: 400 malformed, 404 unknown/not-ready registry, 409 conflict,
// 503 backend).
type PublicationBinder struct {
	Store *Store
}

// Bind durably binds one explicit caller operation key to one logical
// payload. A fresh key is reserved; an identical existing binding passes
// (so a preflight reservation never blocks its matching later commit); a
// reused key with a different binding is errFeedSignerConflict BEFORE any
// write. All validation happens before any durable mutation, and no error
// ever carries a request field value.
func (b *PublicationBinder) Bind(ctx context.Context, req publish.OperationBindingRequest) error {
	if isNilDependency(b.Store) {
		return errFeedSignerBackend
	}
	if err := publish.ValidatePublicationBindingRequest(req); err != nil {
		return errFeedSignerMalformed
	}

	// The registry must exist and be READY before any binding row is created:
	// a provisioning/failed registry must not accumulate publication intents.
	reg, err := b.Store.FindRegistryByID(ctx, req.RegistryID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errFeedSignerRegistryNotFound
		}
		return errFeedSignerBackend
	}
	if reg.ProvisioningState != ProvisioningStateReady {
		return errFeedSignerNotReady
	}
	// Owner proof BEFORE any durable write: the claimed owner must be the
	// registry's normalized feed-owner address (constant-time compare).
	if !constantEqual(spec.NormalizeOwner(req.Owner), spec.NormalizeOwner(reg.FeedOwnerAddress)) {
		return errFeedSignerRegistryNotFound
	}

	hash := NormalizePublicationBindingHash(req.RegistryID, req.Owner, req.Repo, req.Tag, req.ManifestDigest)
	existing, err := b.Store.ReservePublicationBinding(ctx, req.OperationID, req.RegistryID, hash)
	if err != nil {
		return errFeedSignerBackend
	}
	if existing.BindingHash != hash {
		// The operation key was ALREADY durably bound to a different logical
		// payload — a hard conflict, decided before any object write.
		return errFeedSignerConflict
	}
	return nil
}
