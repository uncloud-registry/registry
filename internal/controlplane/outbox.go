package controlplane

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// ObjectStore is the writable/readable content-address store a publication
// worker uses: Put uploads bytes and returns a content address, Get reads a
// content address back so read-back can be verified. The production Bee object
// store satisfies it; tests use a memory implementation.
type ObjectStore interface {
	Put(ctx context.Context, data []byte, batchID string) (string, error)
	Get(ctx context.Context, ref string) ([]byte, error)
}

// Provisioning state vocabulary. A registry is born 'provisioning', transitions
// to 'ready' only after BOTH bootstrap jobs have completed verified read-back,
// and to 'failed' only under the explicit bounded-attempts rule. Partial success
// (one job done, the other still retrying) always remains 'provisioning'.
const (
	ProvisioningStateProvisioning = "provisioning"
	ProvisioningStateReady        = "ready"
	ProvisioningStateFailed       = "failed"
)

// Publication kinds: the two deterministic logical bootstrap jobs created
// transactionally with every registry. There is exactly one row per
// (registry, kind), enforced by the schema's unique(registry_id, kind).
const (
	PublicationKindAuth  = "auth"
	PublicationKindStamp = "stamp"
)

// Publication states: pending (eligible for a worker), claimed (held by one
// worker until a lease), succeeded (terminal, verified read-back), and failed
// (terminal, attempts exhausted). Stale claimed jobs are reclaimed after the
// lease by another worker.
const (
	PublicationStatePending   = "pending"
	PublicationStateClaimed   = "claimed"
	PublicationStateSucceeded = "succeeded"
	PublicationStateFailed    = "failed"
)

// Claim/ownership failures that must never leak as a retryable external
// failure (they mean the job is legitimately owned by another, newer worker,
// so a stale worker must back off, not overwrite).
var (
	errLostClaim        = errors.New("publication claim was lost to another worker")
	errReadBackMismatch = errors.New("publication read-back did not match expected content")
)

// PublicationJob is the inbox row for one logical bootstrap publication. The
// payload holds the DETERMINISTIC canonical policy-document JSON and contains
// NO secret key material; the object_ref (uploaded content address) and
// feed_ref (published topic feed) are persisted stage-by-stage so a retry after
// an upload or feed-update failure resumes without repeating finished stages.
// LastError is a sanitized coarse class (never a payload, secret, or internal
// response body).
type PublicationJob struct {
	ID           int64
	RegistryID   int64
	Kind         string
	PayloadJSON  []byte
	State        string
	ObjectRef    string
	FeedRef      string
	Attempts     int
	NextAttempt  time.Time
	ClaimedUntil *time.Time
	ClaimedBy    string
	LastError    string
	CreatedAt    time.Time
	CompletedAt  *time.Time
}

// publicationJobColumns is the canonical read column list for
// registry_publication_jobs.
const publicationJobColumns = `id, registry_id, kind, state, payload_json, object_ref, feed_ref,
	attempts, next_attempt_at, claimed_until, claimed_by, last_error, created_at, completed_at`

func scanPublicationJob(s scanRow, job *PublicationJob) error {
	var nextAttempt, createdAt string
	var claimedUntil, completedAt sql.NullString
	var payload []byte
	if err := s.Scan(&job.ID, &job.RegistryID, &job.Kind, &job.State, &payload,
		&job.ObjectRef, &job.FeedRef, &job.Attempts, &nextAttempt, &claimedUntil,
		&job.ClaimedBy, &job.LastError, &createdAt, &completedAt); err != nil {
		return err
	}
	job.PayloadJSON = payload
	job.NextAttempt, _ = time.Parse(time.RFC3339, nextAttempt)
	job.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	if claimedUntil.Valid {
		if t, err := time.Parse(time.RFC3339, claimedUntil.String); err == nil {
			job.ClaimedUntil = &t
		}
	}
	if completedAt.Valid {
		if t, err := time.Parse(time.RFC3339, completedAt.String); err == nil {
			job.CompletedAt = &t
		}
	}
	return nil
}

// randomWorkerToken returns a fresh cryptographically random hex token that
// identifies one claim. It is generated inside the claim transaction so a
// worker's ownership of a claimed job is provable and unforgeable.
func randomWorkerToken() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// CreateProvisionedRegistry atomically creates a registry, its owner
// membership, and its two durable bootstrap jobs (auth, stamp) in ONE write
// transaction. The feed-owner signing key is encrypted inside the transaction
// with the row's own ID and owner as AES-GCM AAD (the same custody contract as
// CreateRegistry; the plaintext is owned by the caller and wiped after the
// call). Any failure — including a second job insert failing — rolls the whole
// thing back, so there is never an orphan registry, member, or job, and no
// external publication happens here. The registry is returned 'provisioning',
// never claiming published bootstrap refs.
func (s *Store) CreateProvisionedRegistry(ctx context.Context, registry Registry, keyCipher *FeedKeyCipher, feedKey []byte, authPayload []byte, stampPayload []byte) (Registry, error) {
	if keyCipher == nil {
		return Registry{}, errFeedKeyCipherNotConfigured
	}
	if len(feedKey) == 0 {
		return Registry{}, errors.New("create registry: feed key plaintext is required")
	}
	if len(authPayload) == 0 || len(stampPayload) == 0 {
		return Registry{}, errors.New("create registry: both bootstrap policy payloads are required")
	}
	registry.ProvisioningState = ProvisioningStateProvisioning

	var created Registry
	err := s.withWriteTx(ctx, func(ctx context.Context, c *sql.Conn) error {
		now := time.Now().UTC().Format(time.RFC3339)
		result, err := c.ExecContext(ctx, `insert into registries
			(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, provisioning_state, created_at)
			values (?, ?, ?, ?, ?, '', ?, ?, ?, ?)`,
			registry.Slug, registry.Host, registry.ENSName, registry.OwnerUserID, registry.FeedOwnerAddress,
			registry.DefaultStampBatchID, boolToInt(registry.AnonymousPull), registry.ProvisioningState, now)
		if err != nil {
			return fmt.Errorf("create registry: %w", err)
		}
		id, _ := result.LastInsertId()

		enc, err := keyCipher.Encrypt(id, registry.FeedOwnerAddress, feedKey)
		if err != nil {
			return err
		}
		if _, err := c.ExecContext(ctx, `update registries set feed_key_ciphertext = ?, feed_key_nonce = ?, feed_key_version = ? where id = ?`,
			enc.Ciphertext, enc.Nonce, enc.KeyVersion, id); err != nil {
			return err
		}

		if _, err := c.ExecContext(ctx, `insert into registry_memberships (registry_id, user_id, role, can_pull, can_push, created_at) values (?, ?, ?, ?, ?, ?)`,
			id, registry.OwnerUserID, "owner", 1, 1, now); err != nil {
			return err
		}

		for _, j := range []struct {
			kind    string
			payload []byte
		}{
			{PublicationKindAuth, authPayload},
			{PublicationKindStamp, stampPayload},
		} {
			if _, err := c.ExecContext(ctx, `insert into registry_publication_jobs
				(registry_id, kind, state, payload_json, attempts, next_attempt_at, created_at)
				values (?, ?, ?, ?, 0, ?, ?)`,
				id, j.kind, PublicationStatePending, j.payload, now, now); err != nil {
				return err
			}
		}

		created = registry
		created.ID = id
		created.FeedKey = enc
		created.FeedKeySet = true
		return nil
	})
	if err != nil {
		return Registry{}, err
	}
	return created, nil
}

// ClaimStalePublicationJobs atomically claims a bounded batch of jobs that are
// either pending (and due) or claimed past their lease, returning the claimed
// rows plus the worker token that owns them for the lease. The claim is a
// guarded conditional UPDATE so concurrent workers never both win: only the
// worker whose conditional update affected exactly one row owns the job, and a
// job claimed by a live lease is invisible to other workers until it expires.
// This is a short write transaction with no network calls inside it.
func (s *Store) ClaimStalePublicationJobs(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]PublicationJob, string, error) {
	if limit <= 0 {
		return nil, "", errors.New("claim: limit must be positive")
	}
	worker, err := randomWorkerToken()
	if err != nil {
		return nil, "", err
	}
	nowText := now.UTC().Format(time.RFC3339)
	untilText := now.UTC().Add(lease).Format(time.RFC3339)

	var claimed []PublicationJob
	err = s.withWriteTx(ctx, func(ctx context.Context, c *sql.Conn) error {
		rows, err := c.QueryContext(ctx, `select id from registry_publication_jobs
			where (state = 'pending' and next_attempt_at <= ?)
			   or (state = 'claimed' and claimed_until <= ?)
			order by id asc limit ?`, nowText, nowText, limit)
		if err != nil {
			return err
		}
		var ids []int64
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		for _, id := range ids {
			res, err := c.ExecContext(ctx, `update registry_publication_jobs
				set state = 'claimed', claimed_by = ?, claimed_until = ?, last_error = ''
				where id = ? and ((state = 'pending' and next_attempt_at <= ?)
				              or (state = 'claimed' and claimed_until <= ?))`,
				worker, untilText, id, nowText, nowText)
			if err != nil {
				return err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return err
			}
			if n != 1 {
				continue // another worker claimed it first in a concurrent batch; skip
			}
			var job PublicationJob
			if err := scanPublicationJob(c.QueryRowContext(ctx, `select `+publicationJobColumns+` from registry_publication_jobs where id = ?`, id), &job); err != nil {
				return err
			}
			claimed = append(claimed, job)
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return claimed, worker, nil
}

// SetPublicationObjectRef persists the uploaded object reference for a claimed
// job. It is conditional on ownership so a stale worker cannot write onto a job
// it no longer owns. Returns errLostClaim when the claim was lost (the job was
// reclaimed after lease expiry by a newer worker).
func (s *Store) SetPublicationObjectRef(ctx context.Context, jobID int64, worker string, ref string) error {
	return s.jobGuardUpdate(ctx, jobID, worker,
		`update registry_publication_jobs set object_ref = ? where id = ? and state = 'claimed' and claimed_by = ?`, ref)
}

// SetPublicationFeedRef persists the published feed reference for a claimed
// job, conditionally on ownership (see SetPublicationObjectRef).
func (s *Store) SetPublicationFeedRef(ctx context.Context, jobID int64, worker string, ref string) error {
	return s.jobGuardUpdate(ctx, jobID, worker,
		`update registry_publication_jobs set feed_ref = ? where id = ? and state = 'claimed' and claimed_by = ?`, ref)
}

// CompletePublicationJob marks a claimed job succeeded (terminal) conditionally
// on ownership and current state, so a stale worker cannot overwrite a newer
// claim. Returns errLostClaim if ownership was lost.
func (s *Store) CompletePublicationJob(ctx context.Context, jobID int64, worker string, now time.Time) error {
	return s.jobGuardUpdate(ctx, jobID, worker,
		`update registry_publication_jobs set state = 'succeeded', completed_at = ?, claimed_by = '', claimed_until = null
		 where id = ? and state = 'claimed' and claimed_by = ?`, now.UTC().Format(time.RFC3339))
}

// FailPublicationJob registers a retryable failure for a claimed job: it
// increments the attempt count, schedules the next attempt with bounded
// exponential backoff, and applies the terminal rule (state becomes 'failed'
// once attempts reach maxAttempts). It is conditional on ownership. Returns
// terminal=true when the job exhausts attempts, and the caller then marks the
// registry 'failed' — the only explicit bounded path to terminal provisioning
// failure. LastError holds only a sanitized class string (never payload,
// secrets, or internal response body).
func (s *Store) FailPublicationJob(ctx context.Context, jobID int64, worker string, now time.Time, maxAttempts int, backoffBase, backoffMax time.Duration, safeErr string) (bool, error) {
	var terminal bool
	err := s.withWriteTx(ctx, func(ctx context.Context, c *sql.Conn) error {
		var attempts int
		if err := c.QueryRowContext(ctx, `select attempts from registry_publication_jobs where id = ? and state = 'claimed' and claimed_by = ?`, jobID, worker).Scan(&attempts); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return errLostClaim
			}
			return err
		}
		newAttempts := attempts + 1
		state := PublicationStatePending
		if maxAttempts > 0 && newAttempts >= maxAttempts {
			state = PublicationStateFailed
			terminal = true
		}
		next := now.UTC().Add(attemptBackoff(newAttempts, backoffBase, backoffMax)).Format(time.RFC3339)
		res, err := c.ExecContext(ctx, `update registry_publication_jobs
			set attempts = ?, state = ?, last_error = ?, next_attempt_at = ?, claimed_by = '', claimed_until = null
			where id = ? and state = 'claimed' and claimed_by = ?`,
			newAttempts, state, safeErr, next, jobID, worker)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return errLostClaim
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return terminal, nil
}

// jobGuardUpdate runs a single-by-statement ownership-guarded UPDATE and
// returns errLostClaim when fewer than one row changed. args are by-position:
// [<dynamic values...>, jobID, worker].
func (s *Store) jobGuardUpdate(ctx context.Context, jobID int64, worker string, query string, dynamicArgs ...any) error {
	return s.withWriteTx(ctx, func(ctx context.Context, c *sql.Conn) error {
		args := append(append([]any{}, dynamicArgs...), jobID, worker)
		res, err := c.ExecContext(ctx, query, args...)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return errLostClaim
		}
		return nil
	})
}

// attemptBackoff returns the bounded exponential backoff for the given attempt
// number: base << (attempt-1), capped at max, with a hard shift cap so naive
// overflow cannot blow the delay into the far future.
func attemptBackoff(attempt int, base, max time.Duration) time.Duration {
	shift := attempt - 1
	if shift > 16 {
		shift = 16
	}
	d := base << shift
	if d > max {
		d = max
	}
	if d < 0 {
		return max
	}
	return d
}

// MarkRegistryReady transitions a registry from provisioning to ready. It is
// guarded in SQL to only apply from the provisioning state, so it can never
// regress a ready or failed registry.
func (s *Store) MarkRegistryReady(ctx context.Context, registryID int64) error {
	return s.updateProvisioningState(ctx, registryID, ProvisioningStateReady)
}

// MarkRegistryFailed transitions a registry from provisioning to failed. See
// MarkRegistryReady.
func (s *Store) MarkRegistryFailed(ctx context.Context, registryID int64) error {
	return s.updateProvisioningState(ctx, registryID, ProvisioningStateFailed)
}

func (s *Store) updateProvisioningState(ctx context.Context, registryID int64, state string) error {
	_, err := s.DB.ExecContext(ctx, `update registries set provisioning_state = ? where id = ? and provisioning_state = 'provisioning'`, state, registryID)
	return err
}

// RegistryProvisioningJobsComplete reports whether both bootstrap jobs for a
// registry are in the terminal succeeded state — the only condition under which
// the reconciler marks the registry 'ready'.
func (s *Store) RegistryProvisioningJobsComplete(ctx context.Context, registryID int64) (bool, error) {
	var n int
	if err := s.DB.QueryRowContext(ctx, `select count(*) from registry_publication_jobs where registry_id = ? and state = 'succeeded'`, registryID).Scan(&n); err != nil {
		return false, err
	}
	return n == 2, nil
}

// GetPublicationJob returns one job row by id (test/diagnostic helper; not used
// by the reconciler's happy path).
func (s *Store) GetPublicationJob(ctx context.Context, jobID int64) (PublicationJob, error) {
	var job PublicationJob
	if err := scanPublicationJob(s.DB.QueryRowContext(ctx, `select `+publicationJobColumns+` from registry_publication_jobs where id = ?`, jobID), &job); err != nil {
		return PublicationJob{}, err
	}
	return job, nil
}
