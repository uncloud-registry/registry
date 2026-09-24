package staging

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/uncloud-registry/registry/internal/spec"
)

// Service is the durable upload-staging contract (approved plan Task 15).
//
// Sessions are backed by a private 0700 descriptor-relative filesystem spool
// (os.Root, retained for the service lifetime) and a dedicated SQLite
// metadata database. Every state transition that reads then writes (Append,
// Open, MarkFinalized, Delete, Expire, Create, startup reconciliation) is
// serialized across independent service instances with a real BEGIN
// IMMEDIATE transaction and bounded context-aware busy retry — never a
// process-local mutex.
//
// Append durability order: bounded streamed copy at the exact committed
// offset, fsync of the spool file, then the SQLite offset commit. The
// database offset never advances beyond durable file bytes; a crash between
// fsync and commit leaves a recoverable tail that reconciliation truncates
// on startup and before every subsequent access — the truncation itself is
// fsynced, so an acknowledged reconciliation can never reappear. A file
// shorter than the committed offset is fail-closed corruption.
//
// Filesystem deletion protocol: a durable `deleting` tombstone is committed
// BEFORE any unlink; the unlink and the containing-directory fsync happen
// OUTSIDE any transaction (a transaction could roll back and strand live
// rows with removed files); the metadata row is removed only after the file
// is durably gone. Any failure retains the tombstone for a later run, so a
// restart is always exact. Delete is idempotent and confidential: absent and
// wrong-owner ids return identically nil.
//
// Create protocol: a durable `creating` row carrying an unforgeable random
// token and a bounded lease anchor commits FIRST; only after the spool file
// durably carries the token bytes does the creator activate the row with a
// token-and-anchor-guarded update. Startup never activates a creating row:
// stale leases are rolled back only when attributable to their token file,
// live leases are left alone, and unknown residue fails startup closed.
type Service interface {
	Create(ctx context.Context, repo, actor string, ttl time.Duration) (Session, error)
	Status(ctx context.Context, id, repo, actor string) (Session, error)
	Append(ctx context.Context, id, repo, actor string, expectedOffset int64, src io.Reader, maxBytes int64) (Session, error)
	Open(ctx context.Context, id, repo, actor string) (io.ReadCloser, Session, error)
	MarkFinalized(ctx context.Context, id, repo, actor, digest, beeRef, mediaType string, size int64) error
	ListFinalized(ctx context.Context, repo, actor string) ([]spec.StagedBlob, error)
	Delete(ctx context.Context, id, repo, actor string) error
	Expire(ctx context.Context, now time.Time, limit int) (int, error)
}

var _ Service = (*service)(nil)

// maxTxAttempts bounds BEGIN IMMEDIATE serialization retries per operation.
const maxTxAttempts = 50

// creationLease bounds how long a `creating` row may exist before another
// instance may treat it as abandoned. A crashed creator whose row is older
// than the lease is rolled back (its attributable file removed); a live
// creator's row is never touched.
const creationLease = 5 * time.Minute

// creatingTokenLen is the byte length of the unforgeable per-create token
// written to a creating file and bound to its row.
const creatingTokenLen = 32

// service is the concrete durable staging service.
type service struct {
	spool         *spool
	pool          *dbPool
	now           func() time.Time
	creationLease time.Duration

	// closeOnce and closeErr make Close IDEMPOTENT and JOINED: exactly one
	// invocation runs the (pool + spool) shutdown body while every concurrent
	// or later call waits for it and shares the fixed data-free result, so
	// the pool and the spool are never closed twice and no Close returns
	// before shutdown fully finishes.
	closeOnce sync.Once
	closeErr  error

	// Test-only fault injection points (nil in production). They are set
	// before operations and never mutated concurrently.
	fsyncHook        func() error // replaces the spool-file fsync
	dirSyncHook      func() error // replaces the spool-directory fsync
	dbWriteHook      func() error // fires before the offset UPDATE
	commitHook       func() error // fires before COMMIT
	createBarrier    func()       // fires after both durable files exist, before activation
	postActivateHook func()       // fires immediately after the activation commit, before token-file removal
}

// NewService constructs the durable staging service: it validates and
// creates the private spool root and the database parent (descriptor-
// relative, symlink-rejecting), opens and migrates the dedicated staging
// database after exact schema verification, pins every database connection
// to the verified file, and reconciles spool files against the committed
// database state before returning. Interrupted creates are only ever rolled
// back from stale, token-attributable state and live creating leases are
// never touched. Every constructor failure is a data-free ErrDependency;
// only an actually canceled context surfaces as the exact context error.
func NewService(ctx context.Context, spoolRoot, dbPath string) (*service, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sp, err := newSpool(ctx, spoolRoot)
	if err != nil {
		return nil, err
	}
	pool, err := openStagingPool(ctx, dbPath, 4)
	if err != nil {
		sp.Close()
		return nil, err
	}
	svc := &service{spool: sp, pool: pool, now: time.Now, creationLease: creationLease}
	svc.spool.syncFile = func(f *os.File) error { return svc.syncFile(f) }
	if err := svc.reconcileStartup(ctx); err != nil {
		pool.close()
		sp.Close()
		return nil, err
	}
	return svc, nil
}

// Close releases the retained database handles and the root descriptor. It is
// IDEMPOTENT and JOINED: concurrent or repeated Close calls wait for the
// single shutting-down completion and share its fixed data-free result, so
// the pool and the spool are never closed twice and no Close returns before
// shutdown fully finishes. Acquires made after Close return a fixed
// closed-pool error.
func (s *service) Close() error {
	s.closeOnce.Do(func() {
		var errs []error
		if s.pool != nil {
			s.pool.close()
			s.pool = nil
		}
		if s.spool != nil {
			if err := s.spool.Close(); err != nil {
				errs = append(errs, err)
			}
			s.spool = nil
		}
		s.closeErr = errors.Join(errs...)
	})
	return s.closeErr
}

// ---------------------------------------------------------------------------
// BEGIN IMMEDIATE serialization
// ---------------------------------------------------------------------------

// withTx pins one retained connection, runs BEGIN IMMEDIATE (retried on
// BUSY/LOCKED with bounded context-aware backoff), executes fn on that
// connection, and COMMITs. Any failure rolls back; a busy failure
// mid-transaction retries the WHOLE read-decision-write body, never a single
// statement.
//
// Panic safety: runTxAttempt installs the rollback BEFORE invoking the
// callback and guarantees the transaction is rolled back on EVERY
// non-committed exit — including a panic from the callback or from an
// io.Reader it drives (Append copies inside fn). A connection with BEGIN
// active is therefore never released back to the pool, the panic still
// propagates to the caller, and a recovered caller finds a clean pool.
func (s *service) withTx(ctx context.Context, fn func(conn *sql.Conn) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	conn, err := s.pool.acquire(ctx)
	if err != nil {
		return err
	}
	defer s.pool.release(conn)

	for attempt := 0; attempt < maxTxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, "begin immediate"); err != nil {
			if isBusyLocked(err) {
				if waitErr := busyWait(ctx, attempt); waitErr != nil {
					return waitErr
				}
				continue
			}
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			return typed(ErrDependency, err)
		}

		runErr := s.runTxAttempt(ctx, conn, fn)
		if runErr == nil {
			return nil
		}
		if isBusyLocked(runErr) && ctx.Err() == nil {
			if waitErr := busyWait(ctx, attempt); waitErr != nil {
				return waitErr
			}
			continue
		}
		return runErr
	}
	return typed(ErrDependency, errors.New("staging transaction serialization exceeded retry bound"))
}

// runTxAttempt executes one begin/fn/commit cycle on a connection that is
// already inside BEGIN IMMEDIATE. The rollback defer is installed FIRST and
// the recover defer SECOND, so on a panic the recover re-raises only after
// the rollback has run — the connection leaving this function never carries
// an open transaction, committed or not (commit success disables the
// rollback).
func (s *service) runTxAttempt(ctx context.Context, conn *sql.Conn, fn func(conn *sql.Conn) error) error {
	committed := false
	defer func() {
		if !committed {
			// Best-effort rollback on every non-committed exit. The
			// callback, the commit hook, and COMMIT itself all run above
			// this defer, so a panic from any of them is covered too.
			_, _ = conn.ExecContext(context.Background(), "rollback")
		}
	}()
	// Recover must be registered AFTER the rollback defer so the rollback
	// runs (it is invoked by the re-panic unwinding) before the panic
	// propagates; the panic value is preserved.
	defer func() {
		if r := recover(); r != nil {
			panic(r)
		}
	}()

	runErr := fn(conn)
	if runErr == nil && s.commitHook != nil {
		if hookErr := s.commitHook(); hookErr != nil {
			runErr = typed(ErrDependency, hookErr)
		}
	}
	if runErr == nil {
		if _, err := conn.ExecContext(ctx, "commit"); err != nil {
			if cerr := ctx.Err(); cerr != nil {
				runErr = cerr
			} else {
				runErr = typed(ErrDependency, err)
			}
		} else {
			committed = true
		}
	}
	return runErr
}

// queryer abstracts the pinned *sql.Conn used inside withTx.
type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// ---------------------------------------------------------------------------
// Session row mapping
// ---------------------------------------------------------------------------

type sessionRow struct {
	id, repo, actor, state string
	offset                 int64
	createdNanos           int64
	expiresNanos           int64
	digest                 sql.NullString
	beeRef                 sql.NullString
	mediaType              sql.NullString
	size                   sql.NullInt64
	createToken            sql.NullString
	cleanupToken           sql.NullString
}

const sessionColumns = `id, repo, actor, state, offset, created_at, expires_at, digest, bee_ref, media_type, size, create_token, cleanup_token`

func fetchSession(ctx context.Context, q queryer, id string) (*sessionRow, bool, error) {
	var row sessionRow
	err := q.QueryRowContext(ctx,
		`select `+sessionColumns+` from upload_sessions where id = ?`, id).
		Scan(&row.id, &row.repo, &row.actor, &row.state, &row.offset,
			&row.createdNanos, &row.expiresNanos, &row.digest, &row.beeRef,
			&row.mediaType, &row.size, &row.createToken, &row.cleanupToken)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		// An actually canceled context is authoritative over any wrapped
		// driver error.
		if cerr := ctx.Err(); cerr != nil {
			return nil, false, cerr
		}
		return nil, false, err
	}
	return &row, true, nil
}

func ownsSession(row *sessionRow, repo, actor string) bool {
	return row.repo == repo && row.actor == actor
}

func (s *service) expiredNanos(expiresNanos int64) bool {
	return s.now().UTC().UnixNano() >= expiresNanos
}

// creatingLeaseStale reports whether a creating row's lease has expired:
// only the creator may activate it while the lease is live; after the lease
// another instance may roll it back.
func (s *service) creatingLeaseStale(createdNanos int64) bool {
	lease := s.creationLease
	if lease <= 0 {
		lease = creationLease
	}
	return s.now().UTC().UnixNano() >= createdNanos+lease.Nanoseconds()
}

// buildSession maps a durable row to the exported Session.
func buildSession(row *sessionRow) Session {
	ses := Session{
		ID:        row.id,
		Repo:      row.repo,
		Actor:     row.actor,
		State:     State(row.state),
		Offset:    row.offset,
		CreatedAt: time.Unix(0, row.createdNanos).UTC(),
		ExpiresAt: time.Unix(0, row.expiresNanos).UTC(),
	}
	if row.digest.Valid {
		ses.Digest = row.digest.String
		ses.BeeRef = row.beeRef.String
		ses.MediaType = row.mediaType.String
		ses.Size = row.size.Int64
	}
	return ses
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

// Create protocol (crash-safe state machine with explicit durable phases):
//
//	Tx 1   commit the durable `creating` row carrying an unforgeable random
//	       token and a bounded lease anchor (created_at). No file exists yet.
//	PhaseT make the TOKEN FILE (`<id>.tok`, O_EXCL, exact 0600) carry the
//	       token bytes, fsync the file, fsync the directory. This file is the
//	       attribution anchor: at every later crash point it proves who owns
//	       this create attempt.
//	PhaseC make the CANONICAL payload file (`<id>`, O_EXCL, exact 0600)
//	       exist EMPTY and durable (fsync file, fsync directory). The
//	       canonical file contains ONLY upload bytes from offset 0 — it never
//	       carries the token — so an active canonical file is always
//	       token-free by construction.
//	verify re-read the token file and compare constant-time with the row
//	       token; anything else fails closed before activation is attempted.
//	Tx 2   activate: creating→active with create_token cleared and the token
//	       atomically moved INTO cleanup_token (the durable post-activation
//	       sidecar provenance), guarded by `state='creating' AND
//	       create_token=? AND created_at=?` — THE POINT OF NO RETURN. From
//	       this commit on the session is durably valid and Create returns it
//	       truthfully whatever happens next; the token sidecar is ONLY ever
//	       removed as a sidecar, never as a rollback of the active row.
//	PhaseR remove the token file, fsync the directory, then clear
//	       cleanup_token in a guarded transaction. Any failure here leaves
//	       durable provenance (cleanup_token + the authenticated .tok file)
//	       that startup reconciliation finishes; Create STILL returns the
//	       committed active session. The canonical payload is NEVER touched
//	       by this cleanup, so bytes accepted by a concurrent Append are
//	       safe by construction.
//	Pre-activation failures (Phases T/C/verify/Tx2) roll the creating row
//	back (tombstone → remove attributable files → delete row) and return a
//	data-free dependency error, and NEVER leave a durable active row.
//
// Crash points are therefore all attributable and recoverable: no durable
// `active` row can exist whose canonical file is not already empty,
// token-free, and fsynced; every interrupted create converges either to a
// tombstoned (deleting) row that a later run finishes, to live creating
// residue that only its creator (holding the lease) may activate, or — after
// the point of no return — to a committed active session with a pending
// sidecar cleanup that startup finishes. Startup re-reads the current row
// state/token/lease inside the serialized decision and never acts on a stale
// snapshot, so a row concurrently activated and truncated by its creator is
// never rejected.
func (s *service) Create(ctx context.Context, repo, actor string, ttl time.Duration) (Session, error) {
	if err := validateRepo(repo); err != nil {
		return Session{}, err
	}
	if err := validateActor(actor); err != nil {
		return Session{}, err
	}
	if ttl <= 0 {
		return Session{}, ErrInvalidInput
	}
	createdNanos := s.now().UTC().UnixNano()
	ttlNanos := ttl.Nanoseconds()
	if ttlNanos <= 0 || ttlNanos > math.MaxInt64-createdNanos {
		return Session{}, ErrInvalidInput
	}
	expiresNanos := createdNanos + ttlNanos

	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return Session{}, typed(ErrDependency, err)
	}
	id := hex.EncodeToString(raw[:])

	var tokenRaw [creatingTokenLen]byte
	if _, err := rand.Read(tokenRaw[:]); err != nil {
		return Session{}, typed(ErrDependency, err)
	}
	token := hex.EncodeToString(tokenRaw[:])

	// Transaction 1: the durable creating row carrying the unforgeable
	// token and lease anchor. Committed BEFORE any file byte exists.
	if err := s.withTx(ctx, func(conn *sql.Conn) error {
		if _, err := conn.ExecContext(ctx,
			`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at, create_token)
			 values (?, ?, ?, 'creating', 0, ?, ?, ?)`,
			id, repo, actor, createdNanos, expiresNanos, token); err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			return typed(ErrDependency, err)
		}
		return nil
	}); err != nil {
		return Session{}, err
	}

	// Phase T: the attribution token file — durable before the canonical
	// file or any activation can exist.
	tf, err := s.spool.createTok(id)
	if err != nil {
		_ = s.rollbackCreate(ctx, id, token)
		return Session{}, typed(ErrDependency, err)
	}
	if _, werr := tf.Write(tokenRaw[:]); werr != nil {
		_ = tf.Close()
		_ = s.rollbackCreate(ctx, id, token)
		return Session{}, typed(ErrDependency, werr)
	}
	serr := s.syncFile(tf)
	cerr := tf.Close()
	if serr == nil {
		serr = cerr
	}
	if serr != nil {
		_ = s.rollbackCreate(ctx, id, token)
		return Session{}, typed(ErrDependency, serr)
	}
	if err := s.syncDir(); err != nil {
		_ = s.rollbackCreate(ctx, id, token)
		return Session{}, typed(ErrDependency, err)
	}

	// Phase C: the canonical payload file — EMPTY upload bytes from offset 0,
	// durable before activation. The token never enters this file.
	cf, err := s.spool.create(id)
	if err != nil {
		_ = s.rollbackCreate(ctx, id, token)
		return Session{}, typed(ErrDependency, err)
	}
	serr = s.syncFile(cf)
	cerr = cf.Close()
	if serr == nil {
		serr = cerr
	}
	if serr != nil {
		_ = s.rollbackCreate(ctx, id, token)
		return Session{}, typed(ErrDependency, serr)
	}
	if err := s.syncDir(); err != nil {
		_ = s.rollbackCreate(ctx, id, token)
		return Session{}, typed(ErrDependency, err)
	}

	// The token file must still carry exactly our token before activation
	// is even attempted; anything else is a fail-closed dependency error.
	if err := s.verifyCreatingTok(ctx, id, token); err != nil {
		_ = s.rollbackCreate(ctx, id, token)
		return Session{}, err
	}

	if s.createBarrier != nil {
		s.createBarrier()
	}

	// Activate: creating -> active, guarded by token and lease anchor so
	// only this creator can activate this exact row. The canonical file is
	// already empty, token-free, and durable, so the moment this commits
	// the session is a fully valid active session. The create token is
	// atomically cleared and moved into cleanup_token — THE POINT OF NO
	// RETURN: every later failure leaves the committed session intact and
	// only ever defers sidecar cleanup.
	activated := false
	err = s.withTx(ctx, func(conn *sql.Conn) error {
		res, err := conn.ExecContext(ctx,
			`update upload_sessions set state = 'active', create_token = null, cleanup_token = ?
			 where id = ? and state = 'creating' and create_token = ? and created_at = ?`,
			token, id, token, createdNanos)
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			return typed(ErrDependency, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return typed(ErrDependency, err)
		}
		activated = n == 1
		return nil
	})
	if err != nil || !activated {
		_ = s.rollbackCreate(ctx, id, token)
		if err == nil {
			err = typed(ErrDependency, errors.New("staging create activation lost its row"))
		}
		return Session{}, err
	}

	if s.postActivateHook != nil {
		s.postActivateHook()
	}

	// Phase R: token-sidecar removal — the FINAL token-clearing step, itself
	// durable (directory fsync), followed by clearing the cleanup provenance
	// in a guarded transaction. This is pure sidecar maintenance: the
	// canonical payload is never touched. Any failure leaves the durable
	// provenance (cleanup_token + the authenticated .tok file) for startup
	// reconciliation, and Create STILL returns the committed active session
	// — a committed activation is never reported as failed solely because
	// post-commit cleanup could not finish.
	rctx := context.WithoutCancel(ctx)
	if err := s.removeTokDurable(id); err == nil {
		_ = s.clearCleanupToken(rctx, id, token)
	}
	return Session{
		ID:        id,
		Repo:      repo,
		Actor:     actor,
		State:     StateActive,
		CreatedAt: time.Unix(0, createdNanos).UTC(),
		ExpiresAt: time.Unix(0, expiresNanos).UTC(),
	}, nil
}

// verifyCreatingTok reads exactly the token lobe of the creating session's
// TOKEN FILE and compares it constant-time with the row token. Any mismatch
// or absence is a fail-closed dependency error; the file is never touched.
func (s *service) verifyCreatingTok(ctx context.Context, id, tokenHex string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	want, err := hex.DecodeString(tokenHex)
	if err != nil {
		return typed(ErrDependency, err)
	}
	got, err := s.spool.readTokExact(id, creatingTokenLen)
	if err != nil {
		return typed(ErrDependency, err)
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return typed(ErrDependency, errors.New("creating session token file does not carry its token"))
	}
	return nil
}

// removeTokDurable unlinks the creating session's token file and fsyncs the
// spool directory, so a completed create leaves no token bytes anywhere.
func (s *service) removeTokDurable(id string) error {
	if err := s.spool.removeTok(id); err != nil {
		return typed(ErrDependency, err)
	}
	if err := s.syncDir(); err != nil {
		return typed(ErrDependency, err)
	}
	return nil
}

// removeFiles unlinks BOTH files of a session (the canonical payload file
// and its token file) through the anchored descriptor, idempotent when
// either is absent. The caller must hold a durable tombstone for the row
// before calling (the row-id ownership proof); the containing directory is
// fsynced by the caller afterwards.
func (s *service) removeFiles(id string) error {
	if err := s.spool.remove(id); err != nil {
		return err
	}
	return s.spool.removeTok(id)
}

// rollbackCreate tears down a creating row and its attributable files
// (idempotent, safe when the row or files are already absent). The guarded
// tombstone update — `state='creating' AND create_token=?` — is the
// serialization point: a row concurrently activated by its creator (or
// tombstoned by another instance) is NOT touched, and no file is ever
// unlinked whose row this call did not tombstone. It runs its own
// transactions under a cancellation-proof context so a failed create always
// converges. It is also the startup rollback path for interrupted creates.
func (s *service) rollbackCreate(ctx context.Context, id, token string) error {
	rctx := context.WithoutCancel(ctx)
	proceed := false
	if err := s.withTx(rctx, func(conn *sql.Conn) error {
		res, err := conn.ExecContext(rctx,
			`update upload_sessions set state = 'deleting', create_token = null, cleanup_token = null
			 where id = ? and state = 'creating' and create_token = ?`, id, token)
		if err != nil {
			return typed(ErrDependency, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return typed(ErrDependency, err)
		}
		proceed = n == 1
		return nil
	}); err != nil {
		return err
	}
	if !proceed {
		// The row is not in creating state (already activated or already
		// tombstoned by another instance); never unlink files we do not own.
		return nil
	}
	if err := s.removeFiles(id); err != nil {
		return typed(ErrDependency, err)
	}
	if err := s.syncDir(); err != nil {
		return typed(ErrDependency, err)
	}
	_, err := s.deleteTombstonedRow(rctx, id)
	return err
}

// clearCleanupToken clears the durable post-activation sidecar provenance
// once the token sidecar is durably gone (or verified absent). The guarded
// update — `cleanup_token = ? AND state IN (active,finalized)` — makes it
// idempotent across instances and a no-op once another instance (or a
// tombstone) already resolved the row. It runs under a cancellation-proof
// context so a committed create always converges.
func (s *service) clearCleanupToken(ctx context.Context, id, token string) error {
	return s.withTx(ctx, func(conn *sql.Conn) error {
		if _, err := conn.ExecContext(ctx,
			`update upload_sessions set cleanup_token = null
			 where id = ? and cleanup_token = ? and state in ('active', 'finalized')`, id, token); err != nil {
			return typed(ErrDependency, err)
		}
		return nil
	})
}

// finishTokCleanup is the startup (and retry) path for a committed
// activation whose token-sidecar removal is still pending: it removes the
// sidecar ONLY when it provably carries exactly the row's cleanup token,
// fsyncs the directory, and clears the cleanup provenance. A sidecar that
// is absent is treated as already removed (the metadata is cleared); a
// sidecar carrying foreign or empty bytes is NEVER removed, the provenance
// is retained, and the startup fails closed with the foreign leaf untouched.
func (s *service) finishTokCleanup(ctx context.Context, id, token string) error {
	if token == "" {
		// No provenance at all: nothing is authenticated to remove, and a
		// leftover <id>.tok is benign residue (Phase C tolerates it). The
		// row itself is already clean.
		return nil
	}
	_, exists, err := s.spool.tokInfo(id)
	if err != nil {
		return typed(ErrDependency, err)
	}
	if !exists {
		// The sidecar is already gone (its unlink succeeded before the
		// directory sync faulted, or another instance removed it): clear the
		// durable provenance.
		return s.clearCleanupToken(ctx, id, token)
	}
	if err := s.verifyCreatingTok(ctx, id, token); err != nil {
		// The sidecar does not carry OUR token: foreign/empty residue is
		// NEVER removed and the provenance is retained (fail closed,
		// untouched).
		return err
	}
	if err := s.removeTokDurable(id); err != nil {
		return err
	}
	return s.clearCleanupToken(ctx, id, token)
}

// deleteTombstonedRow removes the metadata row of a deleting tombstone and
// reports whether THIS call performed the removal (the single deletion
// winner among concurrent instances).
func (s *service) deleteTombstonedRow(ctx context.Context, id string) (bool, error) {
	removed := false
	err := s.withTx(ctx, func(conn *sql.Conn) error {
		res, err := conn.ExecContext(ctx,
			`delete from upload_sessions where id = ? and state = 'deleting'`, id)
		if err != nil {
			return typed(ErrDependency, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return typed(ErrDependency, err)
		}
		removed = n == 1
		return nil
	})
	return removed, err
}

// syncFile fsyncs a spool file (hookable for fault injection).
func (s *service) syncFile(f *os.File) error {
	if s.fsyncHook != nil {
		return s.fsyncHook()
	}
	return f.Sync()
}

// syncDir fsyncs the spool root directory (hookable for fault injection).
func (s *service) syncDir() error {
	if s.dirSyncHook != nil {
		return s.dirSyncHook()
	}
	return s.spool.syncDir()
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

func (s *service) Status(ctx context.Context, id, repo, actor string) (Session, error) {
	if err := validateID(id); err != nil {
		return Session{}, err
	}
	if err := validateRepo(repo); err != nil {
		return Session{}, err
	}
	if err := validateActor(actor); err != nil {
		return Session{}, err
	}
	conn, err := s.pool.acquire(ctx)
	if err != nil {
		return Session{}, err
	}
	defer s.pool.release(conn)
	row, found, err := fetchSession(ctx, conn, id)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return Session{}, cerr
		}
		return Session{}, typed(ErrDependency, err)
	}
	if !found {
		return Session{}, ErrNotFound
	}
	if !ownsSession(row, repo, actor) {
		return Session{}, ErrNotFound
	}
	// A committed creating row is invisible: only its creator may activate
	// it and startup reconciliation may roll it back.
	if row.state == string(StateCreating) {
		return Session{}, ErrNotFound
	}
	if s.expiredNanos(row.expiresNanos) {
		return Session{}, ErrExpired
	}
	return buildSession(row), nil
}

// ---------------------------------------------------------------------------
// Append
// ---------------------------------------------------------------------------

func (s *service) Append(ctx context.Context, id, repo, actor string, expectedOffset int64, src io.Reader, maxBytes int64) (Session, error) {
	if err := validateID(id); err != nil {
		return Session{}, err
	}
	if err := validateRepo(repo); err != nil {
		return Session{}, err
	}
	if err := validateActor(actor); err != nil {
		return Session{}, err
	}
	if expectedOffset < 0 || maxBytes < 0 {
		return Session{}, ErrInvalidInput
	}
	if src == nil {
		return Session{}, ErrInvalidInput
	}

	var fd *os.File
	var oldOffset int64
	var result Session
	// Panic safety: a panicking source reader (or hook) unwinds through
	// withTx, which rolls the transaction back; here the same unwind must
	// close the append descriptor and truncate the uncommitted tail back to
	// the pre-append offset so neither an fd nor uncommitted bytes survive.
	defer func() {
		if r := recover(); r != nil {
			if fd != nil {
				_ = fd.Truncate(oldOffset)
				_ = s.syncFile(fd)
				_ = fd.Close()
			}
			panic(r)
		}
	}()
	err := s.withTx(ctx, func(conn *sql.Conn) error {
		row, found, err := fetchSession(ctx, conn, id)
		if err != nil {
			return err // exact context error or raw mapped below
		}
		if !found {
			return ErrNotFound
		}
		if !ownsSession(row, repo, actor) {
			return ErrNotFound
		}
		if row.state == string(StateCreating) {
			return ErrNotFound
		}
		if s.expiredNanos(row.expiresNanos) {
			return ErrExpired
		}
		if row.state != string(StateActive) {
			return ErrInvalidState
		}
		if row.offset != expectedOffset {
			return ErrOffsetMismatch
		}
		if maxBytes > math.MaxInt64-row.offset {
			// The resulting offset would overflow int64: reject before any
			// write.
			return ErrTooLarge
		}
		oldOffset = row.offset

		f, err := s.spool.openForAppend(id, oldOffset)
		if err != nil {
			return typed(ErrDependency, err)
		}
		fd = f

		n, overflowing, err := copyBounded(f, src, maxBytes)
		if err != nil {
			return typed(ErrSourceRead, err)
		}
		if overflowing {
			return ErrTooLarge
		}
		if err := s.syncFile(f); err != nil {
			return typed(ErrDependency, err)
		}
		if s.dbWriteHook != nil {
			if err := s.dbWriteHook(); err != nil {
				return typed(ErrDependency, err)
			}
		}
		newOffset := oldOffset + n
		res, err := conn.ExecContext(ctx,
			`update upload_sessions set offset = ? where id = ?`, newOffset, id)
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			return typed(ErrDependency, err)
		}
		if affected, err := res.RowsAffected(); err != nil || affected != 1 {
			return typed(ErrDependency, errors.New("staging offset update affected no row"))
		}
		sess := buildSession(row)
		sess.Offset = newOffset
		result = sess
		return nil
	})
	if fd != nil {
		// Any failure after bytes were written (source error, overflow,
		// fsync, update, or commit) must leave the file exactly at the
		// committed offset: a partial append is never accepted. The rollback
		// truncate is itself made durable and a sync failure propagates, so
		// the tail cannot reappear after an acknowledged failure.
		if err != nil {
			if terr := fd.Truncate(oldOffset); terr != nil {
				err = typed(ErrDependency, terr)
			} else if serr := s.syncFile(fd); serr != nil {
				err = typed(ErrDependency, serr)
			}
		}
		_ = fd.Close()
	}
	if err != nil {
		return Session{}, err
	}
	return result, nil
}

// copyBounded streams src into dst with a fixed-size buffer, reading at most
// maxBytes+1 bytes from src without arithmetic overflow: exactly maxBytes
// bytes are copied through an io.LimitedReader, then a single probe read
// detects the (maxBytes+1)-th byte. Bounded memory by construction.
func copyBounded(dst io.Writer, src io.Reader, maxBytes int64) (written int64, overflowing bool, err error) {
	lr := &io.LimitedReader{R: src, N: maxBytes}
	var buf [copyBufSize]byte
	n, err := io.CopyBuffer(dst, lr, buf[:])
	if err != nil {
		return n, false, err
	}
	var one [1]byte
	m, perr := src.Read(one[:])
	if perr == nil && m > 0 {
		return n, true, nil
	}
	if perr != nil && !errors.Is(perr, io.EOF) {
		return n, false, perr
	}
	return n, false, nil
}

// ---------------------------------------------------------------------------
// Open
// ---------------------------------------------------------------------------

type fileReadCloser struct {
	f *os.File
	r io.Reader
}

func (c *fileReadCloser) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *fileReadCloser) Close() error { return c.f.Close() }

func (s *service) Open(ctx context.Context, id, repo, actor string) (io.ReadCloser, Session, error) {
	if err := validateID(id); err != nil {
		return nil, Session{}, err
	}
	if err := validateRepo(repo); err != nil {
		return nil, Session{}, err
	}
	if err := validateActor(actor); err != nil {
		return nil, Session{}, err
	}

	var rc io.ReadCloser
	var sess Session
	err := s.withTx(ctx, func(conn *sql.Conn) error {
		row, found, err := fetchSession(ctx, conn, id)
		if err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		if !ownsSession(row, repo, actor) {
			return ErrNotFound
		}
		if row.state == string(StateCreating) {
			return ErrNotFound
		}
		if s.expiredNanos(row.expiresNanos) {
			return ErrExpired
		}
		if row.state != string(StateActive) && row.state != string(StateFinalized) {
			return ErrInvalidState
		}
		f, err := s.spool.openForRead(id, row.offset)
		if err != nil {
			return typed(ErrDependency, err)
		}
		// The reader is size-limited to the committed offset so a concurrent
		// append can never leak uncommitted bytes through an open handle.
		rc = &fileReadCloser{f: f, r: io.LimitReader(f, row.offset)}
		sess = buildSession(row)
		return nil
	})
	if err != nil {
		if rc != nil {
			rc.Close()
		}
		return nil, Session{}, err
	}
	return rc, sess, nil
}

// ---------------------------------------------------------------------------
// MarkFinalized
// ---------------------------------------------------------------------------

func (s *service) MarkFinalized(ctx context.Context, id, repo, actor, digest, beeRef, mediaType string, size int64) error {
	if err := validateID(id); err != nil {
		return err
	}
	if err := validateRepo(repo); err != nil {
		return err
	}
	if err := validateActor(actor); err != nil {
		return err
	}
	if err := validateDigest(digest); err != nil {
		return err
	}
	if err := validateBeeRef(beeRef); err != nil {
		return err
	}
	if err := validateMediaType(mediaType); err != nil {
		return err
	}
	if size < 0 {
		return ErrInvalidInput
	}

	return s.withTx(ctx, func(conn *sql.Conn) error {
		row, found, err := fetchSession(ctx, conn, id)
		if err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		if !ownsSession(row, repo, actor) {
			return ErrNotFound
		}
		if row.state == string(StateCreating) {
			return ErrNotFound
		}
		if s.expiredNanos(row.expiresNanos) {
			return ErrExpired
		}
		switch row.state {
		case string(StateDeleting):
			return ErrInvalidState
		case string(StateFinalized):
			// Idempotent only for byte-identical metadata.
			if row.digest.Valid && row.digest.String == digest &&
				row.beeRef.String == beeRef && row.mediaType.String == mediaType &&
				row.size.Int64 == size {
				return nil
			}
			return ErrFinalizeConflict
		case string(StateActive):
			// Exact committed size.
			if size != row.offset {
				return ErrInvalidInput
			}
			// The file must still be present and aligned; finalization never
			// modifies its bytes.
			if err := s.spool.align(id, row.offset); err != nil {
				return typed(ErrDependency, err)
			}
			if _, err := conn.ExecContext(ctx,
				`insert into staged_blobs (upload_id, repo, actor, digest, bee_ref, size, media_type, created_at, expires_at)
				 values (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				id, row.repo, row.actor, digest, beeRef, size, mediaType, row.createdNanos, row.expiresNanos); err != nil {
				if cerr := ctx.Err(); cerr != nil {
					return cerr
				}
				return typed(ErrDependency, err)
			}
			if _, err := conn.ExecContext(ctx,
				`update upload_sessions set state = 'finalized', digest = ?, bee_ref = ?, media_type = ?, size = ? where id = ?`,
				digest, beeRef, mediaType, size, id); err != nil {
				if cerr := ctx.Err(); cerr != nil {
					return cerr
				}
				return typed(ErrDependency, err)
			}
			return nil
		default:
			return ErrInvalidState
		}
	})
}

// ---------------------------------------------------------------------------
// ListFinalized
// ---------------------------------------------------------------------------

func (s *service) ListFinalized(ctx context.Context, repo, actor string) ([]spec.StagedBlob, error) {
	if err := validateRepo(repo); err != nil {
		return nil, err
	}
	if err := validateActor(actor); err != nil {
		return nil, err
	}
	conn, err := s.pool.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer s.pool.release(conn)
	rows, err := conn.QueryContext(ctx,
		`select upload_id, repo, actor, digest, bee_ref, size, media_type, created_at, expires_at
		 from staged_blobs where repo = ? and actor = ? order by created_at, upload_id`, repo, actor)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		return nil, typed(ErrDependency, err)
	}
	defer rows.Close()
	blobs := []spec.StagedBlob{}
	for rows.Next() {
		var b spec.StagedBlob
		var created, expires int64
		if err := rows.Scan(&b.UploadID, &b.Repo, &b.Actor, &b.Digest, &b.SwarmRef, &b.Size, &b.MediaType, &created, &expires); err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return nil, cerr
			}
			return nil, typed(ErrDependency, err)
		}
		b.CreatedAt = time.Unix(0, created).UTC().Format(time.RFC3339)
		b.ExpiresAt = time.Unix(0, expires).UTC().Format(time.RFC3339)
		blobs = append(blobs, b)
	}
	if err := rows.Err(); err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		return nil, typed(ErrDependency, err)
	}
	return blobs, nil
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// Delete removes a session with the same tombstone state machine as Expire:
// a durable deleting row is committed first, the file is unlinked and the
// directory fsynced OUTSIDE any transaction, and only then is the metadata
// row removed. A failed unlink retains the tombstone; the caller's retry —
// or startup reconciliation — finishes the deletion. Delete is idempotent:
// an absent id returns nil WITHOUT touching anything, and a row owned by a
// different tenant returns identically nil — the API is never an existence
// oracle for foreign sessions.
func (s *service) Delete(ctx context.Context, id, repo, actor string) error {
	if err := validateID(id); err != nil {
		return err
	}
	if err := validateRepo(repo); err != nil {
		return err
	}
	if err := validateActor(actor); err != nil {
		return err
	}

	// Tx 1: durable tombstone.
	proceed := false
	err := s.withTx(ctx, func(conn *sql.Conn) error {
		row, found, err := fetchSession(ctx, conn, id)
		if err != nil {
			return err
		}
		if !found {
			return nil // idempotent: nothing to delete; same public result as a foreign row
		}
		if !ownsSession(row, repo, actor) {
			// Confidential: a wrong-owner id is indistinguishable from an
			// absent id — the foreign row is NEVER touched and the result is
			// identically nil.
			return nil
		}
		proceed = true
		if row.state == string(StateDeleting) {
			return nil // tombstone already durable
		}
		res, err := conn.ExecContext(ctx,
			`update upload_sessions set state = 'deleting', create_token = null, cleanup_token = null where id = ? and state <> 'deleting'`, id)
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			return typed(ErrDependency, err)
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return typed(ErrDependency, errors.New("staging tombstone update affected no row"))
		}
		return nil
	})
	if err != nil {
		return err
	}
	if !proceed {
		return nil
	}

	// Unlink + directory fsync OUTSIDE any transaction (a rollback must
	// never revive rows whose files are gone). Both the canonical payload
	// file and the session's token file (residue of an interrupted create)
	// are removed through the anchored descriptor.
	if err := s.removeFiles(id); err != nil {
		return typed(ErrDependency, err)
	}
	if err := s.syncDir(); err != nil {
		return typed(ErrDependency, err)
	}

	// Tx 2: metadata removal — only now is the file durably gone.
	_, err = s.deleteTombstonedRow(ctx, id)
	return err
}

// ---------------------------------------------------------------------------
// Expire
// ---------------------------------------------------------------------------

// Expire removes expired sessions in deterministic (expires_at, id) order,
// limited to limit rows. For each row the same tombstone state machine as
// Delete runs; the returned count is the number of FULLY completed
// deletions (tombstone + durable unlink + metadata removal) performed by
// THIS instance: the final DELETE's RowsAffected decides, so across any
// number of concurrent expirers the aggregate count for one logical row is
// exactly 1. A failure at any phase stops the run with an ErrDependency and
// leaves a coherent state: the row either still active or durably
// tombstoned, never missing its file.
func (s *service) Expire(ctx context.Context, now time.Time, limit int) (int, error) {
	if limit <= 0 {
		return 0, ErrInvalidInput
	}
	nowNanos := now.UTC().UnixNano()

	ids, err := s.expiredIDs(ctx, nowNanos, limit)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return count, err
		}
		done, err := s.expireOne(ctx, id)
		if err != nil {
			return count, err
		}
		if done {
			count++
		}
	}
	return count, nil
}

// expiredIDs lists the limit oldest-expiring row ids whose expiry has
// passed, in deterministic order.
func (s *service) expiredIDs(ctx context.Context, nowNanos int64, limit int) ([]string, error) {
	conn, err := s.pool.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer s.pool.release(conn)
	rows, err := conn.QueryContext(ctx,
		`select id from upload_sessions where expires_at <= ? order by expires_at, id limit ?`, nowNanos, limit)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		return nil, typed(ErrDependency, err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return nil, ctx.Err()
		}
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, typed(ErrDependency, err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		return nil, typed(ErrDependency, err)
	}
	return ids, nil
}

// expireOne deletes one expired row with the crash-safe tombstone protocol.
// It reports whether THIS call performed the final metadata removal.
func (s *service) expireOne(ctx context.Context, id string) (bool, error) {
	// Tx 1: durable tombstone — committed before any unlink. A row that
	// vanished (another instance) is skipped; a row already tombstoned
	// proceeds to the unlink phase.
	proceed := false
	err := s.withTx(ctx, func(conn *sql.Conn) error {
		row, found, err := fetchSession(ctx, conn, id)
		if err != nil {
			return err
		}
		if !found {
			return nil
		}
		proceed = true
		if row.state == string(StateDeleting) {
			return nil
		}
		res, err := conn.ExecContext(ctx,
			`update upload_sessions set state = 'deleting', create_token = null, cleanup_token = null where id = ? and state <> 'deleting'`, id)
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			return typed(ErrDependency, err)
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return typed(ErrDependency, errors.New("staging tombstone update affected no row"))
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	if !proceed {
		return false, nil
	}

	// Unlink + directory fsync OUTSIDE any transaction. On failure the
	// tombstone stays durable for the retry. Both the canonical payload file
	// and the session's token file are removed.
	if err := s.removeFiles(id); err != nil {
		return false, typed(ErrDependency, err)
	}
	if err := s.syncDir(); err != nil {
		return false, typed(ErrDependency, err)
	}

	// Tx 2: metadata removal — only now is the file durably gone. The
	// RowsAffected decides completion: exactly one instance's DELETE may
	// remove the row, so concurrent expirers sum to one completion per row.
	return s.deleteTombstonedRow(ctx, id)
}

// ---------------------------------------------------------------------------
// Startup reconciliation
// ---------------------------------------------------------------------------

// reconcileStartup converges the spool and the database after a crash:
//
//   - Phase A takes a durable-consistent snapshot of every row (one
//     read-only transaction). A test hook fires here so barrier tests can
//     interleave a concurrently-activating creator.
//   - Phase B repairs each row WITHOUT any unlink inside a transaction,
//     re-reading the CURRENT row state/token/lease inside the serialized
//     decision — a stale snapshot is NEVER used to reject a row that a
//     live creator concurrently activated and truncated. deleting rows are
//     finished (durable unlink of both files, then metadata removal); stale
//     creating rows are rolled back ONLY when attributable through their
//     unforgeable TOKEN FILE (<id>.tok): no files -> row removed; matching
//     token file -> row AND its attributable token/canonical files removed;
//     a canonical file with no token file, or a token file carrying foreign
//     bytes, is unknown residue and fails closed with every file UNTOUCHED —
//     attacker-planted empty/wrong-token canonical files are never adopted
//     or deleted; live creating leases are left strictly alone; active/
//     finalized rows (including rows just activated by their creator) are
//     aligned to the committed offset (crash tails truncated, short files
//     fail closed); unknown states fail closed.
//   - Phase C re-queries the database FRESH (not the Phase A snapshot) and
//     demands exact attribution of every spool entry against it: any entry
//     with no database row makes startup fail closed with its file UNTOUCHED
//     — a foreign or unowned file is never swept. A leftover <id>.tok whose
//     base id HAS a live row is benign interrupted-create residue: it is
//     never adopted (it is not a canonical file) and never deleted (its
//     token was already cleared from the row).
func (s *service) reconcileStartup(ctx context.Context) error {
	var rows []rowInfo
	// Phase A: durable-consistent snapshot.
	err := s.withTx(ctx, func(conn *sql.Conn) error {
		r, err := conn.QueryContext(ctx, `select id, state, offset, created_at, create_token, cleanup_token from upload_sessions`)
		if err != nil {
			return typed(ErrDependency, err)
		}
		defer r.Close()
		for r.Next() {
			if err := ctx.Err(); err != nil {
				return ctx.Err()
			}
			var ri rowInfo
			var tok, cleanup sql.NullString
			if err := r.Scan(&ri.id, &ri.state, &ri.offset, &ri.createdNanos, &tok, &cleanup); err != nil {
				if cerr := ctx.Err(); cerr != nil {
					return cerr
				}
				return typed(ErrDependency, err)
			}
			ri.token = tok.String
			ri.cleanupToken = cleanup.String
			rows = append(rows, ri)
		}
		if err := r.Err(); err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			return typed(ErrDependency, err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if reconcileSnapshotHook != nil {
		reconcileSnapshotHook()
	}

	// Phase B: per-row repair.
	for _, ri := range rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		switch State(ri.state) {
		case StateDeleting:
			if err := s.removeFiles(ri.id); err != nil {
				return typed(ErrDependency, err)
			}
			if err := s.syncDir(); err != nil {
				return typed(ErrDependency, err)
			}
			if _, err := s.deleteTombstonedRow(ctx, ri.id); err != nil {
				return err
			}
		case StateCreating:
			if err := s.reconcileCreatingRow(ctx, ri); err != nil {
				return err
			}
		case StateActive, StateFinalized:
			if err := s.spool.align(ri.id, ri.offset); err != nil {
				return typed(ErrDependency, err)
			}
			// A committed activation with a pending sidecar cleanup carries
			// the authenticated cleanup token: finish the cleanup now
			// (verify the sidecar, remove it durably, clear the metadata).
			if ri.cleanupToken != "" {
				if err := s.finishTokCleanup(ctx, ri.id, ri.cleanupToken); err != nil {
					return err
				}
			}
		default:
			return typed(ErrDependency, errors.New("unknown session state"))
		}
	}

	// Phase C: exact attribution against FRESH database state (a Create
	// committed while Phase B ran is visible here, not in the snapshot). An
	// entry with no database row means an interrupted pre-row create or a
	// foreign file: either way it is preserved untouched and startup fails
	// closed.
	names, err := s.spool.entries()
	if err != nil {
		return typed(ErrDependency, err)
	}
	dbIDs := make(map[string]bool, len(names))
	err = s.withTx(ctx, func(conn *sql.Conn) error {
		r, err := conn.QueryContext(ctx, `select id from upload_sessions`)
		if err != nil {
			return typed(ErrDependency, err)
		}
		defer r.Close()
		for r.Next() {
			if err := ctx.Err(); err != nil {
				return ctx.Err()
			}
			var id string
			if err := r.Scan(&id); err != nil {
				if cerr := ctx.Err(); cerr != nil {
					return cerr
				}
				return typed(ErrDependency, err)
			}
			dbIDs[id] = true
		}
		if err := r.Err(); err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			return typed(ErrDependency, err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, name := range names {
		if dbIDs[name] {
			continue
		}
		if base, ok := strings.CutSuffix(name, ".tok"); ok && dbIDs[base] {
			// Benign interrupted-create residue: the token file of a live
			// row. It is never adopted (only canonical names are payload),
			// never deleted (its token was cleared from the row and cannot
			// be re-verified), and never blocks startup.
			continue
		}
		return typed(ErrDependency, errors.New("unexpected file in spool"))
	}
	return nil
}

// rowInfo is a durable-consistent snapshot row: the create-time row
// fields needed to decide a creating row's fate at startup, plus the
// post-activation sidecar cleanup provenance.
type rowInfo struct {
	id           string
	state        string
	offset       int64
	createdNanos int64
	token        string
	cleanupToken string
}

// reconcileCreatingRow decides the fate of a creating row WITHOUT trusting
// the Phase A snapshot: it re-reads the current row state, token, and lease
// inside a serialized transaction, then acts conditionally on THAT state.
// A row concurrently activated and truncated by its creator is therefore
// aligned like any active row instead of being rejected through a stale
// snapshot. Attribution of the create attempt comes from the row's token
// FILE — a stale creating row is rolled back only when that file carries
// exactly the row token; a canonical file without a token file, or a token
// file with foreign bytes, fails closed untouched.
func (s *service) reconcileCreatingRow(ctx context.Context, ri rowInfo) error {
	if ri.offset != 0 {
		return typed(ErrDependency, errors.New("creating session has a nonzero offset"))
	}
	// Re-read the CURRENT row inside the serialized decision.
	var curState, curTok, curCleanup string
	var curCreated int64
	found := false
	err := s.withTx(ctx, func(conn *sql.Conn) error {
		row, f, err := fetchSession(ctx, conn, ri.id)
		if err != nil {
			return err
		}
		if f {
			found = true
			curState = row.state
			curTok = row.createToken.String
			curCleanup = row.cleanupToken.String
			curCreated = row.createdNanos
		}
		return nil
	})
	if err != nil {
		return err
	}
	if !found {
		// The row vanished (another instance finished or rolled it back).
		return nil
	}
	switch State(curState) {
	case StateActive, StateFinalized:
		// The creator won: the row is already active/finalized with its
		// canonical file empty/token-free. Align (crash-tail truncation is
		// idempotent) and finish any pending sidecar cleanup — never reject
		// through the stale snapshot.
		if err := s.spool.align(ri.id, ri.offset); err != nil {
			return typed(ErrDependency, err)
		}
		if curCleanup != "" {
			return s.finishTokCleanup(ctx, ri.id, curCleanup)
		}
		return nil
	case StateDeleting:
		// Another instance already tombstoned the interrupted create;
		// finish the deletion (remove both files, then the row).
		if err := s.removeFiles(ri.id); err != nil {
			return typed(ErrDependency, err)
		}
		if err := s.syncDir(); err != nil {
			return typed(ErrDependency, err)
		}
		_, err := s.deleteTombstonedRow(ctx, ri.id)
		return err
	case StateCreating:
		// Still creating: decide with the CURRENT token and lease.
		if !s.creatingLeaseStale(curCreated) {
			// Live lease: the creator is still between row commit and
			// activation; leave it (and its files) strictly alone.
			return nil
		}
		tokFi, tokExists, err := s.spool.tokInfo(ri.id)
		if err != nil {
			return typed(ErrDependency, err)
		}
		_ = tokFi
		if !tokExists {
			// No token file: our create never durably wrote its attribution
			// anchor. A canonical file without a token file is never OURS
			// (the protocol always writes the token file first and keeps it
			// until after activation) — it is attacker-planted or foreign
			// residue and fails closed UNTOUCHED.
			if _, cexists, cerr := s.spool.nameInfo(ri.id); cerr != nil {
				return typed(ErrDependency, cerr)
			} else if cexists {
				return typed(ErrDependency, errors.New("creating session has an unattributable canonical file"))
			}
			// No files at all: roll the row back.
			return s.rollbackCreate(ctx, ri.id, curTok)
		}
		if err := s.verifyCreatingTok(ctx, ri.id, curTok); err != nil {
			// The token file carries foreign bytes: unknown residue. Never
			// adopt it, never delete it.
			return err
		}
		// Stale AND attributable: roll the row back and remove its
		// attributable token + canonical files (the canonical file was
		// created with O_EXCL by this same create — the unforgeable id plus
		// a verified token file prove ownership). Never adopt.
		return s.rollbackCreate(ctx, ri.id, curTok)
	default:
		return typed(ErrDependency, errors.New("unknown session state"))
	}
}
