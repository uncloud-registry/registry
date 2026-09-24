package staging

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"os"
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
// on startup and before every subsequent access. A file shorter than the
// committed offset is fail-closed corruption.
//
// Filesystem deletion protocol: a durable `deleting` tombstone is committed
// BEFORE any unlink; the unlink and the containing-directory fsync happen
// OUTSIDE any transaction (a transaction could roll back and strand live
// rows with removed files); the metadata row is removed only after the file
// is durably gone. Any failure retains the tombstone for a later run, so a
// restart is always exact.
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

// service is the concrete durable staging service.
type service struct {
	spool *spool
	db    *sql.DB
	now   func() time.Time

	// Test-only fault injection points (nil in production). They are set
	// before operations and never mutated concurrently.
	fsyncHook   func() error // replaces the spool-file fsync
	dirSyncHook func() error // replaces the spool-directory fsync
	dbWriteHook func() error // fires before the offset UPDATE
	commitHook  func() error // fires before COMMIT
}

// NewService constructs the durable staging service: it validates and
// creates the private spool root and the database parent (descriptor-
// relative, symlink-rejecting), opens and migrates the dedicated staging
// database after exact schema verification, and reconciles spool files
// against the committed database state (truncating crashed tails, finishing
// interrupted deletions, rolling back or finishing interrupted creates,
// failing closed on unowned files) before returning. Every constructor
// failure is a data-free ErrDependency; only an actually canceled context
// surfaces as the exact context error.
func NewService(ctx context.Context, spoolRoot, dbPath string) (*service, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sp, err := newSpool(ctx, spoolRoot)
	if err != nil {
		return nil, err
	}
	db, err := openStagingDB(ctx, dbPath, 4)
	if err != nil {
		sp.Close()
		return nil, err
	}
	svc := &service{spool: sp, db: db, now: time.Now}
	if err := svc.reconcileStartup(ctx); err != nil {
		sp.Close()
		db.Close()
		return nil, err
	}
	return svc, nil
}

// Close releases the database handle and the root descriptor.
func (s *service) Close() error {
	var errs []error
	if s.db != nil {
		errs = append(errs, s.db.Close())
		s.db = nil
	}
	if s.spool != nil {
		if err := s.spool.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ---------------------------------------------------------------------------
// BEGIN IMMEDIATE serialization
// ---------------------------------------------------------------------------

// withTx pins one connection, runs BEGIN IMMEDIATE (retried on BUSY/LOCKED
// with bounded context-aware backoff), executes fn on that connection, and
// COMMITs. Any failure rolls back; a busy failure mid-transaction retries the
// WHOLE read-decision-write body, never a single statement.
func (s *service) withTx(ctx context.Context, fn func(conn *sql.Conn) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		return typed(ErrDependency, err)
	}
	defer conn.Close()

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
			return typed(ErrDependency, err)
		}

		runErr := fn(conn)
		if runErr == nil && s.commitHook != nil {
			if hookErr := s.commitHook(); hookErr != nil {
				runErr = typed(ErrDependency, hookErr)
			}
		}
		committed := false
		if runErr == nil {
			if _, err := conn.ExecContext(ctx, "commit"); err != nil {
				runErr = typed(ErrDependency, err)
			} else {
				committed = true
			}
		}
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "rollback")
		}
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

// queryer abstracts *sql.DB and the pinned *sql.Conn used inside withTx.
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
}

const sessionColumns = `id, repo, actor, state, offset, created_at, expires_at, digest, bee_ref, media_type, size`

func fetchSession(ctx context.Context, q queryer, id string) (*sessionRow, bool, error) {
	var row sessionRow
	err := q.QueryRowContext(ctx,
		`select `+sessionColumns+` from upload_sessions where id = ?`, id).
		Scan(&row.id, &row.repo, &row.actor, &row.state, &row.offset,
			&row.createdNanos, &row.expiresNanos, &row.digest, &row.beeRef,
			&row.mediaType, &row.size)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
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

// Create commits a durable `creating` row FIRST (transaction 1), then
// creates the spool file and makes both the file bytes and the directory
// entry durable, and only then activates the session (transaction 2). A
// crash at ANY point is attributable: startup either finishes the create
// (row + durable empty file) or rolls it back (row without file). Any
// durability failure rolls the creating row back and removes the file, so a
// failed create leaves no residue.
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

	// Transaction 1: the durable creating tombstone-eligible row. Committed
	// BEFORE any file byte exists, so startup can finish or roll back only
	// rows it owns and never sweeps a file it cannot attribute.
	if err := s.withTx(ctx, func(conn *sql.Conn) error {
		if _, err := conn.ExecContext(ctx,
			`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at)
			 values (?, ?, ?, 'creating', 0, ?, ?)`,
			id, repo, actor, createdNanos, expiresNanos); err != nil {
			return typed(ErrDependency, err)
		}
		return nil
	}); err != nil {
		return Session{}, err
	}

	// Create the file and make the file and its directory entry durable
	// before the session becomes visible.
	f, err := s.spool.create(id)
	if err != nil {
		_ = s.rollbackCreate(ctx, id)
		return Session{}, typed(ErrDependency, err)
	}
	serr := s.syncFile(f)
	cerr := f.Close()
	if serr == nil {
		serr = cerr
	}
	if serr != nil {
		_ = s.rollbackCreate(ctx, id)
		return Session{}, typed(ErrDependency, serr)
	}
	if err := s.syncDir(); err != nil {
		_ = s.rollbackCreate(ctx, id)
		return Session{}, typed(ErrDependency, err)
	}

	// Activate: creating -> active.
	activated := false
	err = s.withTx(ctx, func(conn *sql.Conn) error {
		res, err := conn.ExecContext(ctx,
			`update upload_sessions set state = 'active' where id = ? and state = 'creating'`, id)
		if err != nil {
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
		_ = s.rollbackCreate(ctx, id)
		if err == nil {
			err = typed(ErrDependency, errors.New("staging create activation lost its row"))
		}
		return Session{}, err
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

// rollbackCreate tears down a creating row and its file (idempotent, safe
// when the row or file is already absent). It runs its own transactions —
// never inside a caller's transaction — under a cancellation-proof context so
// a failed create always converges. It is also the startup rollback path for
// interrupted creates whose file never became durable.
func (s *service) rollbackCreate(ctx context.Context, id string) error {
	rctx := context.WithoutCancel(ctx)
	proceed := false
	if err := s.withTx(rctx, func(conn *sql.Conn) error {
		res, err := conn.ExecContext(rctx,
			`update upload_sessions set state = 'deleting' where id = ? and state = 'creating'`, id)
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
		// tombstoned by another instance); never unlink a file we do not own.
		return nil
	}
	if err := s.spool.remove(id); err != nil {
		return typed(ErrDependency, err)
	}
	if err := s.syncDir(); err != nil {
		return typed(ErrDependency, err)
	}
	return s.deleteTombstonedRow(rctx, id)
}

// deleteTombstonedRow removes the metadata row of a deleting tombstone.
func (s *service) deleteTombstonedRow(ctx context.Context, id string) error {
	return s.withTx(ctx, func(conn *sql.Conn) error {
		if _, err := conn.ExecContext(ctx,
			`delete from upload_sessions where id = ? and state = 'deleting'`, id); err != nil {
			return typed(ErrDependency, err)
		}
		return nil
	})
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
	row, found, err := fetchSession(ctx, s.db, id)
	if err != nil {
		return Session{}, typed(ErrDependency, err)
	}
	if !found {
		return Session{}, ErrNotFound
	}
	if !ownsSession(row, repo, actor) {
		return Session{}, ErrNotFound
	}
	// A committed creating row is invisible: only startup reconciliation may
	// attribute it.
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
	err := s.withTx(ctx, func(conn *sql.Conn) error {
		row, found, err := fetchSession(ctx, conn, id)
		if err != nil {
			return typed(ErrDependency, err)
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
		// committed offset: a partial append is never accepted.
		if err != nil {
			_ = fd.Truncate(oldOffset)
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
			return typed(ErrDependency, err)
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
			return typed(ErrDependency, err)
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
				return typed(ErrDependency, err)
			}
			if _, err := conn.ExecContext(ctx,
				`update upload_sessions set state = 'finalized', digest = ?, bee_ref = ?, media_type = ?, size = ? where id = ?`,
				digest, beeRef, mediaType, size, id); err != nil {
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
	rows, err := s.db.QueryContext(ctx,
		`select upload_id, repo, actor, digest, bee_ref, size, media_type, created_at, expires_at
		 from staged_blobs where repo = ? and actor = ? order by created_at, upload_id`, repo, actor)
	if err != nil {
		return nil, typed(ErrDependency, err)
	}
	defer rows.Close()
	blobs := []spec.StagedBlob{}
	for rows.Next() {
		var b spec.StagedBlob
		var created, expires int64
		if err := rows.Scan(&b.UploadID, &b.Repo, &b.Actor, &b.Digest, &b.SwarmRef, &b.Size, &b.MediaType, &created, &expires); err != nil {
			return nil, typed(ErrDependency, err)
		}
		b.CreatedAt = time.Unix(0, created).UTC().Format(time.RFC3339)
		b.ExpiresAt = time.Unix(0, expires).UTC().Format(time.RFC3339)
		blobs = append(blobs, b)
	}
	if err := rows.Err(); err != nil {
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
// or startup reconciliation — finishes the deletion.
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
			return typed(ErrDependency, err)
		}
		if !found {
			return nil // idempotent: nothing to delete
		}
		if !ownsSession(row, repo, actor) {
			return ErrNotFound
		}
		proceed = true
		if row.state == string(StateDeleting) {
			return nil // tombstone already durable
		}
		res, err := conn.ExecContext(ctx,
			`update upload_sessions set state = 'deleting' where id = ? and state <> 'deleting'`, id)
		if err != nil {
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
	// never revive rows whose files are gone).
	if err := s.spool.remove(id); err != nil {
		return typed(ErrDependency, err)
	}
	if err := s.syncDir(); err != nil {
		return typed(ErrDependency, err)
	}

	// Tx 2: metadata removal — only now is the file durably gone.
	return s.deleteTombstonedRow(ctx, id)
}

// ---------------------------------------------------------------------------
// Expire
// ---------------------------------------------------------------------------

// Expire removes expired sessions in deterministic (expires_at, id) order,
// limited to limit rows. For each row the same tombstone state machine as
// Delete runs; the returned count is the number of FULLY completed
// deletions (tombstone + durable unlink + metadata removal). A failure at
// any phase stops the run with an ErrDependency and leaves a coherent
// state: the row either still active or durably tombstoned, never missing
// its file.
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
	rows, err := s.db.QueryContext(ctx,
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
		return nil, typed(ErrDependency, err)
	}
	return ids, nil
}

// expireOne deletes one expired row with the crash-safe tombstone protocol.
// It reports whether the deletion fully completed.
func (s *service) expireOne(ctx context.Context, id string) (bool, error) {
	// Tx 1: durable tombstone — committed before any unlink. A row that
	// vanished (another instance) is skipped; a row already tombstoned
	// proceeds to the unlink phase.
	proceed := false
	err := s.withTx(ctx, func(conn *sql.Conn) error {
		row, found, err := fetchSession(ctx, conn, id)
		if err != nil {
			return typed(ErrDependency, err)
		}
		if !found {
			return nil
		}
		proceed = true
		if row.state == string(StateDeleting) {
			return nil
		}
		res, err := conn.ExecContext(ctx,
			`update upload_sessions set state = 'deleting' where id = ? and state <> 'deleting'`, id)
		if err != nil {
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
	// tombstone stays durable for the retry.
	if err := s.spool.remove(id); err != nil {
		return false, typed(ErrDependency, err)
	}
	if err := s.syncDir(); err != nil {
		return false, typed(ErrDependency, err)
	}

	// Tx 2: metadata removal — only now is the file durably gone.
	if err := s.deleteTombstonedRow(ctx, id); err != nil {
		return false, err
	}
	return true, nil
}

// ---------------------------------------------------------------------------
// Startup reconciliation
// ---------------------------------------------------------------------------

// reconcileStartup converges the spool and the database after a crash:
//
//   - Phase A takes a durable-consistent snapshot of every row (one
//     read-only transaction).
//   - Phase B repairs each row WITHOUT any unlink inside a transaction:
//     deleting rows are finished (durable unlink, then metadata removal);
//     creating rows are finished (durable empty file -> active) or rolled
//     back (no file -> row removed); active/finalized rows are aligned to
//     the committed offset (crash tails truncated, short files fail closed);
//     unknown states fail closed.
//   - Phase C enumerates the spool THROUGH the anchored descriptor and
//     demands exact attribution: any entry with no database row makes
//     startup fail closed with its file UNTOUCHED — a foreign or unowned
//     file is never swept.
func (s *service) reconcileStartup(ctx context.Context) error {
	type rowInfo struct {
		id, state string
		offset    int64
	}
	var rows []rowInfo
	idset := map[string]bool{}
	// Phase A: durable-consistent snapshot.
	err := s.withTx(ctx, func(conn *sql.Conn) error {
		r, err := conn.QueryContext(ctx, `select id, state, offset from upload_sessions`)
		if err != nil {
			return typed(ErrDependency, err)
		}
		defer r.Close()
		for r.Next() {
			if err := ctx.Err(); err != nil {
				return ctx.Err()
			}
			var ri rowInfo
			if err := r.Scan(&ri.id, &ri.state, &ri.offset); err != nil {
				return typed(ErrDependency, err)
			}
			rows = append(rows, ri)
			idset[ri.id] = true
		}
		if err := r.Err(); err != nil {
			return typed(ErrDependency, err)
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Phase B: per-row repair.
	for _, ri := range rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		switch State(ri.state) {
		case StateDeleting:
			if err := s.spool.remove(ri.id); err != nil {
				return typed(ErrDependency, err)
			}
			if err := s.syncDir(); err != nil {
				return typed(ErrDependency, err)
			}
			if err := s.deleteTombstonedRow(ctx, ri.id); err != nil {
				return err
			}
		case StateCreating:
			if ri.offset != 0 {
				return typed(ErrDependency, errors.New("creating session has a nonzero offset"))
			}
			fi, err := s.spool.root.Lstat(ri.id)
			switch {
			case os.IsNotExist(err):
				// The file never became durable: roll the row back.
				if err := s.rollbackCreate(ctx, ri.id); err != nil {
					return err
				}
			case err != nil:
				return typed(ErrDependency, err)
			case fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular():
				return typed(ErrDependency, errors.New("creating session file is not a regular file"))
			case fi.Size() != 0:
				return typed(ErrDependency, errors.New("creating session file carries uncommitted bytes"))
			default:
				// Finish: make the (possibly pre-existing) entry durable,
				// then activate.
				if err := s.finishCreating(ctx, ri.id); err != nil {
					return err
				}
			}
		case StateActive, StateFinalized:
			if err := s.spool.align(ri.id, ri.offset); err != nil {
				return typed(ErrDependency, err)
			}
		default:
			return typed(ErrDependency, errors.New("unknown session state"))
		}
	}

	// Phase C: exact attribution. An entry with no database row means an
	// interrupted create that predates the creating row, or a foreign file:
	// either way it is preserved untouched and startup fails closed.
	names, err := s.spool.entries()
	if err != nil {
		return typed(ErrDependency, err)
	}
	for _, name := range names {
		if !idset[name] {
			return typed(ErrDependency, errors.New("unexpected file in spool"))
		}
	}
	return nil
}

// finishCreating makes the empty file of a creating row durably linked
// (file fsync + directory fsync) and activates the row. Idempotent across
// instances: a row another instance already activated is left alone.
func (s *service) finishCreating(ctx context.Context, id string) error {
	f, err := s.spool.openForAppend(id, 0)
	if err != nil {
		return typed(ErrDependency, err)
	}
	serr := s.syncFile(f)
	cerr := f.Close()
	if serr == nil {
		serr = cerr
	}
	if serr != nil {
		return typed(ErrDependency, serr)
	}
	if err := s.syncDir(); err != nil {
		return typed(ErrDependency, err)
	}
	activated := false
	err = s.withTx(ctx, func(conn *sql.Conn) error {
		res, err := conn.ExecContext(ctx,
			`update upload_sessions set state = 'active' where id = ? and state = 'creating'`, id)
		if err != nil {
			return typed(ErrDependency, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return typed(ErrDependency, err)
		}
		activated = n == 1
		return nil
	})
	if err != nil {
		return err
	}
	if !activated {
		return nil // another instance finished it
	}
	return nil
}
