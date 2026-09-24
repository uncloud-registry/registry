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
// (go 1.25 os.Root) and a dedicated SQLite metadata database. Every state
// transition that reads then writes (Append, Open, MarkFinalized, Delete,
// Expire, Create, startup reconciliation) is serialized across independent
// service instances with a real BEGIN IMMEDIATE transaction and bounded
// context-aware busy retry — never a process-local mutex.
//
// Append durability order: bounded streamed copy at the exact committed
// offset, fsync of the spool file, then the SQLite offset commit. The
// database offset never advances beyond durable file bytes; a crash between
// fsync and commit leaves a recoverable tail that reconciliation truncates
// on startup and before every subsequent access. A file shorter than the
// committed offset is fail-closed corruption.
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
	dbWriteHook func() error // fires before the offset UPDATE
	commitHook  func() error // fires before COMMIT
}

// NewService constructs the durable staging service: it validates and
// creates the private spool root and the database parent, opens and migrates
// the dedicated staging database, and reconciles spool files against the
// committed database offsets (truncating crashed tails, finishing
// interrupted deletions, sweeping orphan files) before returning.
func NewService(ctx context.Context, spoolRoot, dbPath string) (*service, error) {
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
	s := Session{
		ID:        row.id,
		Repo:      row.repo,
		Actor:     row.actor,
		State:     State(row.state),
		Offset:    row.offset,
		CreatedAt: time.Unix(0, row.createdNanos).UTC(),
		ExpiresAt: time.Unix(0, row.expiresNanos).UTC(),
	}
	if row.digest.Valid {
		s.Digest = row.digest.String
		s.BeeRef = row.beeRef.String
		s.MediaType = row.mediaType.String
		s.Size = row.size.Int64
	}
	return s
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

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

	// The spool file is created inside the BEGIN IMMEDIATE transaction, so no
	// other instance's reconciliation can observe a row without its file; a
	// crash before commit leaves at worst an empty orphan file that startup
	// reconciliation sweeps.
	err := s.withTx(ctx, func(conn *sql.Conn) error {
		if err := s.spool.create(id); err != nil {
			return typed(ErrDependency, err)
		}
		if _, err := conn.ExecContext(ctx,
			`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at)
			 values (?, ?, ?, 'active', 0, ?, ?)`,
			id, repo, actor, createdNanos, expiresNanos); err != nil {
			_ = s.spool.remove(id)
			return typed(ErrDependency, err)
		}
		return nil
	})
	if err != nil {
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
		return Session{}, ErrOwnerMismatch
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
			return ErrOwnerMismatch
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

func (s *service) syncFile(f *os.File) error {
	if s.fsyncHook != nil {
		return s.fsyncHook()
	}
	return f.Sync()
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
			return ErrOwnerMismatch
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
			return ErrOwnerMismatch
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

	// Tx 1: durable tombstone. The file is never removed before the deleting
	// state is committed, so an interrupted deletion is completed later and
	// never strands an unknown file.
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
			return ErrOwnerMismatch
		}
		proceed = true
		if row.state == string(StateDeleting) {
			return nil // tombstone already durable
		}
		if _, err := conn.ExecContext(ctx,
			`update upload_sessions set state = 'deleting' where id = ? and state <> 'deleting'`, id); err != nil {
			return typed(ErrDependency, err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if !proceed {
		return nil
	}

	// Unlink the spool file (idempotent when already absent), then remove the
	// durable metadata.
	if err := s.spool.remove(id); err != nil {
		return typed(ErrDependency, err)
	}
	return s.withTx(ctx, func(conn *sql.Conn) error {
		if _, err := conn.ExecContext(ctx,
			`delete from upload_sessions where id = ? and state = 'deleting'`, id); err != nil {
			return typed(ErrDependency, err)
		}
		return nil
	})
}

// ---------------------------------------------------------------------------
// Expire
// ---------------------------------------------------------------------------

func (s *service) Expire(ctx context.Context, now time.Time, limit int) (int, error) {
	if limit <= 0 {
		return 0, ErrInvalidInput
	}
	nowNanos := now.UTC().UnixNano()

	count := 0
	err := s.withTx(ctx, func(conn *sql.Conn) error {
		rows, err := conn.QueryContext(ctx,
			`select id from upload_sessions where expires_at <= ? order by expires_at, id limit ?`, nowNanos, limit)
		if err != nil {
			return typed(ErrDependency, err)
		}
		var ids []string
		for rows.Next() {
			if err := ctx.Err(); err != nil {
				rows.Close()
				return ctx.Err()
			}
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return typed(ErrDependency, err)
			}
			ids = append(ids, id)
		}
		rows.Close()
		for _, id := range ids {
			if err := ctx.Err(); err != nil {
				return ctx.Err()
			}
			if err := s.expireOne(ctx, conn, id); err != nil {
				return err
			}
			count++
		}
		return nil
	})
	return count, err
}

// expireOne tombstones, unlinks, and deletes one expired row inside the
// caller's transaction. Expired rows are never legible to callers, so a
// crash mid-batch leaves at worst an expired row without its file — removed
// by the next sweep — and never an unknown file.
func (s *service) expireOne(ctx context.Context, conn *sql.Conn, id string) error {
	if _, err := conn.ExecContext(ctx,
		`update upload_sessions set state = 'deleting' where id = ? and state <> 'deleting'`, id); err != nil {
		return typed(ErrDependency, err)
	}
	// Never follow symlinks during cleanup: os.Root.Remove unlinks the entry.
	if err := s.spool.remove(id); err != nil {
		return typed(ErrDependency, err)
	}
	if _, err := conn.ExecContext(ctx,
		`delete from upload_sessions where id = ? and state = 'deleting'`, id); err != nil {
		return typed(ErrDependency, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Startup reconciliation
// ---------------------------------------------------------------------------

// reconcileStartup runs under BEGIN IMMEDIATE: active/finalized files are
// aligned to the committed offset (crash tails truncated, short files fail
// closed), interrupted deletions are finished, and canonical-name files with
// no database row (crashed creates) are swept.
func (s *service) reconcileStartup(ctx context.Context) error {
	return s.withTx(ctx, func(conn *sql.Conn) error {
		rows, err := conn.QueryContext(ctx, `select id, state, offset from upload_sessions`)
		if err != nil {
			return typed(ErrDependency, err)
		}
		idset := map[string]bool{}
		for rows.Next() {
			if err := ctx.Err(); err != nil {
				rows.Close()
				return ctx.Err()
			}
			var id, state string
			var offset int64
			if err := rows.Scan(&id, &state, &offset); err != nil {
				rows.Close()
				return typed(ErrDependency, err)
			}
			idset[id] = true
			if state == string(StateDeleting) {
				_ = s.spool.remove(id)
				if _, err := conn.ExecContext(ctx,
					`delete from upload_sessions where id = ? and state = 'deleting'`, id); err != nil {
					rows.Close()
					return typed(ErrDependency, err)
				}
				continue
			}
			if err := s.spool.align(id, offset); err != nil {
				rows.Close()
				return typed(ErrDependency, err)
			}
		}
		rows.Close()
		if err := ctx.Err(); err != nil {
			return ctx.Err()
		}
		orphans, err := s.spool.orphanCandidates()
		if err != nil {
			return typed(ErrDependency, err)
		}
		for _, name := range orphans {
			if !idset[name] {
				_ = s.spool.remove(name)
			}
		}
		return nil
	})
}
