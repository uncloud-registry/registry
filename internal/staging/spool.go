package staging

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// spoolErrorKind identifies fail-closed filesystem divergences so the
// service can surface them as ErrDependency without leaking paths.
type spoolErrKind int

const (
	spoolErrGeneric spoolErrKind = iota
	spoolErrMissing
	spoolErrSymlink
	spoolErrNotRegular
	spoolErrShort // durable (committed) offset exceeds the durable file bytes
)

type spoolError struct {
	kind  spoolErrKind
	cause error
}

func (e *spoolError) Error() string { return e.cause.Error() }

func (e *spoolError) Unwrap() error { return ErrDependency }

func spoolErr(kind spoolErrKind, cause error) error {
	if cause == nil {
		cause = errors.New("spool filesystem error")
	}
	return &spoolError{kind: kind, cause: cause}
}

func spoolErrKindOf(err error) spoolErrKind {
	var se *spoolError
	if errors.As(err, &se) {
		return se.kind
	}
	return spoolErrGeneric
}

// spool is the descriptor-relative filesystem staging area. Every file is
// reached through an os.Root anchored at a private 0700 directory, using
// server-generated 64-hex names, so no caller-controlled string can escape
// the root and no symlink is ever followed on Unix.
type spool struct {
	root     *os.Root
	rootPath string
}

// newSpool validates or creates the spool root: it must be a real directory
// (never a symlink or a regular file) with no group/other access, created
// 0700 under any umask. The descriptor is opened once and reused.
func newSpool(ctx context.Context, rootPath string) (*spool, error) {
	if err := preparePrivateDir(rootPath); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, spoolErr(spoolErrGeneric, err)
	}
	// Post-open verification of the descriptor itself: directory, not a
	// symlink, private mode, and no group/other bits.
	fi, err := root.Lstat(".")
	if err != nil {
		root.Close()
		return nil, spoolErr(spoolErrGeneric, err)
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		root.Close()
		return nil, spoolErr(spoolErrGeneric, errors.New("spool root is not a private directory"))
	}
	if fi.Mode().Perm()&0o077 != 0 {
		root.Close()
		return nil, spoolErr(spoolErrGeneric, errors.New("spool root has group or other access"))
	}
	_ = ctx
	return &spool{root: root, rootPath: rootPath}, nil
}

// preparePrivateDir creates dir (and parents) with 0700 and verifies the
// effective mode allows no group/other access. Pre-existing symlinks or
// non-directories are rejected.
func preparePrivateDir(dir string) error {
	fi, err := os.Lstat(dir)
	switch {
	case err == nil:
		if fi.Mode()&os.ModeSymlink != 0 {
			return spoolErr(spoolErrGeneric, fmt.Errorf("path is a symbolic link"))
		}
		if !fi.IsDir() {
			return spoolErr(spoolErrGeneric, fmt.Errorf("path is not a directory"))
		}
		if fi.Mode().Perm()&0o077 != 0 {
			return spoolErr(spoolErrGeneric, fmt.Errorf("path has group or other access"))
		}
		return nil
	case os.IsNotExist(err):
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return spoolErr(spoolErrGeneric, err)
		}
		fi, err := os.Lstat(dir)
		if err != nil {
			return spoolErr(spoolErrGeneric, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			return spoolErr(spoolErrGeneric, fmt.Errorf("created path is not a private directory"))
		}
		if fi.Mode().Perm()&0o077 != 0 {
			return spoolErr(spoolErrGeneric, fmt.Errorf("created path has group or other access"))
		}
		return nil
	default:
		return spoolErr(spoolErrGeneric, err)
	}
}

func (sp *spool) Close() error {
	if sp.root == nil {
		return nil
	}
	err := sp.root.Close()
	sp.root = nil
	return err
}

// create makes the empty 0600 spool file for a validated id. It never follows
// an existing symlink (O_EXCL + O_NOFOLLOW semantics of os.Root).
func (sp *spool) create(id string) error {
	if err := validateID(id); err != nil {
		return err
	}
	f, err := sp.root.OpenFile(id, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return spoolErr(spoolErrGeneric, err)
	}
	if err := f.Close(); err != nil {
		return spoolErr(spoolErrGeneric, err)
	}
	// Effective mode must be 0600 (umask can only strip owner bits; group and
	// other must never be granted).
	fi, err := sp.root.Lstat(id)
	if err != nil {
		return spoolErr(spoolErrGeneric, err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return spoolErr(spoolErrGeneric, fmt.Errorf("spool file has group or other access"))
	}
	return nil
}

// align verifies the spool file at id is a regular, symlink-free file whose
// durable bytes are at least offset; a longer file is an uncommitted crash
// tail and is truncated back to offset. A shorter file means the database is
// ahead of durable file bytes and fails closed.
func (sp *spool) align(id string, offset int64) error {
	if err := validateID(id); err != nil {
		return err
	}
	fi, err := sp.root.Lstat(id)
	if err != nil {
		if os.IsNotExist(err) {
			return spoolErr(spoolErrMissing, err)
		}
		return spoolErr(spoolErrGeneric, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return spoolErr(spoolErrSymlink, errors.New("spool path is a symbolic link"))
	}
	if !fi.Mode().IsRegular() {
		return spoolErr(spoolErrNotRegular, errors.New("spool path is not a regular file"))
	}
	if fi.Size() < offset {
		return spoolErr(spoolErrShort, errors.New("durable file is shorter than the committed offset"))
	}
	if fi.Size() == offset {
		return nil
	}
	// Uncommitted tail: open (without truncate), verify through the fd, and
	// cut the file back to the committed offset.
	f, err := sp.root.OpenFile(id, os.O_WRONLY, 0)
	if err != nil {
		return spoolErr(spoolErrGeneric, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return spoolErr(spoolErrGeneric, err)
	}
	if !st.Mode().IsRegular() {
		return spoolErr(spoolErrNotRegular, errors.New("opened spool path is not a regular file"))
	}
	if st.Size() < offset {
		return spoolErr(spoolErrShort, errors.New("opened durable file is shorter than the committed offset"))
	}
	if st.Size() > offset {
		if err := f.Truncate(offset); err != nil {
			return spoolErr(spoolErrGeneric, err)
		}
	}
	return nil
}

// openForAppend aligns the file to offset and returns a write-only descriptor
// positioned exactly at offset.
func (sp *spool) openForAppend(id string, offset int64) (*os.File, error) {
	if err := sp.align(id, offset); err != nil {
		return nil, err
	}
	f, err := sp.root.OpenFile(id, os.O_WRONLY, 0)
	if err != nil {
		return nil, spoolErr(spoolErrGeneric, err)
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		f.Close()
		return nil, spoolErr(spoolErrGeneric, err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, spoolErr(spoolErrGeneric, err)
	}
	if !st.Mode().IsRegular() || st.Size() != offset {
		f.Close()
		return nil, spoolErr(spoolErrNotRegular, errors.New("opened spool path is not aligned"))
	}
	return f, nil
}

// openForRead aligns the file to offset and returns a read-only descriptor
// for exactly the committed bytes.
func (sp *spool) openForRead(id string, offset int64) (*os.File, error) {
	if err := sp.align(id, offset); err != nil {
		return nil, err
	}
	f, err := sp.root.OpenFile(id, os.O_RDONLY, 0)
	if err != nil {
		return nil, spoolErr(spoolErrGeneric, err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, spoolErr(spoolErrGeneric, err)
	}
	if !st.Mode().IsRegular() || st.Size() != offset {
		f.Close()
		return nil, spoolErr(spoolErrNotRegular, errors.New("opened spool path is not aligned"))
	}
	return f, nil
}

// remove unlinks the spool file for a validated id. Removing an already
// absent file is a no-op (idempotent cleanup). os.Root.Remove never follows
// a symlink: the link itself is removed.
func (sp *spool) remove(id string) error {
	if err := validateID(id); err != nil {
		return err
	}
	err := sp.root.Remove(id)
	if err != nil && os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return spoolErr(spoolErrGeneric, err)
	}
	return nil
}

// listOrphans returns names in the root directory that match the id grammar.
// Callers reconcile them against the database while holding the SQLite write
// lock.
func (sp *spool) orphanCandidates() ([]string, error) {
	entries, err := os.ReadDir(sp.rootPath)
	if err != nil {
		return nil, spoolErr(spoolErrGeneric, err)
	}
	var names []string
	for _, e := range entries {
		name := e.Name()
		if validateID(name) == nil {
			names = append(names, name)
		}
	}
	return names, nil
}

// rootedPath returns the plain OS path of a validated spool name (used only
// by tests and diagnostics; every production access goes through the root).
func (sp *spool) rootedPath(id string) string {
	return filepath.Join(sp.rootPath, id)
}
