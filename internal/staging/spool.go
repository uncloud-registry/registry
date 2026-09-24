package staging

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
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

// spoolError is a data-free dependency error. Error() and Unwrap() expose
// only the fixed ErrDependency surface; the private cause survives only
// behind a closure so that no formatting or reflection surface (%v, %+v,
// %#v, JSON) can ever print paths, DSNs, or raw causes.
type spoolError struct {
	kind  spoolErrKind
	cause func() error
}

func (e *spoolError) Error() string { return ErrDependency.Error() }

func (e *spoolError) Unwrap() error { return ErrDependency }

func spoolErr(kind spoolErrKind, cause error) error {
	if cause == nil {
		cause = errors.New("spool filesystem error")
	}
	return &spoolError{kind: kind, cause: func() error { return cause }}
}

// spoolErrKindOf classifies a dependency error for internal decisions
// (service-side handling only; never surfaced).
func spoolErrKindOf(err error) spoolErrKind {
	var se *spoolError
	if errors.As(err, &se) {
		return se.kind
	}
	return spoolErrGeneric
}

// spoolErrorCause recovers the private diagnostic of a spool error for
// package-internal logging. It must never be rendered into a caller-visible
// error value.
func spoolErrorCause(err error) error {
	var se *spoolError
	if errors.As(err, &se) && se.cause != nil {
		return se.cause()
	}
	return nil
}

// spool is the descriptor-relative filesystem staging area. Every file is
// reached through an os.Root anchored at a private 0700 directory, using
// server-generated 64-hex names, so no caller-controlled string can escape
// the root and no symlink is ever followed. The descriptor is retained for
// the lifetime of the service, so a rename/swap of the root path never
// redirects production access.
type spool struct {
	root     *os.Root
	rootPath string
}

// openPrivateDirChain resolves `path` to a private 0700 directory and
// returns an os.Root anchored at it. Only the components BELOW the deepest
// existing ancestor are created or mode-repaired, all through the anchored
// descriptor; OS-standard symlink prefixes (/var, /tmp) and unrelated
// ancestors are neither followed into nor touched, so e.g. /var/lib or
// $HOME need not themselves be private. Every below-anchor component is
// verified to be a real non-symlink directory and repaired to exactly 0700;
// a component that cannot be made private, or that is a symlink or
// non-directory, is rejected. When enforce is false (the implied "." parent
// of a bare database name) only the anchor is opened and nothing is created
// or modified.
func openPrivateDirChain(path string, enforce bool) (*os.Root, error) {
	if path == "" {
		return nil, spoolErr(spoolErrGeneric, errors.New("empty directory path"))
	}
	clean := filepath.Clean(path)
	if clean == "." {
		root, err := os.OpenRoot(".")
		if err != nil {
			return nil, spoolErr(spoolErrGeneric, err)
		}
		if !enforce {
			return root, nil
		}
		if err := verifyPrivateDir(root, ".", 0o700, true, clean); err != nil {
			root.Close()
			return nil, err
		}
		return root, nil
	}
	// Bootstrap: find the deepest existing ancestor by path. Every
	// subsequent access is descriptor-relative.
	var tail []string
	cur := clean
	var anchor *os.Root
	for {
		fi, err := os.Lstat(cur)
		switch {
		case err == nil:
			if fi.Mode()&os.ModeSymlink != 0 {
				return nil, spoolErr(spoolErrGeneric, errors.New("path component is a symbolic link"))
			}
			if !fi.IsDir() {
				return nil, spoolErr(spoolErrGeneric, errors.New("path component is not a directory"))
			}
			r, err := os.OpenRoot(cur)
			if err != nil {
				if os.IsNotExist(err) {
					continue // raced away between Lstat and open; walk up
				}
				return nil, spoolErr(spoolErrGeneric, err)
			}
			anchor = r
			goto descend
		case os.IsNotExist(err):
			parent := filepath.Dir(cur)
			if parent == cur {
				return nil, spoolErr(spoolErrGeneric, fmt.Errorf("cannot resolve directory %q", path))
			}
			tail = append([]string{filepath.Base(cur)}, tail...)
			cur = parent
		default:
			return nil, spoolErr(spoolErrGeneric, err)
		}
	}

descend:
	for _, comp := range tail {
		fi, err := anchor.Lstat(comp)
		switch {
		case err == nil:
			if fi.Mode()&os.ModeSymlink != 0 {
				anchor.Close()
				return nil, spoolErr(spoolErrGeneric, errors.New("path component is a symbolic link"))
			}
			if !fi.IsDir() {
				anchor.Close()
				return nil, spoolErr(spoolErrGeneric, errors.New("path component is not a directory"))
			}
		case os.IsNotExist(err):
			if !enforce {
				anchor.Close()
				return nil, spoolErr(spoolErrGeneric, errors.New("path component does not exist"))
			}
			if err := anchor.Mkdir(comp, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
				anchor.Close()
				return nil, spoolErr(spoolErrGeneric, err)
			}
		default:
			anchor.Close()
			return nil, spoolErr(spoolErrGeneric, err)
		}
		sub, err := anchor.OpenRoot(comp)
		if err != nil {
			anchor.Close()
			return nil, spoolErr(spoolErrGeneric, err)
		}
		anchor.Close()
		anchor = sub
	}
	// Final directory: verify and repair exact 0700 through the descriptor.
	if err := verifyPrivateDir(anchor, ".", 0o700, enforce, clean); err != nil {
		anchor.Close()
		return nil, err
	}
	return anchor, nil
}

// verifyPrivateDir confirms the descriptor-relative name is a real
// non-symlink directory and, when repair is allowed and the mode differs
// from want, repairs it through an opened descriptor. Impossible modes are
// rejected. When the descriptor-relative open is impossible because the
// directory lacks the execute bit (an open of "." through the root requires
// it), an identity-verified path-based fallback chmod is used: the opened
// descriptor is compared with the anchored identity BEFORE any chmod, so a
// swapped path is never touched.
func verifyPrivateDir(root *os.Root, name string, want os.FileMode, repair bool, fullPath string) error {
	fi, err := root.Lstat(name)
	if err != nil {
		// A directory without the execute bit cannot be stat'd or opened
		// descriptor-relatively; repair it through the parent (identity
		// verified) and retry.
		if repair && fullPath != "" && errors.Is(err, fs.ErrPermission) {
			if rerr := repairDirModeByPath(fullPath, want, root, name); rerr != nil {
				return rerr
			}
			fi, err = root.Lstat(name)
		}
		if err != nil {
			return spoolErr(spoolErrGeneric, err)
		}
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return spoolErr(spoolErrGeneric, errors.New("directory path is a symbolic link"))
	}
	if !fi.IsDir() {
		return spoolErr(spoolErrGeneric, errors.New("directory path is not a directory"))
	}
	if p := fi.Mode().Perm(); p != want {
		if !repair {
			return spoolErr(spoolErrGeneric, fmt.Errorf("directory mode %o is not private", p))
		}
		f, err := root.Open(name)
		if err != nil && fullPath != "" {
			return repairDirModeByPath(fullPath, want, root, name)
		}
		if err != nil {
			return spoolErr(spoolErrGeneric, err)
		}
		cerr := f.Chmod(want)
		f.Close()
		if cerr != nil {
			return spoolErr(spoolErrGeneric, errors.New("cannot make directory private"))
		}
		fi, err = root.Lstat(name)
		if err != nil {
			return spoolErr(spoolErrGeneric, err)
		}
		if p := fi.Mode().Perm(); p != want {
			return spoolErr(spoolErrGeneric, fmt.Errorf("directory mode repair to %o failed", want))
		}
	}
	return nil
}

// repairDirModeByPath changes a directory's mode through a descriptor opened
// by its full path, but ONLY after verifying the opened descriptor is the
// same file as the pre-open path identity — a rename/swap between
// verification and open is detected and nothing is modified. It is used when
// the directory lacks the execute bit and cannot be opened or stat'd
// descriptor-relatively.
func repairDirModeByPath(fullPath string, want os.FileMode, root *os.Root, name string) error {
	pathFi, err := os.Lstat(fullPath)
	if err != nil {
		return spoolErr(spoolErrGeneric, err)
	}
	if pathFi.Mode()&os.ModeSymlink != 0 || !pathFi.IsDir() {
		return spoolErr(spoolErrGeneric, errors.New("directory path is a symbolic link or not a directory"))
	}
	f, err := os.Open(fullPath)
	if err != nil {
		return spoolErr(spoolErrGeneric, err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return spoolErr(spoolErrGeneric, err)
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || !os.SameFile(st, pathFi) {
		f.Close()
		return spoolErr(spoolErrGeneric, errors.New("directory changed during mode repair"))
	}
	cerr := f.Chmod(want)
	f.Close()
	if cerr != nil {
		return spoolErr(spoolErrGeneric, errors.New("cannot make directory private"))
	}
	fi, err := root.Lstat(name)
	if err != nil {
		return spoolErr(spoolErrGeneric, err)
	}
	if fi.Mode().Perm() != want {
		return spoolErr(spoolErrGeneric, fmt.Errorf("directory mode repair to %o failed", want))
	}
	return nil
}

// newSpool resolves the spool root descriptor-relatively (symlink-rejecting,
// mode-repairing), then verifies descriptor identity against the caller's
// path so a rename/swap during construction is detected.
func newSpool(ctx context.Context, rootPath string) (*spool, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := openPrivateDirChain(rootPath, true)
	if err != nil {
		return nil, err
	}
	// Post-open identity: the opened descriptor must still be what the
	// caller's path names (detects a rename/swap during construction).
	fi, err := root.Lstat(".")
	if err != nil {
		root.Close()
		return nil, spoolErr(spoolErrGeneric, err)
	}
	pfi, perr := os.Lstat(rootPath)
	if perr != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() || !os.SameFile(fi, pfi) {
		root.Close()
		if perr != nil {
			return nil, spoolErr(spoolErrGeneric, err)
		}
		return nil, spoolErr(spoolErrGeneric, errors.New("spool root changed during construction"))
	}
	return &spool{root: root, rootPath: rootPath}, nil
}

func (sp *spool) Close() error {
	if sp.root == nil {
		return nil
	}
	err := sp.root.Close()
	sp.root = nil
	return err
}

// create makes the empty 0600 spool file for a validated id and returns the
// writable descriptor open at offset 0. It never follows an existing symlink
// (os.Root O_EXCL semantics): a pre-existing name of any kind is rejected.
// The caller owns durability: fsync the returned descriptor (or roll the row
// back) and fsync the directory before activating the session.
func (sp *spool) create(id string) (*os.File, error) {
	if err := validateID(id); err != nil {
		return nil, err
	}
	f, err := sp.root.OpenFile(id, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, spoolErr(spoolErrGeneric, err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		_ = sp.remove(id)
		return nil, spoolErr(spoolErrGeneric, err)
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0o077 != 0 {
		f.Close()
		_ = sp.remove(id)
		return nil, spoolErr(spoolErrGeneric, errors.New("spool file is not a private regular file"))
	}
	// Descriptor identity: no swap between creation and hand-off.
	lst, err := sp.root.Lstat(id)
	if err != nil || !os.SameFile(st, lst) || lst.Mode()&os.ModeSymlink != 0 {
		f.Close()
		_ = sp.remove(id)
		return nil, spoolErr(spoolErrGeneric, errors.New("spool file changed during creation"))
	}
	return f, nil
}

// openFile is the single descriptor-relative open path: one Lstat captures
// the expected identity, every subsequent open is verified SameFile against
// it, an overlong crash tail is truncated through the fd, a shorter file
// fails closed, and the returned descriptor is positioned at offset.
func (sp *spool) openFile(id string, offset int64, flag int) (*os.File, error) {
	if err := validateID(id); err != nil {
		return nil, err
	}
	fi, err := sp.root.Lstat(id)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, spoolErr(spoolErrMissing, err)
		}
		return nil, spoolErr(spoolErrGeneric, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, spoolErr(spoolErrSymlink, errors.New("spool path is a symbolic link"))
	}
	if !fi.Mode().IsRegular() {
		return nil, spoolErr(spoolErrNotRegular, errors.New("spool path is not a regular file"))
	}
	if fi.Size() < offset {
		return nil, spoolErr(spoolErrShort, errors.New("durable file is shorter than the committed offset"))
	}
	if fi.Size() > offset {
		// ftruncate requires a writable descriptor.
		tf, err := sp.root.OpenFile(id, os.O_WRONLY, 0)
		if err != nil {
			return nil, spoolErr(spoolErrGeneric, err)
		}
		st, err := tf.Stat()
		if err != nil || !st.Mode().IsRegular() || st.Size() < offset || !os.SameFile(st, fi) {
			tf.Close()
			return nil, spoolErr(spoolErrNotRegular, errors.New("opened spool path is not the verified file"))
		}
		if err := tf.Truncate(offset); err != nil {
			tf.Close()
			return nil, spoolErr(spoolErrGeneric, err)
		}
		if err := tf.Close(); err != nil {
			return nil, spoolErr(spoolErrGeneric, err)
		}
	}
	f, err := sp.root.OpenFile(id, flag, 0)
	if err != nil {
		return nil, spoolErr(spoolErrGeneric, err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, spoolErr(spoolErrGeneric, err)
	}
	if !st.Mode().IsRegular() || st.Size() != offset || !os.SameFile(st, fi) {
		f.Close()
		return nil, spoolErr(spoolErrNotRegular, errors.New("opened spool path is not the verified file"))
	}
	if flag == os.O_WRONLY {
		// Append semantics: position exactly at the committed offset. The
		// read path returns the descriptor at position 0 (the reader is
		// offset-limited by its caller).
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			f.Close()
			return nil, spoolErr(spoolErrGeneric, err)
		}
	}
	return f, nil
}

// align verifies the spool file at id is a regular, symlink-free file whose
// durable bytes are at least offset; a longer file is an uncommitted crash
// tail and is truncated back to offset. A shorter file means the database is
// ahead of durable file bytes and fails closed.
func (sp *spool) align(id string, offset int64) error {
	f, err := sp.openFile(id, offset, os.O_WRONLY)
	if err != nil {
		return err
	}
	return f.Close()
}

// openForAppend returns a write-only descriptor positioned exactly at the
// committed offset (the file identity is verified through the anchor).
func (sp *spool) openForAppend(id string, offset int64) (*os.File, error) {
	return sp.openFile(id, offset, os.O_WRONLY)
}

// openForRead returns a read-only descriptor over exactly the committed
// bytes.
func (sp *spool) openForRead(id string, offset int64) (*os.File, error) {
	return sp.openFile(id, offset, os.O_RDONLY)
}

// remove unlinks the spool file for a validated id. Removing an already
// absent file is a no-op (idempotent cleanup). os.Root.Remove never follows
// a symlink: the link itself is removed. A non-empty directory entry cannot
// be unlinked and is left intact.
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

// removeDurable unlinks the spool file (idempotent when absent) and fsyncs
// the containing directory before returning, so a completed removal is
// durable even across a crash. On error the entry state is reported as-is
// (the unlink may or may not have happened); callers keep the tombstone.
func (sp *spool) removeDurable(id string) error {
	if err := sp.remove(id); err != nil {
		return err
	}
	return sp.syncDir()
}

// syncDir fsyncs the spool root directory through the retained descriptor,
// making a just-created or just-unlinked entry durable.
func (sp *spool) syncDir() error {
	f, err := sp.root.Open(".")
	if err != nil {
		return spoolErr(spoolErrGeneric, err)
	}
	err = f.Sync()
	f.Close()
	if err != nil {
		return spoolErr(spoolErrGeneric, err)
	}
	return nil
}

// entries lists every entry name in the spool root THROUGH the anchored
// descriptor (never through a path), so a renamed-away root or a planted
// symlink at the original path cannot redirect enumeration.
func (sp *spool) entries() ([]string, error) {
	f, err := sp.root.Open(".")
	if err != nil {
		return nil, spoolErr(spoolErrGeneric, err)
	}
	defer f.Close()
	entries, err := f.ReadDir(-1)
	if err != nil {
		return nil, spoolErr(spoolErrGeneric, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}
