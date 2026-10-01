package staging

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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
//
// PRIVACY BOUNDARY: the spool is EXACT-PRIVATE — every leaf is verified to
// exact 0600 and every directory in the chain to exact 0700 through anchored
// descriptors, so a foreign or looser-mode leaf is never chmod'd, opened, or
// unlinked. The threat model is an ATTACKER OUTSIDE THE UID: the owner UID by
// definition may chmod/chown/unlink these files directly, so the quarantine
// protocol defends against another process racing a swap under a DIFFERENT
// owner only insofar as that process cannot already write the directory. It
// does NOT defend an untrusted process sharing the service's UID (same-UID),
// nor root; a same-UID adversary can stat/open/rename the files regardless of
// mode. All pointers, SameFile, and quarantine-guarantees therefore assume
// mount-owner-equivalent access and provide atomicity/durability guarantees
// strictly below that boundary.

// ascLeafSwapHook, when non-nil, runs at a leaf-boundary decision point (in
// verifyPrivateDir before its descriptor open, in removeNameGuarded before
// its guarded unlink, and in createDBFile's guarded cleanup) so a
// deterministic barrier test can swap the leaf underneath and prove the
// guarded code never chmods or unlinks a foreign replacement. Tests only;
// nil in production.
var ascLeafSwapHook func(phase, name string)

type spool struct {
	root     *os.Root
	rootPath string
	// syncFile replaces the fsync of spool files (spool-level fault
	// injection). The service wires its own hook here at construction.
	syncFile func(f *os.File) error
}

// openPrivateDirChain resolves `path` to a private 0700 directory and
// returns an os.Root anchored at it by walking EVERY path component from a
// trusted descriptor anchor — absolute "/" for absolute paths, the
// descriptor-opened CWD (".") for relative ones. Each component is Lstat'd
// in the CURRENT root: a symlink or non-directory is rejected, a missing
// component is created exactly 0700 without touching the process umask (an
// anchored, no-follow descriptor repair re-bases a restrictive umask) only
// when enforce is true, an existing component's mode is verified and
// repaired through the anchored parent descriptor (a no-exec child is
// opened read-only by name from the parent and fchmod'd — never through a
// raw path), then OpenRoot'd and compared against a post-open snapshot so a
// swap of any component is detected. The deepest whole path is never Lstat'd
// or OpenRoot'd directly. Only the components BELOW the anchor may be
// created or mode-repaired, always through the anchored descriptor;
// OS-standard symlink prefixes (/var, /tmp) therefore reject the path rather
// than being followed. The final directory is verified and repaired to
// exactly 0700. When enforce is false (the implied "." parent of a bare
// database name) only the anchor is opened and nothing is created or
// modified.
func openPrivateDirChain(path string, enforce bool) (*os.Root, error) {
	if path == "" {
		return nil, spoolErr(spoolErrGeneric, errors.New("empty directory path"))
	}
	clean := filepath.Clean(path)
	var anchor *os.Root
	var comps []string
	if filepath.IsAbs(clean) {
		r, err := os.OpenRoot("/")
		if err != nil {
			return nil, spoolErr(spoolErrGeneric, err)
		}
		anchor = r
		for _, c := range strings.Split(clean, "/") {
			if c != "" {
				comps = append(comps, c)
			}
		}
	} else {
		r, err := os.OpenRoot(".")
		if err != nil {
			return nil, spoolErr(spoolErrGeneric, err)
		}
		anchor = r
		if clean != "." {
			for _, c := range strings.Split(clean, "/") {
				if c != "" {
					comps = append(comps, c)
				}
			}
		}
	}

	for i, comp := range comps {
		last := i == len(comps)-1
		if comp == "." || comp == ".." {
			anchor.Close()
			return nil, spoolErr(spoolErrGeneric, errors.New("path component is not a plain name"))
		}
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
			if err := createPrivateDir(anchor, comp); err != nil {
				anchor.Close()
				return nil, err
			}
			fi, err = anchor.Lstat(comp)
			if err != nil {
				anchor.Close()
				return nil, spoolErr(spoolErrGeneric, err)
			}
			if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
				anchor.Close()
				return nil, spoolErr(spoolErrGeneric, errors.New("path component is not a real directory"))
			}
		default:
			anchor.Close()
			return nil, spoolErr(spoolErrGeneric, err)
		}
		// The FINAL component alone is ours to verify and repair to exactly
		// 0700, through the ANCHORED parent descriptor: a no-exec final
		// directory is still openable by name from the parent (openat needs
		// only the PARENT's execute bit plus the child's read bit), so the
		// child's own missing execute bit can be repaired safely. Ancestors
		// are the operator's — they are only checked for symlink/type, never
		// mode-repaired. When even the final directory cannot be opened
		// (no read bit), the descent fails closed — no path-based chmod is
		// ever used.
		if last {
			if err := verifyPrivateDir(anchor, comp, 0o700, enforce); err != nil {
				anchor.Close()
				return nil, err
			}
		}
		// Open the component in the CURRENT root and prove its identity with
		// a post-open snapshot of the same component: a swap between the
		// pre-open Lstat and the open is detected and the descent fails
		// closed.
		sub, err := anchor.OpenRoot(comp)
		if err != nil {
			anchor.Close()
			return nil, spoolErr(spoolErrGeneric, err)
		}
		post, err := anchor.Lstat(comp)
		if err != nil || post.Mode()&os.ModeSymlink != 0 || !post.IsDir() || !os.SameFile(fi, post) {
			sub.Close()
			anchor.Close()
			return nil, spoolErr(spoolErrGeneric, errors.New("path component changed during descent"))
		}
		anchor.Close()
		anchor = sub
	}
	// Final directory: verify and repair exact 0700 through the descriptor.
	if clean != "." {
		if err := verifyPrivateDir(anchor, ".", 0o700, enforce); err != nil {
			anchor.Close()
			return nil, err
		}
	} else if enforce {
		if err := verifyPrivateDir(anchor, ".", 0o700, true); err != nil {
			anchor.Close()
			return nil, err
		}
	}
	return anchor, nil
}

// createPrivateDir creates comp as a subdirectory of the anchored parent
// root with EXACTLY 0700 WITHOUT ever touching the process umask (a
// process-global knob a library/service must not mutate — the constructor
// genuinely can run concurrently with unrelated file creation). The
// requested owner-only 0700 carries no group/other bits, so ordinary umasks
// (022, 002, 077) cannot loosen it and no repair is needed. Only a
// restrictive umask that strips OWNER bits (e.g. 0777 -> 0000) loosens it;
// that is repaired through an OPENED DESCRIPTOR of the freshly created
// child — never through a raw-path chmod, never following a symlink — and
// the descriptor is verified SameFile against the pre-repair anchored
// FileInfo so a swapped replacement is never chmod'd. When the platform
// cannot open the restricted-umask directory for descriptor chmod at all
// (a directory masked 0000/unreadable needs read permission to open on
// macOS), the creation FAILS CLOSED and NO entry is removed: cleanup can
// never unlink a leaf it cannot prove it created, so a foreign replacement
// is always left untouched. Verified platform result: a 0000 directory
// cannot be opened (O_RDONLY|O_DIRECTORY and O_EVTONLY both return EACCES)
// while only name-based fchmodat succeeds — which is precisely the unsafe
// indirection this path refuses, so the repair is impossible and fails
// closed rather than chmod a name that might be replaced.
func createPrivateDir(root *os.Root, comp string) error {
	err := root.Mkdir(comp, 0o700)
	switch {
	case err == nil:
	case errors.Is(err, os.ErrExist):
		// A pre-existing entry is not ours; descent (Lstat + verifyPrivateDir
		// on the final component) handles its identity and mode through the
		// anchored parent. Never touch it here.
		return nil
	default:
		return spoolErr(spoolErrGeneric, err)
	}
	fi, err := root.Lstat(comp)
	if err != nil {
		return spoolErr(spoolErrGeneric, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return spoolErr(spoolErrGeneric, errors.New("path component is not a real directory"))
	}
	if fi.Mode().Perm() == 0o700 {
		return nil
	}
	// Restrictive umask stripped owner bits. Repair through the OPENED
	// descriptor bound to the inspected inode: open the leaf without
	// following a symlink, require SameFile against the pre-repair anchored
	// Lstat (so a swap between the Lstat and the open is detected and the
	// opened leaf is NEVER a foreign replacement), fchmod the descriptor,
	// and re-verify the exact mode on the SAME descriptor.
	f, oerr := root.Open(comp)
	if oerr != nil {
		// The masked directory cannot be opened for descriptor chmod on
		// this platform. Fail closed: never chmod comp by name (it may have
		// been replaced) and never remove it (ownership is unprovable).
		return spoolErr(spoolErrGeneric, errors.New("cannot open restricted-umask directory for private-mode repair"))
	}
	st, serr := f.Stat()
	if serr != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || !os.SameFile(fi, st) {
		_ = f.Close()
		// Identity mismatch: the opened leaf is not the entry we inspected
		// (a swap landed between Lstat and open). Do not chmod it; do not
		// remove either entry — fail closed.
		return spoolErr(spoolErrGeneric, errors.New("path component replaced during private-mode repair"))
	}
	cerr := f.Chmod(0o700)
	if cerr == nil {
		ast, aerr := f.Stat()
		if aerr == nil && ast.IsDir() && ast.Mode().Perm() == 0o700 {
			_ = f.Close()
			return nil
		}
	}
	_ = f.Close()
	return spoolErr(spoolErrGeneric, errors.New("cannot make directory private after creation"))
}

// verifyPrivateDir confirms the descriptor-relative name is a real
// non-symlink directory and, when repair is allowed and the mode differs
// from want, repairs it through an OPENED DESCRIPTOR OF THE LEAF reached
// FROM THE ANCHORED PARENT (never through a path) and verified SameFile
// against the anchored Lstat so a swap between stat/open cannot redirect
// the fchmod onto a foreign replacement. A directory that cannot even be
// opened (no owner read bit after a restrictive umask, or the final root
// itself when no parent is retained) is treated as unrrepairable on this
// platform and the descent FAILS CLOSED.
func verifyPrivateDir(root *os.Root, name string, want os.FileMode, repair bool) error {
	fi, err := root.Lstat(name)
	if err != nil {
		return spoolErr(spoolErrGeneric, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return spoolErr(spoolErrGeneric, errors.New("directory path is a symbolic link"))
	}
	if !fi.IsDir() {
		return spoolErr(spoolErrGeneric, errors.New("directory path is not a directory"))
	}
	if p := fi.Mode().Perm(); p == want {
		return nil
	}
	if !repair {
		return spoolErr(spoolErrGeneric, fmt.Errorf("directory mode %o is not private", fi.Mode().Perm()))
	}
	if ascLeafSwapHook != nil {
		// Deterministic swap barrier: the leaf is swapped between the
		// anchored Lstat and the descriptor open, proving the fchmod (when
		// reached) is NEVER redirected onto a foreign replacement.
		ascLeafSwapHook("verify", name)
	}
	f, err := root.Open(name)
	if err != nil {
		// Unopenable (restrictive-umask 0000): descriptor repair is
		// impossible on this platform; fail closed without touching any
		// leaf or name.
		return spoolErr(spoolErrGeneric, err)
	}
	st, serr := f.Stat()
	if serr != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || !os.SameFile(fi, st) {
		// The opened leaf is not the entry we inspected: do not chmod a
		// foreign replacement. Fail closed.
		_ = f.Close()
		return spoolErr(spoolErrGeneric, errors.New("directory replaced before private-mode repair"))
	}
	cerr := f.Chmod(want)
	f.Close()
	if cerr != nil {
		return spoolErr(spoolErrGeneric, errors.New("cannot make directory private"))
	}
	// Re-verify through the anchored parent: the entry must still be the
	// same inode and now carry the exact mode.
	afi, err := root.Lstat(name)
	if err != nil {
		return spoolErr(spoolErrGeneric, err)
	}
	if !os.SameFile(fi, afi) {
		return spoolErr(spoolErrGeneric, errors.New("directory replaced during private-mode repair"))
	}
	if p := afi.Mode().Perm(); p != want {
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

// ensureRootMode keeps the spool root directory EXACTLY 0700: every
// operation that touches the spool verifies (and repairs through the
// descriptor, identity-checked) the root mode first.
func (sp *spool) ensureRootMode() error {
	return verifyPrivateDir(sp.root, ".", 0o700, true)
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
// writable descriptor open at offset 0. The mode is forced to EXACTLY 0600
// immediately (fchmod through the descriptor, never a path, never following
// a symlink) and verified; a restrictive umask cannot leave it looser or
// stricter. It never follows an existing symlink (os.Root O_EXCL semantics):
// a pre-existing name of any kind is rejected. The caller owns durability:
// fsync the returned descriptor (or roll the row back) and fsync the
// directory before activating the session.
func (sp *spool) create(id string) (*os.File, error) {
	if err := validateID(id); err != nil {
		return nil, err
	}
	return sp.createName(id)
}

// tokName is the spool file name carrying the unforgeable create token of a
// creating session. It is derived from the canonical 64-hex id by a fixed
// suffix, so it can never collide with a canonical file name and can never
// be confused with one during enumeration.
func tokName(id string) string { return id + ".tok" }

// createTok creates the O_EXCL 0600 token file for a validated id and
// returns the writable descriptor open at offset 0, exactly like create but
// under the derived .tok name. The caller owns durability: fsync the
// returned descriptor (or roll the row back) and fsync the directory.
func (sp *spool) createTok(id string) (*os.File, error) {
	return sp.createName(tokName(id))
}

// ---------------------------------------------------------------------------
// Atomic quarantine deletion (repair 4).
//
// Quarantine names use a SEPARATE strict grammar, derived deterministically
// from a session id so a crash-faulted quarantine is attributable and
// convergent, but never valid as a session name or a .tok name:
//
//	canonical quarantine: "q-" + <64 lowercase hex id>          (e.g. q-a3..f0)
//	token quarantine:     "q-" + <64 lowercase hex id> + ".t"
//
// The protection of the quarantine protocol comes from the cross-process
// serialization (BEGIN IMMEDIATE) held over the WHOLE rename/authenticate/
// unlink/fsync sequence and from byte/identity authentication — never from
// the secrecy of the name. An unchanged deterministic name keeps interruption
// (rename committed, unlink not yet) recoverable by any instance. POSIX
// offers no conditional unlink-by-inode, so the accepted boundary is: the
// exact-private spool excludes other principals, and every legitimate
// same-UID writer obeys the same BEGIN IMMEDIATE lock, which no legitimate
// process can hold while another quarantines. A malicious same-UID process is
// out of scope (it can already read or delete everything); the protocol still
// detects and preserves a replaced occupant whenever the swap happens within
// an observable boundary.
// ---------------------------------------------------------------------------

// quarantineNameFor returns the deterministic quarantine name of the canonical
// spool file for a validated id.
func quarantineNameFor(id string) string { return "q-" + id }

// quarantineTokNameFor returns the deterministic quarantine name of the token
// sidecar for a validated id.
func quarantineTokNameFor(id string) string { return "q-" + id + ".t" }

// quarantineForManaged maps a managed spool name (a canonical id or its .tok
// sidecar) to its quarantine name.
func quarantineForManaged(name string) string {
	if base, ok := strings.CutSuffix(name, ".tok"); ok {
		return quarantineTokNameFor(base)
	}
	return quarantineNameFor(name)
}

// isQuarantineName reports whether name uses the quarantine grammar and, if
// so, returns its base id and whether it is the token sidecar quarantine.
func isQuarantineName(name string) (base string, tok bool, ok bool) {
	if !strings.HasPrefix(name, "q-") {
		return "", false, false
	}
	rest := name[2:]
	if len(rest) == 64 && isHex64(rest) {
		return rest, false, true
	}
	if len(rest) == 66 && strings.HasSuffix(rest, ".t") && isHex64(rest[:64]) {
		return rest[:64], true, true
	}
	return "", false, false
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < 64; i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

// quarantineUnlink atomically removes a leaf after moving it from its mutable
// managed name into the private quarantine name, then AUTHENTICATING the
// quarantined entry as the object the caller owns / observed at a serialized
// transition. It NEVER unlinks a mutable managed name directly.
//
//	... managed -> quarantine (atomic rename, same retained root)
//	... fsync the containing directory so the rename is durable BEFORE any
//	    authentication or unlink proceeds (a sync failure fails closed with the
//	    quarantine retained, never restored via another unsynced rename)
//	... open the quarantine NO-FOLLOW, require a real regular exact-0600 file
//	    whose inode is SameFile against `want` (when non-nil, the created or
//	    transition-observed identity) and which satisfies `verify` (a durably
//	    proven contract such as exact size, or exact sidecar bytes).
//	... on success, unlink the quarantine and fsync the directory.
//	... on ANY mismatch/swap/wrong-size/symlink, the quarantined entry is
//	    RESTORED non-clobberingly to `managed` when that name is free, or
//	    retained at `quarantine` when occupied, and an error is returned:
//	    a foreign or unowned entry is NEVER deleted.
//	... a crash between rename and unlink is recovered by a later call: when
//	    `managed` is absent but `quarantine` is present, the outstanding
//	    quarantine is authenticated and finished (deterministic name).
//
// The caller MUST hold the cross-process serialization (BEGIN IMMEDIATE) or —
// for constructor cleanup — the unique created-object identity for the whole
// call; that is what prevents a legitimate writer from replacing the
// quarantine name between authentication and unlink. A test-only `barrier`
// fires before the rename and immediately before the final unlink so swap
// injection proves the protocol detects and preserves replacements at every
// former final-check window.
func (sp *spool) quarantineUnlink(managed, quarantine string, want os.FileInfo, verify func(st os.FileInfo, f *os.File) error, syncDir func() error, barrier func(phase, name string)) (bool, error) {
	return quarantineUnlinkRoot(sp.root, managed, quarantine, want, verify, syncDir, barrier)
}

func quarantineUnlinkRoot(root *os.Root, managed, quarantine string, want os.FileInfo, verify func(st os.FileInfo, f *os.File) error, syncDir func() error, barrier func(phase, name string)) (bool, error) {
	if barrier != nil {
		barrier("pre-rename", managed)
	}

	srcFi, serr := root.Lstat(managed)
	var captured os.FileInfo
	renamed := false
	switch {
	case serr == nil:
		if srcFi.Mode()&os.ModeSymlink != 0 {
			// Managed names are never symlinks; reject without moving.
			return false, spoolErr(spoolErrGeneric, errors.New("spool leaf is a symbolic link"))
		}
		// The destination must be ABSENT: POSIX rename would atomically
		// replace it. An occupied quarantine (e.g. a crashed sibling's
		// outstanding rename, or an attacker) is never clobbered.
		if _, derr := root.Lstat(quarantine); derr == nil {
			return false, spoolErr(spoolErrGeneric, errors.New("quarantine destination is already occupied"))
		} else if !os.IsNotExist(derr) {
			return false, spoolErr(spoolErrGeneric, derr)
		}
		if err := root.Rename(managed, quarantine); err != nil {
			if os.IsNotExist(err) {
				// The managed name vanished between Lstat and rename: recover
				// to the outstanding-quarantine branch below.
				serr = err
				break
			}
			return false, spoolErr(spoolErrGeneric, err)
		}
		renamed = true
		captured = srcFi
	case os.IsNotExist(serr):
		// Fall through: an outstanding quarantine from an earlier rename
		// (managed absent) is finished when present.
	default:
		return false, spoolErr(spoolErrGeneric, serr)
	}
	if !renamed {
		// managed was absent at Lstat (or vanished before rename): recover an
		// outstanding quarantine, or treat as already-clean idempotency.
		// (Nothing was moved this call, so NO post-rename sync is needed here.)
		if _, qerr := root.Lstat(quarantine); os.IsNotExist(qerr) {
			// Nothing at either name. The ABSENCE is a durable fact only once
			// the containing directory fsync succeeds: a crash before that sync
			// could resurrect the unlink, so a clean result here must not be
			// acknowledged without the same directory sync an unlink performs.
			// A failing sync fails closed exactly like it would after an unlink,
			// retaining the tombstone and count for a later run. Idempotency is
			// preserved for a previously-durable unlink (the dir is already
			// synced, so a follow-up sync succeeds).
			if syncDir != nil {
				if err := syncDir(); err != nil {
					return false, err
				}
			}
			return false, nil
		} else if qerr != nil {
			return false, spoolErr(spoolErrGeneric, qerr)
		}
		qFi, lerr := root.Lstat(quarantine)
		if lerr != nil {
			return false, spoolErr(spoolErrGeneric, lerr)
		}
		captured = qFi
	} else {
		// A successful same-root rename moved the managed leaf into the
		// quarantine name. That rename MUST be durable before any
		// authentication or unlink of the quarantined entry proceeds: fsync
		// the containing directory immediately. A sync failure fails closed
		// with the quarantine RETAINED — never restored through another
		// unsynced rename (which could itself be lost) — so a crash cannot
		// leave the leaf half-moved between names or unaccounted. The
		// post-sync barrier fires only after the directory sync has completed,
		// immediately before authentication and the pre-unlink barrier.
		if syncDir != nil {
			if err := syncDir(); err != nil {
				return false, err
			}
		}
		if barrier != nil {
			barrier("post-sync", quarantine)
		}
		// Prove the rename moved exactly the inspected inode: a swap between
		// the Lstat and the rename is a FOREIGN capture and is restored, never
		// unlinked. This is the FIRST authentication and it runs ONLY after
		// the containing directory was fsynced (the post-sync barrier above),
		// so any unsynced-restore decision is impossible on a failed fsync.
		pdst, lerr := root.Lstat(quarantine)
		if lerr != nil || !os.SameFile(srcFi, pdst) {
			_ = restoreQuarantine(root, quarantine, managed)
			if syncDir != nil {
				// Directory fsync after every restore (best-effort; the
				// failed cleanup already retains durable metadata).
				_ = syncDir()
			}
			return false, spoolErr(spoolErrGeneric, errors.New("quarantine captured a replaced leaf"))
		}
	}

	if err := authAndUnlinkQuarantine(root, quarantine, captured, want, verify, syncDir, barrier); err != nil {
		// Foreign / unowned / wrong content: the caller restores after a
		// fresh rename; a resumed quarantine is retained (fail closed).
		if renamed {
			_ = restoreQuarantine(root, quarantine, managed)
			if syncDir != nil {
				// Directory fsync after every restore (best-effort; the
				// failed cleanup already retains durable metadata).
				_ = syncDir()
			}
		}
		return false, err
	}
	return true, nil
}

// authAndUnlinkQuarantine authenticates an existing quarantine entry against
// its captured inode / owned identity / durable contract, re-checks identity
// immediately before the final unlink (the last replacement window) while the
// serialization is held, then unlinks it and fsyncs the directory. A swap of
// the quarantine name between authentication and unlink is detected and the
// replacement is never unlinked (the caller restores it non-clobberingly or
// retains it fail-closed).
func authAndUnlinkQuarantine(root *os.Root, quarantine string, captured, want os.FileInfo, verify func(st os.FileInfo, f *os.File) error, syncDir func() error, barrier func(phase, name string)) error {
	if err := ensureQuarantinedLeaf(root, quarantine, captured, want, verify); err != nil {
		return err
	}
	if barrier != nil {
		barrier("pre-unlink", quarantine)
	}
	// FINAL identity re-check immediately before the unlink.
	if err := ensureQuarantinedLeaf(root, quarantine, captured, want, verify); err != nil {
		return err
	}
	if err := root.Remove(quarantine); err != nil && !os.IsNotExist(err) {
		return spoolErr(spoolErrGeneric, err)
	}
	if syncDir != nil {
		if err := syncDir(); err != nil {
			return err
		}
	}
	return nil
}

// resumeQuarantine finishes a pending quarantine left by a prior crash-faulted
// rename (the managed name is already free and this call stays off that
// mutable name entirely). If the quarantine is absent it is a NO-OP. A
// quarantine that does not authenticate (foreign or unowned content) is NEVER
// deleted; it is retained and an error is returned.
func (sp *spool) resumeQuarantine(quarantine string, verify func(st os.FileInfo, f *os.File) error, syncDir func() error, barrier func(phase, name string)) error {
	root := sp.root
	if _, err := root.Lstat(quarantine); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return spoolErr(spoolErrGeneric, err)
	}
	qFi, lerr := root.Lstat(quarantine)
	if lerr != nil {
		return spoolErr(spoolErrGeneric, lerr)
	}
	return authAndUnlinkQuarantine(root, quarantine, qFi, nil, verify, syncDir, barrier)
}

// ensureQuarantinedLeaf verifies the entry at name is a real regular,
// non-symlink, exact-0600 file whose inode is SameFile against both `captured`
// (the inode the rename moved / is resuming) and `want` (the owned or observed
// identity, when non-nil) and against the opened descriptor, and which
// satisfies `verify`. Used both for the authentication decision and for the
// identity re-check immediately before the final unlink.
func ensureQuarantinedLeaf(root *os.Root, name string, captured, want os.FileInfo, verify func(st os.FileInfo, f *os.File) error) error {
	fi, err := root.Lstat(name)
	if err != nil {
		return spoolErr(spoolErrGeneric, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return spoolErr(spoolErrGeneric, errors.New("quarantine path is a symbolic link"))
	}
	if !fi.Mode().IsRegular() {
		return spoolErr(spoolErrGeneric, errors.New("quarantine path is not a regular file"))
	}
	if p := fi.Mode().Perm(); p != 0o600 {
		return spoolErr(spoolErrGeneric, fmt.Errorf("quarantine mode %o is not exact 0600", p))
	}
	if captured != nil && !os.SameFile(captured, fi) {
		return spoolErr(spoolErrGeneric, errors.New("quarantine does not match the captured inode"))
	}
	f, err := root.OpenFile(name, os.O_RDONLY, 0) // os.Root uses O_NOFOLLOW
	if err != nil {
		return spoolErr(spoolErrGeneric, err)
	}
	st, serr := f.Stat()
	if serr != nil || !st.Mode().IsRegular() {
		f.Close()
		return spoolErr(spoolErrGeneric, errors.New("opened quarantine is not a regular file"))
	}
	if !os.SameFile(fi, st) {
		f.Close()
		return spoolErr(spoolErrGeneric, errors.New("quarantine changed between stat and open"))
	}
	if want != nil && !os.SameFile(want, st) {
		f.Close()
		return spoolErr(spoolErrGeneric, errors.New("quarantine identity does not match the owned object"))
	}
	if verify != nil {
		if verr := verify(st, f); verr != nil {
			f.Close()
			return spoolErr(spoolErrGeneric, verr)
		}
	}
	return f.Close()
}

// restoreQuarantine moves a quarantined entry back to its managed name ONLY
// when that name is currently FREE (never clobbering); when it is occupied the
// entry is retained at the private quarantine name and restore reports false.
func restoreQuarantine(root *os.Root, quarantine, managed string) bool {
	if _, err := root.Lstat(managed); err != nil {
		if !os.IsNotExist(err) {
			return false
		}
	} else {
		return false // occupied: never clobber; keep it quarantined
	}
	return root.Rename(quarantine, managed) == nil
}

// quarantineCreated is the created-object failure cleanup: it atomically
// quarantines a leaf the CALLER just created (O_EXCL) and authenticates it
// against the retained created descriptor identity. A foreign replacement
// occupying the name is never removed and never clobbered. Used by createName
// and createDBFile. The directory is fsynced after every rename/unlink.
func quarantineCreated(root *os.Root, managed string, created os.FileInfo, syncDir func() error, barrier func(phase, name string)) error {
	if created == nil {
		// No created identity to authenticate against: never remove a name.
		return nil
	}
	if barrier != nil {
		barrier("pre-rename", managed)
	}
	// Atomic capture then authenticate against the created inode.
	_, err := quarantineUnlinkRoot(root, managed, quarantineForManaged(managed), created,
		func(st os.FileInfo, f *os.File) error { return nil }, // identity + regular/0600 suffice
		syncDir, barrier)
	if err != nil {
		// The quarantined leaf did not match the created identity (a swap
		// replaced it) or the destination was occupied: the foreign or
		// replacement object is preserved and the cleanup fails closed.
		return err
	}
	return nil
}

// createName is the shared O_EXCL create path: validate the caller-supplied
// name derives from a validated id, create it exactly 0600 (fchmod on the
// descriptor, umask-provable), verify by the opened descriptor AND by the
// anchored directory entry, and reject any pre-existing entry (file,
// symlink, or directory) outright. On failure the residue cleaned up is
// ONLY the inode the O_EXCL created for us — a swapped-in foreign
// replacement is never removed (removeNameGuarded).
func (sp *spool) createName(name string) (*os.File, error) {
	if err := sp.ensureRootMode(); err != nil {
		return nil, err
	}
	f, err := sp.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, spoolErr(spoolErrGeneric, err)
	}
	// Immediate chmod on the descriptor, then exact verification —
	// regardless of umask. The cleaned-up residue is always OUR inode,
	// authenticated against it by the atomic quarantine protocol (never a
	// check-then-name unlink).
	cleanup := func(e error) (*os.File, error) {
		st, serr := f.Stat()
		_ = f.Close()
		if serr == nil {
			_ = quarantineCreated(sp.root, name, st, func() error { return sp.syncDir() }, nil)
		}
		return nil, e
	}
	if err := f.Chmod(0o600); err != nil {
		return cleanup(spoolErr(spoolErrGeneric, err))
	}
	st, err := f.Stat()
	if err != nil {
		return cleanup(spoolErr(spoolErrGeneric, err))
	}
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0o600 {
		return cleanup(spoolErr(spoolErrGeneric, errors.New("spool file is not an exact 0600 regular file")))
	}
	// Descriptor identity: no swap between creation and hand-off.
	lst, err := sp.root.Lstat(name)
	if err != nil || !os.SameFile(st, lst) || lst.Mode()&os.ModeSymlink != 0 {
		return cleanup(spoolErr(spoolErrGeneric, errors.New("spool file changed during creation")))
	}
	return f, nil
}

// readTokExact reads exactly n bytes from the token file of a validated id,
// proving first through the anchored descriptor that the entry is a
// symlink-free regular file of exactly that size and refusing any extra
// byte. It is used to attribute a creating session through its unforgeable
// token; an empty, short, long, symlinked, or wrong-identity token file is
// an error and is NEVER touched.
func (sp *spool) readTokExact(id string, n int64) ([]byte, error) {
	return sp.readNameExact(tokName(id), n)
}

// readNameExact is the shared size-exact read used for attribution checks.
func (sp *spool) readNameExact(name string, n int64) ([]byte, error) {
	fi, err := sp.root.Lstat(name)
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
	if fi.Size() != n {
		return nil, spoolErr(spoolErrShort, errors.New("spool file size does not match the expected lobe"))
	}
	f, err := sp.root.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		return nil, spoolErr(spoolErrGeneric, err)
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() != n || !os.SameFile(st, fi) {
		f.Close()
		return nil, spoolErr(spoolErrNotRegular, errors.New("opened spool path is not the verified file"))
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(f, buf); err != nil {
		f.Close()
		return nil, spoolErr(spoolErrGeneric, err)
	}
	// The lobe must be exact: an extra byte (concurrent extension or swap)
	// fails closed.
	var probe [1]byte
	if m, err := f.Read(probe[:]); err != io.EOF || m != 0 {
		f.Close()
		return nil, spoolErr(spoolErrShort, errors.New("spool file carries more bytes than expected"))
	}
	f.Close()
	return buf, nil
}

// tokInfo reports whether the token file for a validated id exists and its
// file info, through the anchored descriptor.
func (sp *spool) tokInfo(id string) (os.FileInfo, bool, error) {
	return sp.nameInfo(tokName(id))
}

// nameInfo reports whether an internal spool name exists, through the
// anchored descriptor and never following symlinks.
func (sp *spool) nameInfo(name string) (os.FileInfo, bool, error) {
	fi, err := sp.root.Lstat(name)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, spoolErr(spoolErrGeneric, err)
	}
	return fi, true, nil
}
func repairFileMode(f *os.File) error {
	st, err := f.Stat()
	if err != nil {
		return spoolErr(spoolErrGeneric, err)
	}
	if !st.Mode().IsRegular() {
		return spoolErr(spoolErrNotRegular, errors.New("opened spool path is not a regular file"))
	}
	if st.Mode().Perm() == 0o600 {
		return nil
	}
	if err := f.Chmod(0o600); err != nil {
		return spoolErr(spoolErrGeneric, errors.New("cannot make spool file private"))
	}
	st, err = f.Stat()
	if err != nil {
		return spoolErr(spoolErrGeneric, err)
	}
	if st.Mode().Perm() != 0o600 {
		return spoolErr(spoolErrGeneric, errors.New("spool file mode repair failed"))
	}
	return nil
}

// openFile is the single descriptor-relative open path: one Lstat captures
// the expected identity, every subsequent open is verified SameFile against
// it, the exact mode 0600 is verified and repaired through the descriptor on
// EVERY existing-file open, an overlong crash tail is truncated through the
// fd AND the truncation is fsynced (a sync failure propagates before any
// success), a shorter file fails closed, and the returned descriptor is
// positioned at offset.
func (sp *spool) openFile(id string, offset int64, flag int) (*os.File, error) {
	if err := validateID(id); err != nil {
		return nil, err
	}
	if err := sp.ensureRootMode(); err != nil {
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
		// ftruncate requires a writable descriptor. The mode is verified and
		// repaired here too; the truncation is made durable BEFORE the
		// operation reports success.
		tf, err := sp.root.OpenFile(id, os.O_WRONLY, 0)
		if err != nil {
			return nil, spoolErr(spoolErrGeneric, err)
		}
		st, err := tf.Stat()
		if err != nil {
			tf.Close()
			return nil, spoolErr(spoolErrGeneric, err)
		}
		if !st.Mode().IsRegular() || !os.SameFile(st, fi) {
			tf.Close()
			return nil, spoolErr(spoolErrNotRegular, errors.New("opened spool path is not the verified file"))
		}
		if err := repairFileMode(tf); err != nil {
			tf.Close()
			return nil, err
		}
		if st.Size() < offset {
			tf.Close()
			return nil, spoolErr(spoolErrShort, errors.New("opened spool file is shorter than the committed offset"))
		}
		if err := tf.Truncate(offset); err != nil {
			tf.Close()
			return nil, spoolErr(spoolErrGeneric, err)
		}
		// Durable truncation: the tail must be gone from stable storage
		// before success is acknowledged.
		if sp.syncFile != nil {
			if err := sp.syncFile(tf); err != nil {
				tf.Close()
				return nil, spoolErr(spoolErrGeneric, err)
			}
		} else if err := tf.Sync(); err != nil {
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
	if err := repairFileMode(f); err != nil {
		f.Close()
		return nil, err
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

// align verifies the spool file at id is a regular, symlink-free,
// exactly-0600 file whose durable bytes are at least offset; a longer file
// is an uncommitted crash tail and is truncated back to offset with a
// durable sync. A shorter file means the database is ahead of durable file
// bytes and fails closed.
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

// readExact reads exactly n bytes from the spool file at id, first proving
// through the anchored descriptor that the entry is a symlink-free regular
// file of exactly that size, and refusing any extra byte. It is used to
// attribute a creating file through its unforgeable token; an empty, short,
// long, symlinked, or wrong-identity file is an error and is NEVER touched.
func (sp *spool) readExact(id string, n int64) ([]byte, error) {
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
	if fi.Size() != n {
		return nil, spoolErr(spoolErrShort, errors.New("spool file size does not match the expected lobe"))
	}
	f, err := sp.root.OpenFile(id, os.O_RDONLY, 0)
	if err != nil {
		return nil, spoolErr(spoolErrGeneric, err)
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() != n || !os.SameFile(st, fi) {
		f.Close()
		return nil, spoolErr(spoolErrNotRegular, errors.New("opened spool path is not the verified file"))
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(f, buf); err != nil {
		f.Close()
		return nil, spoolErr(spoolErrGeneric, err)
	}
	// The lobe must be exact: an extra byte (concurrent extension or swap)
	// fails closed.
	var probe [1]byte
	if m, err := f.Read(probe[:]); err != io.EOF || m != 0 {
		f.Close()
		return nil, spoolErr(spoolErrShort, errors.New("spool file carries more bytes than expected"))
	}
	f.Close()
	return buf, nil
}

// syncDir fsyncs the spool root directory through the retained descriptor,
// making a just-created or just-unlinked entry durable.
func (sp *spool) syncDir() error {
	if err := sp.ensureRootMode(); err != nil {
		return err
	}
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
	if err := sp.ensureRootMode(); err != nil {
		return nil, err
	}
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
