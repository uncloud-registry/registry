package staging

// Umask isolation: every umask-sensitive scenario runs in a fresh SUBPROCESS
// (an exec.Command of this very test binary), so the process-global umask is
// never mutated by the main test binary — including under -race, where
// concurrent main-process umask mutation would be fragile and could leak to
// unrelated tests. The scenarios prove:
//
//  1. constructor-time mkdir never alters the process umask for an unrelated
//     concurrent file (the core regression),
//  2. a permissive umask still yields EXACT 0700 directories and 0600 files
//     (modes are forced, not delegated to the umask),
//  3. a restrictive umask (077, 0777) yields EXACT private modes through
//     anchored, no-follow descriptor repair, and a failed fresh-DB creation
//     leaves no mode-000 residue.
//
// The subprocess is race-clean, so the parent race suite (ordinary code in
// the main process) still exercises these scenarios without skipping the
// concurrency invariant merely because umask is process-global.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// umaskSubprocEnv selects the subprocess scenario; when empty the test is the
// spawning parent.
const umaskSubprocEnv = "REGISTRY_STAGING_UMASK_SUBPROC"

// runUmaskSubproc re-executes this test binary in a fresh process, running
// only wrapTest with umaskSubprocEnv=<scenario>. The child owns any umask
// mutation; the parent keeps the process-global umask untouched.
func runUmaskSubproc(t *testing.T, scenario, wrapTest string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+wrapTest+"$", "-test.v")
	cmd.Env = append(os.Environ(), umaskSubprocEnv+"="+scenario)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("umask subprocess [%s] failed: %v\n%s", scenario, err, out)
	}
	if testing.Verbose() {
		t.Logf("umask subprocess [%s]:\n%s", scenario, out)
	}
}

// dispatch splits a test between the spawning parent and the child scenario.
func dispatchUmask(t *testing.T, wrapTest, scenario string, fn func(*testing.T)) {
	t.Helper()
	switch env := os.Getenv(umaskSubprocEnv); env {
	case "":
		runUmaskSubproc(t, scenario, wrapTest)
	case scenario:
		fn(t)
	default:
		t.Fatalf("unknown umask scenario %q", env)
	}
}

// ---------------------------------------------------------------------------
// CORE REGRESSION: constructor-time mkdir must not alter the process umask
// for an unrelated concurrent file.
// ---------------------------------------------------------------------------

// TestSpoolConstructorDoesNotTaintUmaskForConcurrentFile is the behavioral
// regression for the process-global umask defect. On the pre-fix code
// mkdirPrivate called syscall.Umask(0) around the constructor's mkdir; an
// unrelated goroutine creating a file (0666) in that window saw umask 0 and
// landed as 0666 instead of 0644. The scenario runs in a subprocess with an
// ordinary 022 umask and a concurrent creator hammering file creation while
// hundreds of constructor-time mkdirs happen; any 0666 observation fails it.
func TestSpoolConstructorDoesNotTaintUmaskForConcurrentFile(t *testing.T) {
	dispatchUmask(t, "TestSpoolConstructorDoesNotTaintUmaskForConcurrentFile",
		"concurrent", scenarioConstructorConcurrentFile)
}

func scenarioConstructorConcurrentFile(t *testing.T) {
	dir := tempPrivate(t)
	syscall.Umask(0o022) // ordinary process umask inside the isolated child

	scratch := filepath.Join(dir, "scratch")
	if err := os.Mkdir(scratch, 0o700); err != nil {
		t.Fatalf("mkdir scratch: %v", err)
	}

	leak := make(chan error, 1) // nil-free; a send means the invariant broke
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	// Unrelated concurrent file: created 0666, so the ordinary 022 umask must
	// reduce it to EXACTLY 0644. If the constructor's mkdir momentarily
	// cleared the process umask, an in-window create would land as 0666.
	go func() {
		defer wg.Done()
		path := filepath.Join(scratch, "creep")
		for {
			select {
			case <-stop:
				return
			default:
			}
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o666)
			if err != nil {
				continue // transient; retry
			}
			st, serr := f.Stat()
			_ = f.Close()
			if serr == nil && st.Mode().Perm() != 0o644 {
				select {
				case leak <- errors.New("unrelated concurrent file created with mode " +
					strconv.FormatUint(uint64(st.Mode().Perm()), 8) +
					"; constructor must not clear the process umask"):
				default:
				}
				_ = os.Remove(path)
				return
			}
			_ = os.Remove(path)
		}
	}()

	// Enough constructor-time mkdirs (each creates a fresh 0700 component) to
	// expose any process-global umask mutation to the concurrent creator.
	for i := 0; i < 500; i++ {
		sp, err := newSpool(context.Background(), filepath.Join(dir, strconv.Itoa(i)))
		if err != nil {
			t.Fatalf("newSpool %d: %v", i, err)
		}
		_ = sp.Close()
	}

	close(stop)
	wg.Wait()
	select {
	case err := <-leak:
		t.Fatal(err)
	default:
	}
}

// ---------------------------------------------------------------------------
// Permissive umask: exact 0700 dir / 0600 file modes are forced by the code.
// ---------------------------------------------------------------------------

func TestUmaskPermissiveSpoolModesExact(t *testing.T) {
	dispatchUmask(t, "TestUmaskPermissiveSpoolModesExact", "permissive", scenarioPermissiveSpoolModes)
}

func scenarioPermissiveSpoolModes(t *testing.T) {
	dir := tempPrivate(t)
	syscall.Umask(0) // permissive: exactness must come from the code, not the umask
	rootPath := filepath.Join(dir, "spool")
	sp, err := newSpool(context.Background(), rootPath)
	if err != nil {
		t.Fatalf("newSpool: %v", err)
	}
	defer func() { _ = sp.Close() }()
	assertMode(t, rootPath, true, 0o700)

	id := validTestID()
	f, err := sp.create(id)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_ = f.Close()
	assertMode(t, filepath.Join(rootPath, id), false, 0o600)
}

// ---------------------------------------------------------------------------
// Restrictive umask 0777: the constructor still yields EXACT 0700 dirs and
// 0600 db/file modes (rebased through the anchored no-follow repair), and a
// session can be created.
// ---------------------------------------------------------------------------

func TestUmaskRestrictiveConstructorExactModes(t *testing.T) {
	dispatchUmask(t, "TestUmaskRestrictiveConstructorExactModes", "restrictive777", scenarioRestrictiveConstructor)
}

func scenarioRestrictiveConstructor(t *testing.T) {
	dir := tempPrivate(t)
	syscall.Umask(0o777)
	spoolDir := filepath.Join(dir, "spool")
	dbPath := filepath.Join(dir, "staging.db")
	svc, err := NewService(context.Background(), spoolDir, dbPath)
	if err != nil {
		t.Fatalf("constructor under umask 0777: %v", err)
	}
	defer func() { _ = svc.Close() }()
	assertMode(t, spoolDir, true, 0o700)
	assertMode(t, dbPath, false, 0o600)
	s := mustCreate(t, svc, "backend/api", "user:alice")
	assertMode(t, filepath.Join(spoolDir, s.ID), false, 0o600)
}

// ---------------------------------------------------------------------------
// Restrictive umask 077: spool files are repaired to EXACT 0600 and the root
// stays 0700.
// ---------------------------------------------------------------------------

func TestUmaskRestrictiveSpoolFileMode077(t *testing.T) {
	dispatchUmask(t, "TestUmaskRestrictiveSpoolFileMode077", "restrictive077", scenarioSpoolMode077)
}

func scenarioSpoolMode077(t *testing.T) {
	dir := tempPrivate(t)
	syscall.Umask(0o077)
	sp, err := newSpool(context.Background(), filepath.Join(dir, "spool"))
	if err != nil {
		t.Fatalf("newSpool: %v", err)
	}
	defer func() { _ = sp.Close() }()
	id := strings.Repeat("33", 32)
	f, err := sp.create(id)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := f.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}
	_ = f.Close()
	fi, err := sp.root.Lstat(id)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if p := fi.Mode().Perm(); p != 0o600 {
		t.Fatalf("spool file mode %o, want 0600", p)
	}
	assertMode(t, filepath.Join(dir, "spool"), true, 0o700)
}

// ---------------------------------------------------------------------------
// Restrictive umask 0777 at the fresh-DB boundary.
// ---------------------------------------------------------------------------

func TestUmaskRestrictiveFreshDB0777(t *testing.T) {
	dispatchUmask(t, "TestUmaskRestrictiveFreshDB0777", "freshDB777", scenarioFreshDB777)
}

func scenarioFreshDB777(t *testing.T) {
	dir := tempPrivate(t)
	syscall.Umask(0o777)
	spoolDir := filepath.Join(dir, "spool")
	dbPath := filepath.Join(dir, "staging.db")
	svc, err := NewService(context.Background(), spoolDir, dbPath)
	if err != nil {
		t.Fatalf("fresh DB under umask 0777: %v", err)
	}
	defer func() { _ = svc.Close() }()
	assertMode(t, dbPath, false, 0o600)
	mustCreate(t, svc, "backend/api", "user:alice")
}

func TestUmaskRestrictiveNoMode000Residue(t *testing.T) {
	dispatchUmask(t, "TestUmaskRestrictiveNoMode000Residue", "noMode000", scenarioNoMode000Residue)
}

func scenarioNoMode000Residue(t *testing.T) {
	dir := tempPrivate(t)
	syscall.Umask(0o777)
	dbPath := filepath.Join(dir, "staging.db")
	migrationFault = errors.New("injected migration fault")
	defer func() { migrationFault = nil }()
	svc, err := NewService(context.Background(), filepath.Join(dir, "spool"), dbPath)
	if err == nil {
		_ = svc.Close()
		t.Fatal("constructor accepted the faulted migration")
	}
	if !errors.Is(err, ErrDependency) {
		t.Fatalf("constructor error: %v, want ErrDependency", err)
	}
	if fi, lerr := os.Lstat(dbPath); lerr == nil && fi.Mode().Perm() == 0 {
		t.Fatal("mode-000 residue left on failed database creation")
	}
}

func assertMode(t *testing.T, path string, dir bool, want os.FileMode) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat %s: %v", path, err)
	}
	if dir && !fi.IsDir() {
		t.Fatalf("%s is not a directory", path)
	}
	if !dir && !fi.Mode().IsRegular() {
		t.Fatalf("%s is not a regular file", path)
	}
	if p := fi.Mode().Perm(); p != want {
		t.Fatalf("mode %o on %s, want %o", p, path, want)
	}
}
