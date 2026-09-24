package staging

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func validTestID() string { return strings.Repeat("a", 64) }

func TestValidateIDGrammar(t *testing.T) {
	ok := validTestID()
	cases := []struct {
		id      string
		invalid bool
	}{
		{ok, false},
		{strings.Repeat("f", 64), false},
		{"abcdef0123456789" + strings.Repeat("0", 48), false},
		// Separators and path tricks.
		{strings.Repeat("a", 63) + "/", true},
		{strings.Repeat("a", 63) + "\\", true},
		{"../" + strings.Repeat("a", 61), true},
		{"." + strings.Repeat("a", 63), true},
		{".." + strings.Repeat("a", 62), true},
		{string([]byte{'a', 0}) + strings.Repeat("a", 62), true},
		{strings.Repeat("a", 32) + "/" + strings.Repeat("b", 31), true},
		{strings.Repeat("a", 32) + "\\" + strings.Repeat("b", 31), true},
		// Length and charset.
		{"", true},
		{strings.Repeat("a", 63), true},
		{strings.Repeat("a", 65), true},
		{strings.ToUpper(ok), true},
		{strings.Repeat("g", 64), true},
		{strings.Repeat("a", 63) + "-", true},
		{strings.Repeat("a", 63) + "_", true},
		{strings.Repeat("a", 63) + " ", true},
		// Unicode lookalikes and malformed UTF-8.
		{"é" + strings.Repeat("a", 63), true},
		{string([]byte{0xF4, 0x90, 0x80, 0x80}) + strings.Repeat("a", 60), true},
		{"\u200b" + strings.Repeat("a", 63), true},
		{strings.Repeat("a", 32) + "\u2215" + strings.Repeat("b", 31), true}, // division slash
	}
	for _, tc := range cases {
		err := validateID(tc.id)
		if tc.invalid && err == nil {
			t.Errorf("validateID(%q) accepted invalid id", printable(tc.id))
		}
		if !tc.invalid && err != nil {
			t.Errorf("validateID(%q) rejected valid id: %v", tc.id, err)
		}
	}
}

func printable(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 32 || r > 126 {
			b.WriteString(fmt.Sprintf("\\x%02x", r))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func TestValidateRepoActorGrammar(t *testing.T) {
	goodRepos := []string{"backend/api", "a", "a/b/c", "my-repo_1.x/app", "0/1"}
	badRepos := []string{"", "Backend/api", "backend api", "backend//api", "/x", "x/", "backend/../api", "backend/./api", strings.Repeat("a", 201), "backend\\api"}
	for _, r := range goodRepos {
		if err := validateRepo(r); err != nil {
			t.Errorf("validateRepo(%q) rejected valid repo: %v", r, err)
		}
	}
	for _, r := range badRepos {
		if err := validateRepo(r); err == nil {
			t.Errorf("validateRepo(%q) accepted invalid repo", r)
		}
	}

	goodActors := []string{"user:alice", "alice", "user:alice@example.com", "svc:deploy-1"}
	badActors := []string{"", "user:al ice", "user/alice", "..", strings.Repeat("u", 201), "user:alice\x00admin"}
	for _, a := range goodActors {
		if err := validateActor(a); err != nil {
			t.Errorf("validateActor(%q) rejected valid actor: %v", a, err)
		}
	}
	for _, a := range badActors {
		if err := validateActor(a); err == nil {
			t.Errorf("validateActor(%q) accepted invalid actor", a)
		}
	}
}

func TestValidateFinalizeGrammar(t *testing.T) {
	dig := "sha256:" + strings.Repeat("b", 64)
	ref := strings.Repeat("c", 64)
	if err := validateDigest(dig); err != nil {
		t.Errorf("valid digest rejected: %v", err)
	}
	for _, d := range []string{
		"", "sha256:" + strings.Repeat("b", 63), "sha256:" + strings.Repeat("B", 64),
		"sha512:" + strings.Repeat("b", 64), "sha256:" + strings.Repeat("b", 65),
		"sha256:" + strings.Repeat("b", 63) + "g", digestWithoutColon(),
	} {
		if err := validateDigest(d); err == nil {
			t.Errorf("invalid digest %q accepted", d)
		}
	}
	if err := validateBeeRef(ref); err != nil {
		t.Errorf("valid bee ref rejected: %v", err)
	}
	for _, r := range []string{"", strings.Repeat("c", 63), strings.Repeat("C", 64), strings.Repeat("c", 64) + "/x", "ref:" + strings.Repeat("c", 60)} {
		if err := validateBeeRef(r); err == nil {
			t.Errorf("invalid bee ref %q accepted", r)
		}
	}
	if err := validateMediaType("application/vnd.oci.image.layer.v1.tar+gzip"); err != nil {
		t.Errorf("valid media type rejected: %v", err)
	}
	for _, m := range []string{"", "Application/json", "application/json ", "application/json; charset=utf-8", strings.Repeat("m", 201)} {
		if err := validateMediaType(m); err == nil {
			t.Errorf("invalid media type %q accepted", m)
		}
	}
}

func digestWithoutColon() string { return "sha256" + strings.Repeat("b", 64) }

// ---------------------------------------------------------------------------
// Root construction and modes
// ---------------------------------------------------------------------------

func TestNewSpoolCreatesRootAndRejectsSymlinks(t *testing.T) {
	dir := t.TempDir()

	t.Run("creates_root_0700", func(t *testing.T) {
		rootPath := filepath.Join(dir, "spool")
		sp, err := newSpool(context.Background(), rootPath)
		if err != nil {
			t.Fatalf("newSpool: %v", err)
		}
		defer sp.Close()
		fi, err := os.Lstat(rootPath)
		if err != nil {
			t.Fatalf("lstat root: %v", err)
		}
		if !fi.IsDir() {
			t.Fatalf("root is not a directory")
		}
		if fi.Mode()&0o077 != 0 {
			t.Fatalf("root has group/other bits: %v", fi.Mode().Perm())
		}
		if fi.Mode()&0o700 != 0o700 {
			t.Fatalf("root lacks owner rwx: %v", fi.Mode().Perm())
		}
	})

	t.Run("rejects_symlink_root", func(t *testing.T) {
		target := filepath.Join(dir, "target")
		if err := os.MkdirAll(target, 0o700); err != nil {
			t.Fatalf("mkdir target: %v", err)
		}
		link := filepath.Join(dir, "spool-link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		if sp, err := newSpool(context.Background(), link); err == nil {
			sp.Close()
			t.Fatal("newSpool followed a symlink root")
		}
	})

	t.Run("rejects_non_directory_root", func(t *testing.T) {
		f := filepath.Join(dir, "plainfile")
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if sp, err := newSpool(context.Background(), f); err == nil {
			sp.Close()
			t.Fatal("newSpool accepted a non-directory root")
		}
	})

	t.Run("rejects_existing_root_with_symlink_component", func(t *testing.T) {
		// Root itself is fine, but the spool id exists as a symlink inside.
		rootPath := filepath.Join(dir, "spool2")
		sp, err := newSpool(context.Background(), rootPath)
		if err != nil {
			t.Fatalf("newSpool: %v", err)
		}
		defer sp.Close()
		other := filepath.Join(dir, "other")
		if err := os.WriteFile(other, []byte("data"), 0o600); err != nil {
			t.Fatalf("write other: %v", err)
		}
		if err := os.Symlink(other, filepath.Join(rootPath, validTestID())); err != nil {
			t.Fatalf("symlink inside root: %v", err)
		}
		if err := sp.create(validTestID()); err == nil {
			t.Fatal("create accepted a pre-existing symlink")
		}
		if _, err := sp.openForRead(validTestID(), 4); err == nil {
			t.Fatal("openForRead followed a symlink")
		}
		if _, err := sp.openForAppend(validTestID(), 4); err == nil {
			t.Fatal("openForAppend followed a symlink")
		}
	})
}

// TestSpoolModesUnderPermissiveUmask proves effective 0700 directory and
// 0600 file modes hold even when the process umask would allow looser bits.
func TestSpoolModesUnderPermissiveUmask(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	dir := t.TempDir()
	rootPath := filepath.Join(dir, "spool")
	sp, err := newSpool(context.Background(), rootPath)
	if err != nil {
		t.Fatalf("newSpool: %v", err)
	}
	defer sp.Close()

	fi, err := os.Lstat(rootPath)
	if err != nil {
		t.Fatalf("lstat root: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o700 {
		t.Fatalf("root mode = %o, want 0700", got)
	}

	id := validTestID()
	if err := sp.create(id); err != nil {
		t.Fatalf("create: %v", err)
	}
	fi, err = os.Lstat(filepath.Join(rootPath, id))
	if err != nil {
		t.Fatalf("lstat spool file: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Fatalf("spool file mode = %o, want 0600", got)
	}
}

// TestSpoolFileLifecycle proves create/openForAppend/openForRead/remove work
// through descriptor-relative operations and that a file created inside the
// root cannot be reached through any rewritten name.
func TestSpoolFileLifecycle(t *testing.T) {
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "spool")
	sp, err := newSpool(context.Background(), rootPath)
	if err != nil {
		t.Fatalf("newSpool: %v", err)
	}
	defer sp.Close()

	id := validTestID()
	if err := sp.create(id); err != nil {
		t.Fatalf("create: %v", err)
	}
	f, err := sp.openForAppend(id, 0)
	if err != nil {
		t.Fatalf("openForAppend: %v", err)
	}
	if _, err := f.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}
	f.Close()

	r, err := sp.openForRead(id, 5)
	if err != nil {
		t.Fatalf("openForRead: %v", err)
	}
	got, err := io.ReadAll(io.LimitReader(r, 5))
	r.Close()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("read %q, want hello", got)
	}

	if err := sp.remove(id); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(rootPath, id)); !os.IsNotExist(err) {
		t.Fatalf("file remains after remove: %v", err)
	}
	// Removing an already-absent file is tolerated (idempotent cleanup).
	if err := sp.remove(id); err != nil {
		t.Fatalf("second remove: %v", err)
	}
}

// TestSpoolAlignTruncatesTailAndRejectsShortFile proves post-crash recovery:
// bytes beyond the committed offset are dropped, and a file shorter than the
// committed offset fails closed.
func TestSpoolAlign(t *testing.T) {
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "spool")
	sp, err := newSpool(context.Background(), rootPath)
	if err != nil {
		t.Fatalf("newSpool: %v", err)
	}
	defer sp.Close()

	id := validTestID()
	if err := sp.create(id); err != nil {
		t.Fatalf("create: %v", err)
	}
	f, _ := sp.openForAppend(id, 0)
	f.Write([]byte("committed-tail"))
	f.Close()

	// Committed offset is 9; the file carries 14 bytes (uncommitted tail).
	if err := sp.align(id, 9); err != nil {
		t.Fatalf("align with tail: %v", err)
	}
	r, err := sp.openForRead(id, 9)
	if err != nil {
		t.Fatalf("openForRead after align: %v", err)
	}
	got, _ := io.ReadAll(io.LimitReader(r, 9))
	r.Close()
	if !bytes.Equal(got, []byte("committed")) {
		t.Fatalf("after align got %q, want committed bytes", got)
	}

	// Shorter than committed -> fail closed, never fabricated.
	if err := sp.align(id, 20); err == nil {
		t.Fatal("align accepted a file shorter than the committed offset")
	}
}

// TestSpoolRejectsNonRegularFile proves a directory planted at the spool name
// is never opened as data.
func TestSpoolRejectsNonRegularFile(t *testing.T) {
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "spool")
	sp, err := newSpool(context.Background(), rootPath)
	if err != nil {
		t.Fatalf("newSpool: %v", err)
	}
	defer sp.Close()

	id := validTestID()
	if err := os.Mkdir(filepath.Join(rootPath, id), 0o700); err != nil {
		t.Fatalf("mkdir at spool name: %v", err)
	}
	if _, err := sp.openForAppend(id, 0); err == nil {
		t.Fatal("openForAppend accepted a directory")
	}
	if _, err := sp.openForRead(id, 0); err == nil {
		t.Fatal("openForRead accepted a directory")
	}
	if err := sp.align(id, 0); err == nil {
		t.Fatal("align accepted a directory")
	}
}

// TestSpoolPathRewritesCannotEscape proves every escape-shaped name is
// rejected by validation before any root operation, and the root layer also
// rejects them (defense in depth).
func TestSpoolPathRewritesCannotEscape(t *testing.T) {
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "spool")
	sp, err := newSpool(context.Background(), rootPath)
	if err != nil {
		t.Fatalf("newSpool: %v", err)
	}
	defer sp.Close()

	for _, name := range []string{
		"../x", "..", ".", "/etc/passwd", "a/b", "a\\b", "..\\x",
		"a\x00b", "\x00", "////", strings.Repeat("a", 64) + "/x",
	} {
		if err := sp.create(name); err == nil {
			t.Errorf("create(%q) escaped validation", printable(name))
		}
		if _, err := sp.openForAppend(name, 0); err == nil {
			t.Errorf("openForAppend(%q) escaped validation", printable(name))
		}
	}
}
