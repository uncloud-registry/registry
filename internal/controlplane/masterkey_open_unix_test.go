//go:build darwin || linux

package controlplane

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestLoadMasterKeyFileParsesOpenedDescriptor pins the TOCTOU fix: the loader
// opens the path exactly once and validates/reads THAT descriptor. Replacing
// the path's content after the open cannot redirect what gets parsed — the
// parsed cipher must come from the originally opened bytes.
func TestLoadMasterKeyFileParsesOpenedDescriptor(t *testing.T) {
	t.Parallel()
	original := masterKeyDocument("1", map[string]string{"1": testMasterKeyB64(1)})
	swapped := masterKeyDocument("1", map[string]string{"1": testMasterKeyB64(9)})

	path := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	f, err := openMasterKeyFile(path)
	if err != nil {
		t.Fatalf("openMasterKeyFile: %v", err)
	}
	defer f.Close()

	// Swap the PATH (directory entry) while the descriptor is still open: the
	// original file is renamed away and replaced via atomic rename, so the open
	// descriptor keeps pointing at the ORIGINAL inode. A path-reopening
	// implementation would read the swapped content; the descriptor-based
	// implementation must parse the original bytes.
	swappedPath := filepath.Join(t.TempDir(), "swapped.json")
	if err := os.WriteFile(swappedPath, []byte(swapped), 0o600); err != nil {
		t.Fatalf("swap write: %v", err)
	}
	if err := os.Rename(swappedPath, path); err != nil {
		t.Fatalf("rename swap: %v", err)
	}
	data, err := readMasterKeyDescriptor(f)
	if err != nil {
		t.Fatalf("readMasterKeyDescriptor: %v", err)
	}
	cipher, err := parseMasterKeyDocument(data)
	if err != nil {
		t.Fatalf("parseMasterKeyDocument: %v", err)
	}

	// The descriptor must have yielded the ORIGINAL key: encrypt+decrypt under
	// the swapped key would fail authentication against the original bytes.
	enc, err := cipher.Encrypt(1, "0xfeed", []byte("private-key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cipher.Decrypt(1, "0xfeed", enc); err != nil {
		t.Fatalf("opened descriptor must yield the ORIGINAL key: %v", err)
	}
	swappedCipher, err := NewFeedKeyCipher(map[int][]byte{1: testMasterKeyBytes(9)}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := swappedCipher.Decrypt(1, "0xfeed", enc); err == nil {
		t.Fatal("path swap after open must not redirect parsing to the new content")
	}
}

// TestLoadMasterKeyFileRejectsFIFO pins that a named pipe (a blocking/special
// file) is refused: O_NONBLOCK lets the open succeed without blocking, and the
// Fstat regular-file requirement rejects it before any read can block.
func TestLoadMasterKeyFileRejectsFIFO(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "pipe.json")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo not supported: %v", err)
	}
	if _, err := LoadMasterKeyFile(path); err == nil {
		t.Fatal("FIFO must be rejected as a non-regular file")
	}
}

// TestOpenMasterKeyFileRejectsSymlinkAtOpen pins that O_NOFOLLOW makes the
// open itself fail for a trailing symlink — no stat-then-open race exists.
func TestOpenMasterKeyFileRejectsSymlinkAtOpen(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "real.json")
	if err := os.WriteFile(target, []byte(masterKeyDocument("1", map[string]string{"1": testMasterKeyB64(1)})), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks not supported on this platform: %v", err)
	}
	if _, err := openMasterKeyFile(link); err == nil {
		t.Fatal("symlink must be refused at open time (O_NOFOLLOW)")
	}
}

func TestLoadMasterKeyFileRejectsDirectory(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "keydir")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMasterKeyFile(dir); err == nil {
		t.Fatal("directory must be rejected as a non-regular file")
	}
}

// TestLoadMasterKeyFileRejectsWritableModes pins the unix permission contract:
// the master key file must never be group- or world-writable. Readable modes
// are permitted; only the writable bits (022) are banned.
func TestLoadMasterKeyFileRejectsWritableModes(t *testing.T) {
	t.Parallel()
	doc := masterKeyDocument("1", map[string]string{"1": testMasterKeyB64(1)})
	cases := []struct {
		name    string
		mode    os.FileMode
		wantErr bool
	}{
		{"owner read-write", 0o600, false},
		{"owner read-only", 0o400, false},
		{"world readable", 0o644, false},
		{"group writable", 0o660, true},
		{"world writable", 0o602, true},
		{"group and world writable", 0o666, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key.json")
			if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
				t.Fatal(err)
			}
			// os.WriteFile applies the process umask, which can strip the very
			// writable bits the test targets; chmod enforces the exact mode.
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			}
			_, err := LoadMasterKeyFile(path)
			if tc.wantErr && err == nil {
				t.Fatalf("mode %04o must be rejected", tc.mode)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("mode %04o must load: %v", tc.mode, err)
			}
			if err != nil && strings.Contains(err.Error(), path) {
				t.Fatalf("error must not contain the path: %v", err)
			}
		})
	}
}

// TestLoadMasterKeyFileRejectsOversizedFile pins the hard size bound: a file
// beyond maxMasterKeyFileSize is refused before any parse.
func TestLoadMasterKeyFileRejectsOversizedFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "huge.json")
	// A valid document head followed by padding past the size bound: only the
	// size gate can reject this (it fires before parsing).
	head := []byte(`{"current":1,"keys":{"1":"` + testMasterKeyB64(1) + `"}}`)
	blob := make([]byte, maxMasterKeyFileSize+1)
	copy(blob, head)
	for i := len(head); i < len(blob); i++ {
		blob[i] = ' '
	}
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadMasterKeyFile(path)
	if err == nil {
		t.Fatal("oversized master key file must be rejected")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected the size-bound error, got: %v", err)
	}
	if strings.Contains(err.Error(), path) {
		t.Fatalf("size error must not contain the path: %v", err)
	}
}
