//go:build darwin || linux

package auth

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestLoadJWKSFromFileParsesOpenedDescriptor pins the TOCTOU fix: the loader
// opens the path exactly once and validates/reads THAT descriptor. Replacing
// the path's content after the open cannot redirect what gets parsed — the
// parsed key set must come from the originally opened bytes.
func TestLoadJWKSFromFileParsesOpenedDescriptor(t *testing.T) {
	t.Parallel()
	original := newJWKSTestKey(t, "orig-key")
	swapped := newJWKSTestKey(t, "swap-key")

	path := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(path, jwksDocument(original.jwkJSON), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	f, err := openJWKSFile(path)
	if err != nil {
		t.Fatalf("openJWKSFile: %v", err)
	}
	defer f.Close()

	// Swap the PATH (directory entry) while the descriptor is still open: the
	// original file is renamed away and replaced via atomic rename, so the open
	// descriptor keeps pointing at the ORIGINAL inode. A path-reopening
	// implementation would read the swapped content; the descriptor-based
	// implementation must parse the original bytes.
	swappedPath := filepath.Join(t.TempDir(), "swapped.json")
	if err := os.WriteFile(swappedPath, jwksDocument(swapped.jwkJSON), 0o644); err != nil {
		t.Fatalf("swap write: %v", err)
	}
	if err := os.Rename(swappedPath, path); err != nil {
		t.Fatalf("rename swap: %v", err)
	}
	data, err := readJWKSDescriptor(f, path)
	if err != nil {
		t.Fatalf("readJWKSDescriptor: %v", err)
	}
	set, err := ParseJWKS(data)
	if err != nil {
		t.Fatalf("ParseJWKS: %v", err)
	}

	if _, err := set.Key(context.Background(), original.kid); err != nil {
		t.Fatalf("opened descriptor must yield the ORIGINAL key: %v", err)
	}
	if _, err := set.Key(context.Background(), swapped.kid); err == nil {
		t.Fatal("path swap after open must not redirect parsing to the new content")
	}
}

// TestLoadJWKSFromFileRejectsFIFO pins that a named pipe (a blocking/special
// file) is refused: O_NONBLOCK lets the open succeed without blocking, and the
// Fstat regular-file requirement rejects it before any read can block.
func TestLoadJWKSFromFileRejectsFIFO(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "pipe.json")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo not supported: %v", err)
	}
	if _, err := LoadJWKSFromFile(path); err == nil {
		t.Fatal("FIFO must be rejected as a non-regular file")
	}
}

// TestOpenJWKSFileRejectsSymlinkAtOpen pins that O_NOFOLLOW makes the open
// itself fail for a trailing symlink — no stat-then-open race exists.
func TestOpenJWKSFileRejectsSymlinkAtOpen(t *testing.T) {
	t.Parallel()
	key := newJWKSTestKey(t, "link-k")
	dir := t.TempDir()
	target := filepath.Join(dir, "real.json")
	if err := os.WriteFile(target, jwksDocument(key.jwkJSON), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks not supported on this platform: %v", err)
	}
	if _, err := openJWKSFile(link); err == nil {
		t.Fatal("symlink must be refused at open time (O_NOFOLLOW)")
	}
}
