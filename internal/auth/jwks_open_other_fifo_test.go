//go:build freebsd || openbsd || netbsd || dragonfly || solaris

package auth

import (
	"errors"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestOpenJWKSFileFailsClosedDoesNotBlockOnFIFO proves the unsupported
// implementation never OPENS the path: a FIFO is a blocking special file, so a
// naively-opened descriptor would hang forever waiting for a writer. Fail-closed
// must return the sentinel immediately without touching the file. (Restricted
// to GOOSes where syscall.Mkfifo exists; Windows and plan9 cannot create
// FIFOs, and the never-stats / never-opens proofs in jwks_open_other_test.go
// cover all unsupported platforms.)
func TestOpenJWKSFileFailsClosedDoesNotBlockOnFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe.json")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo not supported: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := openJWKSFile(path)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrJWKSFileLoadingUnsupported) {
			t.Fatalf("expected ErrJWKSFileLoadingUnsupported, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("openJWKSFile blocked on a FIFO; unsupported platforms must fail closed without opening the path")
	}
}
