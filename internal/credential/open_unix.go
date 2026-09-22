//go:build darwin || linux

package credential

import (
	"fmt"
	"os"
	"syscall"
)

// openSecretFile opens path exactly ONCE for reading, without following a
// trailing symlink (O_NOFOLLOW) and without blocking on special files
// (O_NONBLOCK — regular-file reads are unaffected). The opened descriptor is
// the sole object LoadSecretFile validates and reads, so a path swap between
// open and read cannot redirect parsing: the stat→open→read TOCTOU window does
// not exist on macOS/Linux. O_CLOEXEC keeps the descriptor out of child
// processes. The error never contains the path (an operator secret value).
func openSecretFile(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open internal credential file: %w", err)
	}
	return os.NewFile(uintptr(fd), path), nil
}
