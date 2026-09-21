//go:build !darwin && !linux

package auth

import (
	"fmt"
	"os"
)

// openJWKSFile is the best-effort fallback for platforms whose kernels lack
// O_NOFOLLOW (neither macOS nor Linux). It Lstat-checks the path for a symlink
// before opening and readJWKSDescriptor re-validates the opened descriptor
// (regular file, mode, size), but the symlink TOCTOU window between Lstat and
// open cannot be fully closed without kernel O_NOFOLLOW support. This
// repository targets macOS and Linux; on other platforms the weaker guarantee
// is documented rather than silently hidden.
func openJWKSFile(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat registry token public keys file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("registry token public keys file %q must not be a symlink", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open registry token public keys file: %w", err)
	}
	return f, nil
}
