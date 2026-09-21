//go:build !darwin && !linux

package auth

import (
	"errors"
	"fmt"
	"os"
)

// ErrJWKSFileLoadingUnsupported is the stable, data-free sentinel returned by
// openJWKSFile on every GOOS other than darwin and linux. The registry's JWKS
// security contract — open the keys file exactly ONCE without following a
// trailing symlink (O_NOFOLLOW) and without blocking on special files
// (O_NONBLOCK) — requires kernel support that only macOS and Linux provide. A
// Lstat-then-open fallback would still carry a symlink-swap TOCTOU window and
// could block on special files, so loading is REFUSED outright: the sentinel
// propagates through LoadJWKSFromFile to cmd/registry startup, which fails
// closed instead of running with weaker guarantees. The message carries no
// path and no key material.
var ErrJWKSFileLoadingUnsupported = errors.New("secure JWKS file loading is unsupported on this platform (requires macOS or Linux); refusing to fall back to an insecure open")

// openJWKSFile never opens, stats, or reads path on unsupported platforms. It
// returns the stable ErrJWKSFileLoadingUnsupported sentinel so
// LoadJWKSFromFile and production startup fail closed: because no Lstat, no
// open, and no read of the path happens here, there is no symlink-check/open
// TOCTOU window and no special file can ever block the process. The public
// signature is identical to the darwin/linux implementation.
func openJWKSFile(path string) (*os.File, error) {
	return nil, fmt.Errorf("%w: %q", ErrJWKSFileLoadingUnsupported, path)
}
