//go:build !darwin && !linux

package auth

import (
	"errors"
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
// returns the bare ErrJWKSFileLoadingUnsupported sentinel — NEVER wrapped with
// the supplied path or any other caller-controlled data — so LoadJWKSFromFile
// and production startup fail closed: because no Lstat, no open, and no read
// of the path happens here, there is no symlink-check/open TOCTOU window and
// no special file can ever block the process. The error is returned unwrapped
// because it is propagated unchanged all the way to cmd/registry startup
// (log.Fatal): formatting the path into it would leak the operator's
// REGISTRY_TOKEN_PUBLIC_KEYS_FILE value into logs on every non-macOS/Linux
// host. errors.Is still matches the sentinel exactly. The public signature is
// identical to the darwin/linux implementation.
func openJWKSFile(path string) (*os.File, error) {
	return nil, ErrJWKSFileLoadingUnsupported
}
