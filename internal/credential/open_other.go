//go:build !darwin && !linux

package credential

import (
	"errors"
	"os"
)

// ErrSecretFileLoadingUnsupported is the data-free sentinel returned on every
// platform other than darwin and linux: the internal-credential security
// contract — open exactly once without following a trailing symlink and
// without blocking on special files — requires kernel support only macOS and
// Linux provide. Loading is refused outright rather than falling back to a
// racy Lstat-then-open.
var ErrSecretFileLoadingUnsupported = errors.New("secure internal credential file loading is unsupported on this platform (requires macOS or Linux); refusing to fall back to an insecure open")

func openSecretFile(path string) (*os.File, error) {
	return nil, ErrSecretFileLoadingUnsupported
}
