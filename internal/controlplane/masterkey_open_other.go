//go:build !darwin && !linux

package controlplane

import (
	"os"
)

// openMasterKeyFile never opens, stats, or reads path on unsupported
// platforms. It returns the bare ErrMasterKeyFileLoadingUnsupported sentinel
// (declared in keycrypto.go so it compiles on every GOOS) — NEVER wrapped with
// the supplied path or any other caller-controlled data — so LoadMasterKeyFile
// and production startup fail closed: because no Lstat, no open, and no read
// of the path happens here, there is no symlink-check/open TOCTOU window and
// no special file can ever block the process. The error is returned unwrapped
// because it is propagated unchanged all the way to cmd/controlplane startup
// (log.Fatal): formatting the path into it would leak the operator's
// CONTROLPLANE_MASTER_KEY_FILE value into logs on every non-macOS/Linux host.
// errors.Is still matches the sentinel exactly. The public signature is
// identical to the darwin/linux implementation.
func openMasterKeyFile(path string) (*os.File, error) {
	return nil, ErrMasterKeyFileLoadingUnsupported
}
