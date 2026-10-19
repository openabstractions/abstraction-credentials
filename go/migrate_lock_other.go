//go:build !windows && !linux && !darwin && !freebsd && !netbsd && !openbsd

package credentials

import "os"

// tryLockFile has no file lock on this platform. The Windows migration it
// guards never runs here.
func tryLockFile(*os.File) bool { return true }
