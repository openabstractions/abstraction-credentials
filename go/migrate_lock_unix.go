//go:build linux || darwin || freebsd || netbsd || openbsd

package credentials

import (
	"os"
	"syscall"
)

// tryLockFile takes an exclusive lock on f's open file description without
// waiting, so a second open of the file in the same process is refused too.
func tryLockFile(f *os.File) bool {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil
}
