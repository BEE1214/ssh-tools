//go:build unix

package app

import (
	"os"
	"syscall"
)

// fileOwnerUID returns the owner uid of the file fi describes. ok is false when
// the platform does not report it.
func fileOwnerUID(fi os.FileInfo) (uid int, ok bool) {
	st, isStat := fi.Sys().(*syscall.Stat_t)
	if !isStat || st == nil {
		return 0, false
	}
	return int(st.Uid), true
}
