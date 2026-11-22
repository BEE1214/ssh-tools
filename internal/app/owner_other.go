//go:build !unix

package app

import "os"

// fileOwnerUID reports no owner on platforms without a uid: doctor then falls
// back to judging a file by its mode alone.
func fileOwnerUID(fi os.FileInfo) (uid int, ok bool) {
	return 0, false
}
