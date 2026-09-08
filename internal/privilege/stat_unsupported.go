//go:build !linux

package privilege

import (
	"errors"
	"os"
)

func getFileOwnership(fi os.FileInfo) (uint32, uint32, error) {
	return 0, 0, errors.New("file ownership inspection is only supported on Linux")
}

func verifyOwnership(fi os.FileInfo, expectedUID, expectedGID uint32) error {
	return errors.New("file ownership verification is only supported on Linux")
}

func SameFile(fi1, fi2 os.FileInfo) bool {
	if fi1 == nil || fi2 == nil {
		return false
	}
	return os.SameFile(fi1, fi2)
}
