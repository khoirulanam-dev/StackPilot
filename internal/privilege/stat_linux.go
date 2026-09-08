//go:build linux

package privilege

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// getFileOwnership returns the owner UID and GID from os.FileInfo.
func getFileOwnership(fi os.FileInfo) (uint32, uint32, error) {
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, fmt.Errorf("failed to retrieve stat structure for %s", fi.Name())
	}
	return stat.Uid, stat.Gid, nil
}

// verifyOwnership inspects stat information to verify UID and GID match expected values.
func verifyOwnership(fi os.FileInfo, expectedUID, expectedGID uint32) error {
	uid, gid, err := getFileOwnership(fi)
	if err != nil {
		return err
	}
	if uid != expectedUID {
		if expectedUID == 0 {
			return errors.New("owner is not root")
		}
		return errors.New("owner mismatch")
	}
	if gid != expectedGID {
		return errors.New("group mismatch")
	}
	return nil
}

// SameFile reports whether fi1 and fi2 describe the same file via os.SameFile or device/inode comparison.
func SameFile(fi1, fi2 os.FileInfo) bool {
	if fi1 == nil || fi2 == nil {
		return false
	}
	if os.SameFile(fi1, fi2) {
		return true
	}
	s1, ok1 := fi1.Sys().(*syscall.Stat_t)
	s2, ok2 := fi2.Sys().(*syscall.Stat_t)
	if ok1 && ok2 && s1 != nil && s2 != nil {
		return s1.Dev != 0 && s1.Ino != 0 && s1.Dev == s2.Dev && s1.Ino == s2.Ino
	}
	return false
}
