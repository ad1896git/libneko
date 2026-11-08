//go:build darwin || (linux && !android)

package neko_log

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const desktopLogPlatform = true

func openDesktopLog(path string) (*os.File, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	dir, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(dir) }()
	if err = checkDesktopACL(dir, true); err != nil {
		return nil, err
	}
	// Walk from the root using directory FDs, refusing symlinks in every
	// component. Checking only the immediate parent misses unsafe ancestors.
	for _, part := range parts[:len(parts)-1] {
		next, err := unix.Openat(dir, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		_ = unix.Close(dir)
		dir = next
		var st unix.Stat_t
		if err = unix.Fstat(dir, &st); err != nil {
			return nil, err
		}
		// Root-owned sticky directories (e.g. /tmp) cannot replace another
		// user's entries. All other ancestors must disallow untrusted writes.
		stickyRoot := st.Uid == 0 && st.Mode&unix.S_ISVTX != 0
		if err = checkDesktopACL(dir, true); err != nil {
			return nil, err
		}
		if (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || (st.Mode&0022 != 0 && !stickyRoot) {
			return nil, fmt.Errorf("untrusted log directory: %s", part)
		}
	}
	var parent unix.Stat_t
	if err = unix.Fstat(dir, &parent); err != nil {
		return nil, err
	}
	if parent.Uid != uint32(os.Geteuid()) || parent.Mode&0022 != 0 {
		return nil, fmt.Errorf("log parent must be owned by the current user and not writable by others")
	}
	// NONBLOCK prevents a hostile FIFO from blocking before Fstat can reject it.
	fd, err := unix.Openat(dir, parts[len(parts)-1], unix.O_RDWR|unix.O_APPEND|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	err = unix.Fstat(fd, &st)
	if err == nil && (st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 || st.Nlink != 1) {
		err = fmt.Errorf("log must be an owner-only regular file with one link")
	}
	if err == nil {
		err = checkDesktopACL(fd, false)
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}
