//go:build linux && !android

package neko_log

// Linux POSIX ACL grants are bounded by the group-class mode mask. The FD
// ownership/mode checks therefore also reject effective non-owner ACL access.
func checkDesktopACL(fd int, directory bool) error { return nil }
