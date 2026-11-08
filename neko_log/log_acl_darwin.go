package neko_log

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Darwin extended ACLs can grant access independently of the Unix mode bits.
// Read ATTR_CMN_EXTENDED_SECURITY through the FD; Fgetxattr cannot read the
// protected com.apple.system.Security attribute. Layouts are defined in the
// Darwin SDK's sys/attr.h and sys/kauth.h.
func checkDesktopACL(fd int, directory bool) error {
	attrs := struct {
		Count, Reserved                 uint16
		Common, Volume, Dir, File, Fork uint32
	}{Count: 5, Common: 0x00400000}
	// kauth_filesec (44 bytes) plus up to 128 kauth_ace entries (24 bytes).
	var buf [4096]byte
	_, _, errno := unix.Syscall6(unix.SYS_FGETATTRLIST, uintptr(fd), uintptr(unsafe.Pointer(&attrs)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0)
	if errno != 0 {
		return errno
	}
	order := binary.LittleEndian // All supported Darwin architectures are little endian.
	size := order.Uint32(buf[:4])
	if size < 12 || size > uint32(len(buf)) {
		return fmt.Errorf("invalid log ACL attributes")
	}
	offset, length := order.Uint32(buf[4:8]), order.Uint32(buf[8:12])
	if length == 0 {
		return nil
	}
	start := uint64(4) + uint64(offset) // attrreference is relative to itself.
	if start < 12 || length < 44 || start+uint64(length) > uint64(size) {
		return fmt.Errorf("invalid log ACL reference")
	}
	security := buf[start : start+uint64(length)]
	if order.Uint32(security[:4]) != 0x012cc16d {
		return fmt.Errorf("invalid log ACL magic")
	}
	count := order.Uint32(security[36:40])
	if count == ^uint32(0) {
		return nil
	} // KAUTH_FILESEC_NOACL
	if count > 128 || 44+uint64(count)*24 > uint64(length) {
		return fmt.Errorf("invalid log ACL entries")
	}
	for i := uint32(0); i < count; i++ {
		flags := order.Uint32(security[44+i*24+16 : 44+i*24+20])
		// Normal macOS home directories carry an everyone-deny-delete ACE.
		// Permit deny-only directory ACLs. Fail closed on other extended grants
		// instead of trying to resolve ACL UUIDs/groups into effective access.
		if !directory || flags&0xf != 2 {
			return fmt.Errorf("extended log ACL grants are not supported")
		}
	}
	return nil
}
