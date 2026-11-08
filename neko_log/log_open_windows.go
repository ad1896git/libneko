package neko_log

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const desktopLogPlatform = true

// The Windows Modules Installer service may own system-drive ancestors.
const trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

func logSecurityDescriptor(sid *windows.SID) (*windows.SECURITY_DESCRIPTOR, error) {
	// A protected DACL prevents a permissive parent ACL from being inherited.
	return windows.SecurityDescriptorFromString("O:" + sid.String() + "D:P(A;;FA;;;" + sid.String() + ")")
}

func checkLogACL(h windows.Handle, sid *windows.SID, want *windows.SECURITY_DESCRIPTOR) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	// Compare canonical SDDL ACEs; ignore only the DACL's control flags, which
	// are checked separately. Reject null, inherited and extra allow/deny ACEs.
	actual, expected := sd.String(), want.String()
	a, b := strings.Index(actual, "("), strings.Index(expected, "(")
	if owner == nil || !owner.Equals(sid) || acl == nil || control&windows.SE_DACL_PROTECTED == 0 || a < 0 || b < 0 || actual[a:] != expected[b:] {
		return fmt.Errorf("log must have a protected owner-only ACL; existing ACL was not changed")
	}
	return nil
}

func openDesktopLog(path string) (*os.File, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	volume := filepath.VolumeName(path)
	// Do not accept device namespaces, network paths or alternate data streams.
	if len(volume) != 2 || volume[1] != ':' || strings.Contains(path[len(volume):], ":") {
		return nil, fmt.Errorf("log path must be a local drive path without alternate streams")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	sd, err := logSecurityDescriptor(user.User.Sid)
	if err != nil {
		return nil, err
	}

	dirs, err := openLogAncestors(path, user.User.Sid)
	defer closeLogAncestors(dirs)
	if err != nil {
		return nil, err
	}
	return openDesktopLogAt(dirs[len(dirs)-1], filepath.Base(path), path, user.User.Sid, sd)
}

func closeLogAncestors(dirs []windows.Handle) {
	for i := len(dirs) - 1; i >= 0; i-- {
		_ = windows.CloseHandle(dirs[i])
	}
}

// The caller must close the returned handles even on error.
func openLogAncestors(path string, sid *windows.SID) (dirs []windows.Handle, err error) {
	// No delete sharing keeps these directory objects from being replaced.
	// Attribute-only handles are NOT excluded by sharing: a checked directory
	// can still become a junction. Relative single-component opens below keep
	// using the original directory objects rather than resolving their paths.
	volume := filepath.VolumeName(path)
	parent := filepath.Dir(path)
	parts := strings.Split(strings.TrimPrefix(parent[len(volume):], `\`), `\`)
	for i := -1; i < len(parts); i++ {
		if i >= 0 {
			if parts[i] == "" {
				continue
			}
			if strings.TrimRight(parts[i], " .") != parts[i] {
				return dirs, fmt.Errorf("ambiguous log directory name")
			}
		}
		var h windows.Handle
		var err error
		if len(dirs) == 0 {
			// Only the drive root is opened by absolute path. Every later
			// component is opened relative to its validated parent handle.
			name, nameErr := windows.UTF16PtrFromString(volume + `\`)
			if nameErr != nil {
				return dirs, nameErr
			}
			h, err = windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.FILE_TRAVERSE,
				windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING,
				windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		} else {
			h, err = openLogRelative(dirs[len(dirs)-1], parts[i],
				windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.FILE_TRAVERSE,
				windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE, nil)
		}
		if err != nil {
			return dirs, err
		}
		dirs = append(dirs, h)
		var info windows.ByHandleFileInformation
		if err = windows.GetFileInformationByHandle(h, &info); err != nil {
			return dirs, err
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return dirs, fmt.Errorf("log ancestor is not an ordinary directory")
		}
		security, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
		if err != nil {
			return dirs, err
		}
		owner, _, err := security.Owner()
		if err != nil {
			return dirs, err
		}
		if owner == nil {
			return dirs, fmt.Errorf("log ancestor has no owner")
		}
		ownerSID := owner.String()
		if !owner.Equals(sid) && ownerSID != "S-1-5-18" && ownerSID != "S-1-5-32-544" && ownerSID != trustedInstallerSID {
			return dirs, fmt.Errorf("log ancestor has an untrusted owner")
		}
	}
	return dirs, nil
}

// openLogRelative opens exactly one child of a held directory. Never accept a
// path here: FILE_OPEN_REPARSE_POINT protects only the final component.
func openLogRelative(parent windows.Handle, name string, access, disposition, options uint32, sd *windows.SECURITY_DESCRIPTOR) (windows.Handle, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `\/:`) || strings.TrimRight(name, " .") != name {
		return windows.InvalidHandle, fmt.Errorf("log component must be a single unambiguous name")
	}
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return windows.InvalidHandle, err
	}
	attrs := windows.OBJECT_ATTRIBUTES{
		RootDirectory:      parent,
		ObjectName:         objectName,
		Attributes:         windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
		SecurityDescriptor: sd,
	}
	attrs.Length = uint32(unsafe.Sizeof(attrs))
	var h windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&h, access|windows.SYNCHRONIZE, &attrs, &iosb, nil,
		windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ, disposition,
		options|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	runtime.KeepAlive(sd)
	if err != nil {
		// Unsupported no-reparse semantics also fail closed; do not retry by path.
		return windows.InvalidHandle, err
	}
	return h, nil
}

func openDesktopLogAt(parent windows.Handle, base, path string, sid *windows.SID, sd *windows.SECURITY_DESCRIPTOR) (*os.File, error) {
	h, err := openLogRelative(parent, base, windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE,
		windows.FILE_OPEN_IF, windows.FILE_NON_DIRECTORY_FILE, sd)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), path)
	fail := func(err error) (*os.File, error) { _ = f.Close(); return nil, err }
	kind, err := windows.GetFileType(h)
	if err != nil {
		return fail(err)
	}
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(h, &info); err != nil {
		return fail(err)
	}
	if kind != windows.FILE_TYPE_DISK || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || info.NumberOfLinks != 1 {
		return fail(fmt.Errorf("log must be an ordinary file with one link, not a reparse point"))
	}
	if err = checkLogACL(h, sid, sd); err != nil {
		return fail(err)
	}
	return f, nil
}
