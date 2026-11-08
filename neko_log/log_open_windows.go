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
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}

	// Keep every ancestor open without write/delete sharing while traversing the
	// absolute path. No component can be renamed/replaced between checks and
	// opening the file, nor acquire a write handle to turn a checked directory
	// into a reparse point. OPEN_REPARSE_POINT refuses existing reparse points.
	var dirs []windows.Handle
	defer func() {
		for i := len(dirs) - 1; i >= 0; i-- {
			_ = windows.CloseHandle(dirs[i])
		}
	}()
	parent := filepath.Dir(path)
	parts := strings.Split(strings.TrimPrefix(parent[len(volume):], `\`), `\`)
	current := volume + `\`
	for i := -1; i < len(parts); i++ {
		if i >= 0 {
			if parts[i] == "" {
				continue
			}
			if strings.TrimRight(parts[i], " .") != parts[i] {
				return nil, fmt.Errorf("ambiguous log directory name")
			}
			current = filepath.Join(current, parts[i])
		}
		name, err := windows.UTF16PtrFromString(current)
		if err != nil {
			return nil, err
		}
		h, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL,
			windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			return nil, err
		}
		dirs = append(dirs, h)
		var info windows.ByHandleFileInformation
		if err = windows.GetFileInformationByHandle(h, &info); err != nil {
			return nil, err
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return nil, fmt.Errorf("log ancestor is not an ordinary directory")
		}
		security, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
		if err != nil {
			return nil, err
		}
		owner, _, err := security.Owner()
		if err != nil {
			return nil, err
		}
		if owner == nil {
			return nil, fmt.Errorf("log ancestor has no owner")
		}
		ownerSID := owner.String()
		if !owner.Equals(user.User.Sid) && ownerSID != "S-1-5-18" && ownerSID != "S-1-5-32-544" && ownerSID != trustedInstallerSID {
			return nil, fmt.Errorf("log ancestor has an untrusted owner")
		}
	}
	base := filepath.Base(path)
	if strings.TrimRight(base, " .") != base {
		return nil, fmt.Errorf("ambiguous log file name")
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL,
		windows.FILE_SHARE_READ, sa, windows.OPEN_ALWAYS, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	runtime.KeepAlive(sd)
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
	if err = checkLogACL(h, user.User.Sid, sd); err != nil {
		return fail(err)
	}
	return f, nil
}
