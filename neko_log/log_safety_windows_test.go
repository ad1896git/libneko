package neko_log

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestLogFileSafetyWindowsOwnerOnlyACL(t *testing.T) {
	logTestState(t)
	path := filepath.Join(logTestDir(t), "log")
	if err := SetupLog(1024, path); err != nil {
		t.Fatal(err)
	}
	closeTestLog()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	want, err := windows.SecurityDescriptorFromString("O:" + user.User.Sid.String() + "D:P(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	if sd.String() != want.String() {
		t.Fatalf("ACL = %s; want %s", sd.String(), want.String())
	}
}

func TestLogFileSafetyWindowsRejectPublicACL(t *testing.T) {
	logTestState(t)
	path := filepath.Join(logTestDir(t), "log")
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString("O:" + user.User.Sid.String() + "D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, sa, windows.CREATE_NEW, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(h), path)
	if _, err := f.WriteString("keep"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if err := SetupLog(1, path); err == nil {
		t.Fatal("accepted public ACL")
	}
	assertConsoleOnlyLog(t)
	after, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if before.String() != after.String() {
		t.Fatal("migrated existing ACL")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep" {
		t.Fatalf("changed rejected file: %q", got)
	}
}

func TestLogFileSafetyWindowsRejectLinks(t *testing.T) {
	for _, kind := range []string{"symlink", "directory-symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			logTestState(t)
			dir := logTestDir(t)
			target, path := filepath.Join(dir, "target"), filepath.Join(dir, "log")
			seedTestLog(t, target, "keep")
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(target, path)
			case "hardlink":
				err = os.Link(target, path)
			case "directory-symlink":
				real := filepath.Join(dir, "real")
				if err = os.Mkdir(real, 0700); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(real, path)
				path = filepath.Join(path, "log")
			}
			if err != nil {
				if kind != "hardlink" {
					t.Skipf("symlink creation needs Windows developer mode or privileges: %v", err)
				}
				t.Fatal(err)
			}
			if err := SetupLog(1, path); err == nil {
				t.Fatal("accepted link/reparse point")
			}
			got, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "keep" {
				t.Fatalf("modified target: %q", got)
			}
		})
	}
}

func TestLogFileSafetyWindowsRejectAmbiguousPaths(t *testing.T) {
	logTestState(t)
	for _, name := range []string{"log:stream", "log.", "log "} {
		closeTestLog()
		if err := SetupLog(1, filepath.Join(logTestDir(t), name)); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
}

func TestLogFileSafetyWindowsRelativeNames(t *testing.T) {
	// Reject names that could make a relative open traverse another component,
	// escape its directory handle, or address an alternate stream. This check
	// runs before calling Windows, so an invalid parent must not mask it.
	for _, name := range []string{"", ".", "..", `dir\log`, "dir/log", `\log`, "C:log", "log:stream", "log.", "log ", "log\x00suffix"} {
		h, err := openLogRelative(windows.InvalidHandle, name, windows.FILE_GENERIC_READ,
			windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE, nil)
		if err == nil {
			_ = windows.CloseHandle(h)
			t.Fatalf("accepted component %q", name)
		}
		if !strings.Contains(err.Error(), "single unambiguous name") && !strings.Contains(name, "\x00") {
			t.Fatalf("component %q reached the system call: %v", name, err)
		}
	}
}

// installTestJunction deliberately requests only FILE_WRITE_ATTRIBUTES, which
// is compatible with the ancestor's FILE_SHARE_READ. It does not replace or
// rename the held directory. No symlink privilege/developer mode is needed.
func installTestJunction(t *testing.T, path, target string) {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(name, windows.FILE_WRITE_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatalf("attribute-only handle must coexist with the checked directory handle: %v", err)
	}
	defer windows.CloseHandle(h)

	// REPARSE_DATA_BUFFER: 8-byte header, 8-byte mount-point fields, followed
	// by the null-terminated substitute and print names (offsets in bytes).
	substitute, err := windows.UTF16FromString(`\??\` + target)
	if err != nil {
		t.Fatal(err)
	}
	printName, err := windows.UTF16FromString(target)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16+2*(len(substitute)+len(printName)))
	binary.LittleEndian.PutUint32(buf[0:4], windows.IO_REPARSE_TAG_MOUNT_POINT)
	binary.LittleEndian.PutUint16(buf[4:6], uint16(len(buf)-8))
	binary.LittleEndian.PutUint16(buf[10:12], uint16(2*(len(substitute)-1)))
	binary.LittleEndian.PutUint16(buf[12:14], uint16(2*len(substitute)))
	binary.LittleEndian.PutUint16(buf[14:16], uint16(2*(len(printName)-1)))
	for i, c := range append(substitute, printName...) {
		binary.LittleEndian.PutUint16(buf[16+2*i:], c)
	}
	var returned uint32
	if err := windows.DeviceIoControl(h, windows.FSCTL_SET_REPARSE_POINT,
		&buf[0], uint32(len(buf)), nil, 0, &returned, nil); err != nil {
		t.Fatalf("convert checked empty directory to junction using write attributes: %v", err)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		t.Fatal(err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
		t.Fatal("junction conversion did not set reparse attribute")
	}
}

func makeTestAttributeWritableDir(t *testing.T, path string, sid *windows.SID) {
	t.Helper()
	// Model the finding: trusted owner, but an untrusted principal can acquire
	// a write-attribute handle. In-process mutation makes the timing exact;
	// this is not a multi-account access-check test.
	sd, err := windows.SecurityDescriptorFromString("O:" + sid.String() +
		"D:P(A;;FA;;;" + sid.String() + ")(A;;0x100;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	if err := windows.CreateDirectory(name, sa); err != nil {
		t.Fatal(err)
	}
}

func TestLogFileSafetyWindowsJunctionAfterValidation(t *testing.T) {
	for _, scenario := range []string{"existing-target", "missing-target", "next-directory", "before-validation"} {
		t.Run(scenario, func(t *testing.T) {
			logTestState(t)
			dir := logTestDir(t)
			user, err := windows.GetCurrentProcessToken().GetTokenUser()
			if err != nil {
				t.Fatal(err)
			}
			sid := user.User.Sid
			sd, err := logSecurityDescriptor(sid)
			if err != nil {
				t.Fatal(err)
			}
			parent, target := filepath.Join(dir, "checked"), filepath.Join(dir, "target")
			makeTestAttributeWritableDir(t, parent, sid)
			if err := os.Mkdir(target, 0700); err != nil {
				t.Fatal(err)
			}
			victim := filepath.Join(target, "log")
			if scenario == "next-directory" {
				if err := os.Mkdir(filepath.Join(target, "child"), 0700); err != nil {
					t.Fatal(err)
				}
				victim = filepath.Join(target, "child", "log")
			}
			var victimInfo os.FileInfo
			if scenario != "missing-target" {
				// This file passes the final owner-only ACL checks; refusal by
				// that unrelated check must not hide a redirected open.
				seedTestLog(t, victim, "keep victim")
				// Stat the handle to capture identity now. Go 1.22 path Stat
				// loads Windows file IDs lazily, which can fail sharing checks
				// once the log is open and make SameFile silently return false.
				vf, err := os.Open(victim)
				if err != nil {
					t.Fatal(err)
				}
				victimInfo, err = vf.Stat()
				closeErr := vf.Close()
				if err != nil || closeErr != nil {
					t.Fatalf("capture target identity: stat=%v close=%v", err, closeErr)
				}
			}

			path := filepath.Join(parent, "log")
			if scenario == "before-validation" {
				installTestJunction(t, parent, target)
				if err := SetupLog(0, path); err == nil {
					t.Fatal("accepted existing junction ancestor")
				}
				assertConsoleOnlyLog(t)
				got, err := os.ReadFile(victim)
				if err != nil || string(got) != "keep victim" {
					t.Fatalf("changed rejected junction target: %q, %v", got, err)
				}
				return
			}
			dirs, err := openLogAncestors(path, sid)
			defer closeLogAncestors(dirs)
			if err != nil {
				t.Fatal(err)
			}
			// Deterministic race boundary: all ancestors passed the actual
			// production checks, but the final child has not been opened.
			installTestJunction(t, parent, target)
			if scenario == "next-directory" {
				// Also exercise the exact relative-open helper used by the
				// ancestor loop after a preceding component was validated.
				h, err := openLogRelative(dirs[len(dirs)-1], "child",
					windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.FILE_TRAVERSE,
					windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE, nil)
				if err == nil {
					_ = windows.CloseHandle(h)
					t.Fatal("opened child that exists only through the junction")
				}
			} else {
				f, err := openDesktopLogAt(dirs[len(dirs)-1], "log", path, sid, sd)
				if err == nil {
					defer f.Close()
					info, err := f.Stat()
					if err != nil {
						t.Fatal(err)
					}
					if victimInfo != nil && os.SameFile(info, victimInfo) {
						t.Fatal("opened junction target instead of original directory object")
					}
					// Original-directory success or fail-closed are both safe.
					if err := prepareDesktopLog(f, 0); err != nil {
						t.Fatal(err)
					}
					if _, err := f.WriteString("original only"); err != nil {
						t.Fatal(err)
					}
					if err := f.Close(); err != nil {
						t.Fatal(err)
					}
				}
			}
			if scenario == "missing-target" {
				if _, err := os.Stat(victim); !os.IsNotExist(err) {
					t.Fatalf("created a log through the junction: %v", err)
				}
			} else {
				got, err := os.ReadFile(victim)
				if err != nil || string(got) != "keep victim" {
					t.Fatalf("changed junction target: %q, %v", got, err)
				}
			}
		})
	}
}
