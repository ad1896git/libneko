package neko_log

import (
	"os"
	"path/filepath"
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
