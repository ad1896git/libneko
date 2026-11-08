//go:build darwin || (linux && !android)

package neko_log

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestLogFileSafetyPermissions(t *testing.T) {
	logTestState(t)
	path := filepath.Join(logTestDir(t), "log")
	if err := SetupLog(1024, path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode %04o, want 0600", info.Mode().Perm())
	}
}

func TestLogFileSafetyRejectUnsafeFiles(t *testing.T) {
	for _, kind := range []string{"symlink", "dangling", "hardlink", "public", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			logTestState(t)
			dir := logTestDir(t)
			target, path := filepath.Join(dir, "target"), filepath.Join(dir, "log")
			if err := os.WriteFile(target, []byte("untouched"), 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(target, path)
			case "dangling":
				err = os.Symlink(filepath.Join(dir, "missing"), path)
			case "hardlink":
				err = os.Link(target, path)
			case "public":
				err = os.WriteFile(path, []byte("old public log"), 0644)
				if err == nil {
					err = os.Chmod(path, 0644)
				}
			case "fifo":
				err = syscall.Mkfifo(path, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = SetupLog(2, path); err == nil {
				t.Fatalf("accepted %s", kind)
			}
			got, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "untouched" {
				t.Fatalf("changed target: %q", got)
			}
			if kind == "public" {
				assertConsoleOnlyLog(t)
				info, _ := os.Stat(path)
				got, _ := os.ReadFile(path)
				if info.Mode().Perm() != 0644 || string(got) != "old public log" {
					t.Fatal("migrated existing file")
				}
			}
			if kind == "dangling" {
				if _, err := os.Stat(filepath.Join(dir, "missing")); !os.IsNotExist(err) {
					t.Fatalf("created symlink target: %v", err)
				}
			}
		})
	}
}

func TestLogFileSafetyRejectUnsafeAncestors(t *testing.T) {
	for _, kind := range []string{"symlink", "writable-parent", "writable-ancestor"} {
		t.Run(kind, func(t *testing.T) {
			logTestState(t)
			dir := logTestDir(t)
			parent := filepath.Join(dir, "parent")
			if err := os.Mkdir(parent, 0700); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink":
				alias := filepath.Join(dir, "alias")
				if err := os.Symlink(parent, alias); err != nil {
					t.Fatal(err)
				}
				parent = alias
			case "writable-parent":
				if err := os.Chmod(parent, 0777); err != nil {
					t.Fatal(err)
				}
			case "writable-ancestor":
				if err := os.Chmod(parent, 0777); err != nil {
					t.Fatal(err)
				}
				parent = filepath.Join(parent, "private")
				if err := os.Mkdir(parent, 0700); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(parent, "log")
			if err := SetupLog(2, path); err == nil {
				t.Fatal("accepted unsafe ancestor")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("created file before validation: %v", err)
			}
		})
	}
}
