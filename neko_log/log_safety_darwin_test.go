package neko_log

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestLogFileSafetyDarwinACL(t *testing.T) {
	for _, kind := range []string{"file", "ancestor"} {
		t.Run(kind, func(t *testing.T) {
			logTestState(t)
			dir := logTestDir(t)
			path := filepath.Join(dir, "log")
			target, grant := path, "everyone allow read"
			if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
			if kind == "ancestor" {
				target, grant = dir, "everyone allow add_file,delete_child"
			}
			if out, err := exec.Command("/bin/chmod", "+a", grant, target).CombinedOutput(); err != nil {
				t.Fatalf("set ACL: %s: %v", out, err)
			}
			t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-N", target).Run() })
			if err := SetupLog(1, path); err == nil {
				t.Fatal("accepted ACL that bypasses mode bits")
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "keep" {
				t.Fatalf("changed rejected file: %q", got)
			}
		})
	}
}
