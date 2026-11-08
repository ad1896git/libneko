//go:build darwin || (linux && !android) || windows

package neko_log

import (
	"bytes"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/matsuridayo/libneko/neko_common"
)

func logTestState(t *testing.T) {
	t.Helper()
	oldWriter, oldMode, oldTruncate := LogWriter, neko_common.RunMode, TruncateOnStart
	oldOutput, oldFlags := log.Writer(), log.Flags()
	LogWriter = nil
	neko_common.RunMode = neko_common.RunMode_NekoBox_Core
	TruncateOnStart = true
	t.Cleanup(func() {
		closeTestLog()
		LogWriter, neko_common.RunMode, TruncateOnStart = oldWriter, oldMode, oldTruncate
		log.SetOutput(oldOutput)
		log.SetFlags(oldFlags)
	})
}

func closeTestLog() {
	if LogWriter == nil {
		return
	}
	for _, w := range LogWriter.writers {
		if w == os.Stdout || w == os.Stderr {
			continue
		}
		if c, ok := w.(io.Closer); ok {
			_ = c.Close()
		}
	}
	LogWriter = nil
}

func logTestDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func seedTestLog(t *testing.T, path, content string) {
	t.Helper()
	TruncateOnStart = false
	if err := SetupLog(0, path); err != nil {
		t.Fatal(err)
	}
	// Write only to the file, keeping stdout out of test output.
	for _, w := range LogWriter.writers {
		if w != os.Stdout {
			if _, err := io.WriteString(w, content); err != nil {
				t.Fatal(err)
			}
		}
	}
	closeTestLog()
	TruncateOnStart = true
}

func TestLogFileSafetyTailAndAppend(t *testing.T) {
	for _, tc := range []struct {
		name     string
		size     int
		truncate bool
		want     string
	}{
		{"tail", 4, true, "6789"}, {"zero", 0, true, ""},
		{"unchanged", 20, true, "0123456789"}, {"disabled", 4, false, "0123456789"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logTestState(t)
			path := filepath.Join(logTestDir(t), "log")
			seedTestLog(t, path, "0123456789")
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			TruncateOnStart = tc.truncate
			if err := SetupLog(tc.size, path); err != nil {
				t.Fatal(err)
			}
			after, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if !os.SameFile(before, after) {
				t.Error("truncation replaced the file")
			}
			for _, w := range LogWriter.writers {
				if w != os.Stdout {
					_, err = io.WriteString(w, "!")
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want+"!" {
				t.Fatalf("got %q, want %q", got, tc.want+"!")
			}
		})
	}
}

func assertConsoleOnlyLog(t *testing.T) {
	t.Helper()
	if LogWriter == nil || len(LogWriter.writers) != 1 || LogWriter.writers[0] != os.Stdout {
		t.Fatal("file refusal must leave a usable console-only writer")
	}
	if n, err := LogWriter.Write([]byte("console remains available after log-file refusal\n")); err != nil || n == 0 {
		t.Fatalf("fallback write: n=%d, err=%v", n, err)
	}
	log.Print("standard logger remains available")
}

func TestLogFileSafetyFailureKeepsConsole(t *testing.T) {
	logTestState(t)
	dir := logTestDir(t)
	if err := SetupLog(4, dir); err == nil {
		t.Fatal("accepted directory")
	}
	assertConsoleOnlyLog(t)
}

func TestLogFileSafetyNegativeLimit(t *testing.T) {
	logTestState(t)
	path := filepath.Join(logTestDir(t), "log")
	seedTestLog(t, path, "keep")
	if err := SetupLog(-1, path); err == nil {
		t.Fatal("accepted negative limit")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep" {
		t.Fatalf("modified file: %q", got)
	}
}

func TestLogFileSafetyConcurrentWriteAndTruncate(t *testing.T) {
	logTestState(t)
	path := filepath.Join(logTestDir(t), "log")
	if err := SetupLog(1024, path); err != nil {
		t.Fatal(err)
	}
	// Keep only the file writer for concurrent calls.
	LogWriter.writers = LogWriter.writers[1:]
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_, _ = LogWriter.Write([]byte("entry\n"))
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 20; j++ {
			LogWriter.Truncate()
		}
	}()
	wg.Wait()
	LogWriter.Truncate()
	_, _ = LogWriter.Write([]byte("final\n"))
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("final\n")) {
		t.Fatalf("truncate left a gap or stale bytes: %q", got)
	}
}
