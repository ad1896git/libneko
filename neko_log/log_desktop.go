package neko_log

import (
	"fmt"
	"io"
	"log"
	"os"
	"sync"

	"github.com/matsuridayo/libneko/syscallw"
)

func setupDesktopLog(maxSize int, path string) (err error) {
	if LogWriter != nil {
		return nil
	}
	// A refused or unavailable file must not disable core logging. Return the
	// diagnostic to the caller while keeping LogWriter and log usable on stdout.
	defer func() {
		if err != nil {
			installDesktopLog(nil)
		}
	}()
	if maxSize < 0 {
		return fmt.Errorf("file logging disabled: negative size limit")
	}
	f, err := openDesktopLog(path)
	if err != nil {
		return fmt.Errorf("file logging disabled: %w", err)
	}
	if err = prepareDesktopLog(f, maxSize); err != nil {
		_ = f.Close()
		return fmt.Errorf("file logging disabled: %w", err)
	}
	installDesktopLog(f)
	return nil
}

func installDesktopLog(f *os.File) {
	writers := []io.Writer{os.Stdout}
	if f != nil {
		writers = append(writers, &desktopLogFile{file: f})
	}
	LogWriter = &logWriter{writers: writers}
	log.SetFlags(log.LstdFlags | log.LUTC)
	log.SetOutput(LogWriter)
}

// All startup operations use the validated handle. In particular, truncation
// must never unlink or reopen the caller's path (including on Windows).
func prepareDesktopLog(f *os.File, maxSize int) error {
	fd := int(f.Fd())
	if err := syscallw.Flock(fd, syscallw.LOCK_EX); err != nil {
		return err
	}
	defer syscallw.Flock(fd, syscallw.LOCK_UN)
	if TruncateOnStart {
		info, err := f.Stat()
		if err != nil {
			return err
		}
		if info.Size() > int64(maxSize) {
			tail := make([]byte, maxSize)
			if _, err = f.ReadAt(tail, info.Size()-int64(maxSize)); err != nil {
				return err
			}
			if err = f.Truncate(0); err != nil {
				return err
			}
			if _, err = f.Seek(0, io.SeekStart); err != nil {
				return err
			}
			if _, err = f.Write(tail); err != nil {
				return err
			}
		}
	}
	_, err := f.Seek(0, io.SeekEnd)
	return err
}

// os.File serializes individual calls; this mutex also serializes the compound
// truncate/seek operation with writes. Unix flock coordinates other processes.
type desktopLogFile struct {
	mu   sync.Mutex
	file *os.File
}

func (f *desktopLogFile) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fd := int(f.file.Fd())
	if err := syscallw.Flock(fd, syscallw.LOCK_EX); err != nil {
		return 0, err
	}
	defer syscallw.Flock(fd, syscallw.LOCK_UN)
	return f.file.Write(p)
}

func (f *desktopLogFile) truncate() {
	f.mu.Lock()
	defer f.mu.Unlock()
	fd := int(f.file.Fd())
	if syscallw.Flock(fd, syscallw.LOCK_EX) != nil {
		return
	}
	defer syscallw.Flock(fd, syscallw.LOCK_UN)
	if f.file.Truncate(0) == nil {
		_, _ = f.file.Seek(0, io.SeekStart)
	}
}

func (f *desktopLogFile) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.file.Close()
}
