//go:build android || (!darwin && !linux && !windows)

package neko_log

import (
	"fmt"
	"os"
)

const desktopLogPlatform = false

func openDesktopLog(path string) (*os.File, error) {
	return nil, fmt.Errorf("unsupported desktop platform")
}
