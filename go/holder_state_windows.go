package credentials

import (
	"errors"
	"time"

	"golang.org/x/sys/windows"
)

// Windows can report access denied when an ordinary read handle temporarily
// prevents replacing the destination. Retry only the original atomic rename.
func retryStateRename(rename func() error) error {
	waits := [...]time.Duration{25 * time.Millisecond, 75 * time.Millisecond, 150 * time.Millisecond, 250 * time.Millisecond}
	for attempt := 0; ; attempt++ {
		err := rename()
		if attempt == len(waits) ||
			!errors.Is(err, windows.ERROR_ACCESS_DENIED) && !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			return err
		}
		time.Sleep(waits[attempt])
	}
}
