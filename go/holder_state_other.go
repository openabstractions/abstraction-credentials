//go:build !windows

package credentials

func retryStateRename(rename func() error) error {
	return rename()
}
