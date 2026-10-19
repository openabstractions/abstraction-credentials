package credentials

import (
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"strings"
)

// SecretResetReport records irreversible native-store effects without reading
// or exporting a secret value. Remaining includes the failed target and every
// target not attempted after it.
type SecretResetReport struct{ Deleted, Remaining []string }
type SecretResetPartial struct {
	Report SecretResetReport
	Cause  error
}

func (e *SecretResetPartial) Error() string {
	return fmt.Sprintf("credentials: reset partially completed: deleted=%d remaining=%d: %v", len(e.Report.Deleted), len(e.Report.Remaining), e.Cause)
}
func (e *SecretResetPartial) Unwrap() error { return e.Cause }

// WindowsAccountSecretTargets uses the existing Credential Manager backend's
// namespace enumeration. It opens no credential blob and reads no value.
func WindowsAccountSecretTargets(account string) ([]string, error) {
	if account == "" || strings.ContainsAny(account, "/\\\x00") {
		return nil, errors.New("credentials: account required")
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	if account != u.User.Sid.String() {
		return nil, errors.New("credentials: current account required")
	}
	backend, err := NewCredentialManager()
	if err != nil {
		return nil, err
	}
	return backend.(interface {
		Targets(string) ([]string, error)
	}).Targets(DefaultNamespace + "/" + account + "/")
}

func DeleteWindowsAccountSecretTargets(targets []string) (SecretResetReport, error) {
	backend, err := NewCredentialManager()
	if err != nil {
		return SecretResetReport{Remaining: append([]string(nil), targets...)}, err
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return SecretResetReport{Remaining: append([]string(nil), targets...)}, err
	}
	return deleteResetTargets(backend, u.User.Sid.String(), targets)
}
func deleteResetTargets(backend Backend, account string, targets []string) (SecretResetReport, error) {
	prefix := DefaultNamespace + "/" + account + "/"
	for _, key := range targets {
		if account == "" || !strings.HasPrefix(key, prefix) || len(key) <= len(prefix) {
			return SecretResetReport{Remaining: append([]string(nil), targets...)}, errors.New("credentials: reset target belongs to another account")
		}
	}
	var report SecretResetReport
	for i, key := range targets {
		if !strings.HasPrefix(key, DefaultNamespace+"/") {
			report.Remaining = append([]string(nil), targets[i:]...)
			return report, &SecretResetPartial{report, errors.New("foreign credential target")}
		}
		if err := backend.Delete(key); err != nil {
			report.Remaining = append([]string(nil), targets[i:]...)
			return report, &SecretResetPartial{report, err}
		}
		report.Deleted = append(report.Deleted, key)
	}
	return report, nil
}
