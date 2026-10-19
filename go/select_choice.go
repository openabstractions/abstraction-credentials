package credentials

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	cas "github.com/openabstractions/abstraction-cas/go"
)

// legacyLinuxStoreChoice is the file name earlier runtimes wrote the Linux store
// choice to, inside the credentials directory.
const legacyLinuxStoreChoice = "backend"

// LinuxStoreMarker is the Linux store choice beside the credentials directory
// dir, as the Windows and macOS markers are, so a choice never creates dir.
func LinuxStoreMarker(dir string) string {
	return filepath.Join(filepath.Dir(dir), "credentials-linux-backend")
}

// WriteLinuxStoreChoice records the operator's Linux store choice for the
// credentials directory dir: StoreFile or StoreSecretService. It writes the
// marker beside dir, replacing an earlier one, and removes the choice an earlier
// runtime wrote inside dir. The runtime reads it at its next start.
func WriteLinuxStoreChoice(dir, choice string) error {
	if choice != StoreFile && choice != StoreSecretService {
		return fmt.Errorf("credentials: unknown Linux store choice %q", choice)
	}
	if err := replaceMarker(LinuxStoreMarker(dir), choice+"\n"); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(dir, legacyLinuxStoreChoice)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// readLinuxStoreChoice reads the earlier choice inside dir, then the marker
// beside it (round2/storage/DECISION.md section 8 item 21). No marker reads
// StoreSecretService. An unknown word, or a marker that is not a small regular
// file, is an error: the state's store is unavailable.
func readLinuxStoreChoice(dir string) (string, error) {
	for _, path := range []string{filepath.Join(dir, legacyLinuxStoreChoice), LinuxStoreMarker(dir)} {
		info, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		if !info.Mode().IsRegular() || info.Size() > 256 {
			return "", errors.New("credentials: invalid Linux credentials store marker")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		switch word := strings.TrimSpace(string(data)); word {
		case StoreFile, StoreSecretService:
			return word, nil
		default:
			return "", fmt.Errorf("credentials: unknown Linux credentials store %q", word)
		}
	}
	return StoreSecretService, nil
}

// unavailableLinuxStore is the store word of a Linux state whose choice is
// unknown or unreadable. It selects no store.
const unavailableLinuxStore = "linux-store-unavailable"

type linuxConstructors struct {
	file          func(dir string) (Backend, error)
	secretService func() (Backend, error)
}

// openLinuxStore opens the chosen store. An unreachable Secret Service stays
// configured and reads unavailable.
func openLinuxStore(dir string, constructors linuxConstructors) (Backend, error) {
	choice, err := readLinuxStoreChoice(dir)
	if err != nil {
		return Unreachable(unavailableLinuxStore, MaxSecretBytes, err), nil
	}
	if choice == StoreFile {
		return constructors.file(filepath.Join(dir, "items"))
	}
	backend, err := constructors.secretService()
	if err != nil {
		return Unreachable(StoreSecretService, MaxSecretBytes, err), nil
	}
	return backend, nil
}

// replaceMarker writes a marker through the atomic-file writer (cas): a reader
// sees the old or the new contents, never a partial one, and the new contents
// are synced before the call returns.
func replaceMarker(marker, data string) error {
	if err := os.MkdirAll(filepath.Dir(marker), 0o700); err != nil {
		return err
	}
	return cas.Change(marker, func([]byte) ([]byte, error) { return []byte(data), nil })
}
