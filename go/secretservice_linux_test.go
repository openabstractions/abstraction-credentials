//go:build linux

package credentials

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
)

// sessionBus starts a private dbus-daemon for the test, or skips when the
// daemon is not installed.
func sessionBus(t *testing.T) string {
	t.Helper()
	daemon, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Skip("dbus-daemon not installed; the file backend covers this host")
	}
	dir := t.TempDir()
	config := filepath.Join(dir, "session.conf")
	socket := filepath.Join(dir, "bus")
	os.WriteFile(config, []byte(`<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig><type>session</type><listen>unix:path=`+socket+`</listen><auth>EXTERNAL</auth>
<policy context="default"><allow send_destination="*" eavesdrop="true"/><allow eavesdrop="true"/><allow own="*"/></policy></busconfig>`), 0o600)
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, daemon, "--config-file="+config, "--nofork", "--print-address=1")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); cmd.Wait() })
	lines := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(out).ReadString('\n')
		lines <- strings.TrimSpace(line)
	}()
	select {
	case address := <-lines:
		if address == "" {
			t.Fatal("dbus-daemon printed no address")
		}
		return address
	case <-time.After(10 * time.Second):
		t.Fatal("dbus-daemon did not start")
	}
	return ""
}

// TestDBusSessionBus exercises authentication, marshalling and decoding against
// a real dbus-daemon.
func TestDBusSessionBus(t *testing.T) {
	address := sessionBus(t)
	conn, err := dialBus(address, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	out, err := conn.call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "ListNames", "")
	if err != nil {
		t.Fatal(err)
	}
	names, _ := out[0].([]any)
	found := false
	for _, n := range names {
		if n == "org.freedesktop.DBus" {
			found = true
		}
	}
	if !found {
		t.Fatalf("ListNames: %v", out)
	}
	out, err = conn.call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "NameHasOwner", "s", secretsBus)
	if err != nil || out[0] != false {
		t.Fatalf("NameHasOwner: %v %v", out, err)
	}
	_, err = conn.call(secretsBus, secretsPath, secretsService, "OpenSession", "sv", "plain", variant{"s", ""})
	var dErr *dbusError
	if !errors.As(err, &dErr) || !strings.HasPrefix(dErr.name, "org.freedesktop.DBus.Error.") {
		t.Fatalf("missing secrets owner: %v", err)
	}
}

// TestSecretServiceWithoutKeyring is the headless case: a session bus with no
// org.freedesktop.secrets owner reads unavailable, and nothing is substituted.
func TestSecretServiceWithoutKeyring(t *testing.T) {
	address := sessionBus(t)
	backend, err := NewSecretService(address)
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Put("openabstractions/1000/hf/1-00", []byte(testSecret)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("put: %v", err)
	}
	if _, err := backend.Get("openabstractions/1000/hf/1-00"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("get: %v", err)
	}
	h := open(t, Config{Backend: backend})
	if r := h.Store(owner, "", registration("hf")); r.Outcome != wire.StoreOutcomeUnavailable {
		t.Fatalf("store: %+v", r)
	}
	if _, err := NewSecretService("unix:path=" + filepath.Join(t.TempDir(), "absent")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("absent bus: %v", err)
	}
}

// TestSecretServiceKeyring runs a real round trip when gnome-keyring-daemon is
// installed; it is skipped otherwise.
func TestSecretServiceKeyring(t *testing.T) {
	keyring, err := exec.LookPath("gnome-keyring-daemon")
	if err != nil {
		t.Skip("gnome-keyring-daemon not installed")
	}
	address := sessionBus(t)
	// --unlock creates and unlocks the login collection from the password on
	// stdin; gnome-keyring 50 refuses it together with --start.
	cmd := exec.Command(keyring, "--foreground", "--components=secrets", "--unlock")
	cmd.Env = append(os.Environ(), "DBUS_SESSION_BUS_ADDRESS="+address, "XDG_RUNTIME_DIR="+t.TempDir(), "HOME="+t.TempDir())
	cmd.Stdin = strings.NewReader("test-password")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	time.Sleep(2 * time.Second)
	backend, err := NewSecretService(address)
	if err != nil {
		t.Fatal(err)
	}
	key := "openabstractions/1000/hf/1-00"
	if err := backend.Put(key, []byte(testSecret)); err != nil {
		t.Skipf("keyring not usable headless: %v", err)
	}
	if got, err := backend.Get(key); err != nil || string(got) != testSecret {
		t.Fatalf("get: %v", err)
	}
	if err := backend.Delete(key); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Get(key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted: %v", err)
	}
}
