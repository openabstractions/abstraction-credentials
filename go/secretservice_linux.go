//go:build linux

package credentials

import (
	"errors"
	"fmt"
	"os"
	"time"
)

const (
	secretsBus        = "org.freedesktop.secrets"
	secretsPath       = "/org/freedesktop/secrets"
	secretsService    = "org.freedesktop.Secret.Service"
	secretsItem       = "org.freedesktop.Secret.Item"
	secretsCollection = "org.freedesktop.Secret.Collection"
	defaultCollection = "/org/freedesktop/secrets/aliases/default"
	keyAttribute      = "openabstractions-key"
)

type secretService struct{ address string }

// NewSecretService selects the Secret Service on the session bus at address,
// for example "unix:path=/run/user/1000/bus". An empty address uses
// DBUS_SESSION_BUS_ADDRESS, which locates the bus and carries no secret. Items
// go to the default collection; a missing bus, a missing secrets owner, a locked
// collection or a prompt reads ErrUnavailable. The constructor connects once.
func NewSecretService(address string) (Backend, error) {
	if address == "" {
		address = os.Getenv("DBUS_SESSION_BUS_ADDRESS")
	}
	if address == "" {
		return nil, fmt.Errorf("%w: no session bus address", ErrUnavailable)
	}
	s := secretService{address: address}
	conn, err := dialBus(address, 5*time.Second)
	if err != nil {
		return nil, err
	}
	conn.Close()
	return s, nil
}

func (secretService) Name() string        { return StoreSecretService }
func (secretService) MaxSecretBytes() int { return MaxSecretBytes }

func (s secretService) session() (*dbusConn, string, error) {
	conn, err := dialBus(s.address, 5*time.Second)
	if err != nil {
		return nil, "", err
	}
	out, err := conn.call(secretsBus, secretsPath, secretsService, "OpenSession", "sv", "plain", variant{"s", ""})
	if err != nil {
		conn.Close()
		return nil, "", unavailable(err)
	}
	path := ""
	if len(out) == 2 {
		path, _ = out[1].(string)
	}
	if path == "" {
		conn.Close()
		return nil, "", fmt.Errorf("%w: OpenSession reply", ErrUnavailable)
	}
	return conn, path, nil
}

func unavailable(err error) error {
	if errors.Is(err, ErrUnavailable) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrUnavailable, err)
}

// busCaller is the method call a session bus connection makes; tests script it.
type busCaller interface {
	call(dest, path, iface, member, sig string, args ...any) ([]any, error)
}

func (s secretService) find(conn busCaller, key string) (string, error) {
	out, err := conn.call(secretsBus, secretsPath, secretsService, "SearchItems", "a{ss}", []any{[]any{keyAttribute, key}})
	if err != nil {
		return "", unavailable(err)
	}
	if len(out) != 2 {
		return "", fmt.Errorf("%w: SearchItems reply", ErrUnavailable)
	}
	unlocked, unlockedOK := out[0].([]any)
	locked, lockedOK := out[1].([]any)
	if !unlockedOK || !lockedOK {
		return "", fmt.Errorf("%w: SearchItems reply", ErrUnavailable)
	}
	if len(unlocked) > 0 {
		path, ok := unlocked[0].(string)
		if !ok || path == "" {
			return "", fmt.Errorf("%w: SearchItems item path", ErrUnavailable)
		}
		return path, nil
	}
	if len(locked) > 0 {
		return "", fmt.Errorf("%w: secret service item is locked", ErrUnavailable)
	}
	return "", nil
}

func (s secretService) Put(key string, secret []byte) error {
	conn, session, err := s.session()
	if err != nil {
		return err
	}
	defer conn.Close()
	properties := []any{
		[]any{"org.freedesktop.Secret.Item.Label", variant{"s", "OpenAbstractions credential"}},
		[]any{"org.freedesktop.Secret.Item.Attributes", variant{"a{ss}", []any{[]any{keyAttribute, key}}}},
	}
	value := []any{session, []byte{}, secret, "application/octet-stream"}
	out, err := conn.call(secretsBus, defaultCollection, secretsCollection, "CreateItem", "a{sv}(oayays)b", properties, value, true)
	if err != nil {
		return unavailable(err)
	}
	if prompt, _ := out[1].(string); prompt != "/" {
		return fmt.Errorf("%w: secret service requires a prompt", ErrUnavailable)
	}
	return nil
}

func (s secretService) Get(key string) ([]byte, error) {
	conn, session, err := s.session()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return s.read(conn, session, key)
}

// read looks up key and returns its secret over an open session.
func (s secretService) read(conn busCaller, session, key string) ([]byte, error) {
	path, err := s.find(conn, key)
	if err != nil {
		return nil, err
	}
	if path == "" {
		return nil, confirmNotFound(func() error { return s.collectionReady(conn) })
	}
	out, err := conn.call(secretsBus, path, secretsItem, "GetSecret", "o", session)
	if err != nil {
		return nil, unavailable(err)
	}
	if len(out) != 1 {
		return nil, fmt.Errorf("%w: GetSecret reply", ErrUnavailable)
	}
	fields, _ := out[0].([]any)
	if len(fields) != 4 {
		return nil, fmt.Errorf("%w: GetSecret reply", ErrUnavailable)
	}
	secret, _ := fields[2].([]byte)
	if len(secret) == 0 {
		return nil, fmt.Errorf("%w: GetSecret returned no secret", ErrUnavailable)
	}
	return secret, nil
}

// collectionReady is the second signal before an empty search reads as an
// absent item: the default collection must exist and be unlocked. A missing
// alias, a locked or replaced collection, or a malformed reply reads
// ErrUnavailable.
func (s secretService) collectionReady(conn busCaller) error {
	out, err := conn.call(secretsBus, defaultCollection, "org.freedesktop.DBus.Properties", "Get", "ss", secretsCollection, "Locked")
	if err != nil {
		return unavailable(err)
	}
	return collectionLocked(out)
}

// collectionLocked reads the reply of Properties.Get(Collection, "Locked").
func collectionLocked(out []any) error {
	if len(out) != 1 {
		return fmt.Errorf("%w: Locked reply", ErrUnavailable)
	}
	v, ok := out[0].(variant)
	if !ok || v.sig != "b" {
		return fmt.Errorf("%w: Locked reply", ErrUnavailable)
	}
	locked, ok := v.value.(bool)
	if !ok {
		return fmt.Errorf("%w: Locked reply", ErrUnavailable)
	}
	if locked {
		return fmt.Errorf("%w: default collection is locked", ErrUnavailable)
	}
	return nil
}

func (s secretService) Delete(key string) error {
	conn, _, err := s.session()
	if err != nil {
		return err
	}
	defer conn.Close()
	path, err := s.find(conn, key)
	if err != nil || path == "" {
		return err
	}
	out, err := conn.call(secretsBus, path, secretsItem, "Delete", "")
	if err != nil {
		return unavailable(err)
	}
	if prompt, _ := out[0].(string); prompt != "/" {
		return fmt.Errorf("%w: secret service requires a prompt", ErrUnavailable)
	}
	return nil
}
