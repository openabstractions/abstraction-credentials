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

func (s secretService) find(conn *dbusConn, key string) (string, error) {
	out, err := conn.call(secretsBus, secretsPath, secretsService, "SearchItems", "a{ss}", []any{[]any{keyAttribute, key}})
	if err != nil {
		return "", unavailable(err)
	}
	unlocked, _ := out[0].([]any)
	locked, _ := out[1].([]any)
	if len(unlocked) > 0 {
		path, _ := unlocked[0].(string)
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
	path, err := s.find(conn, key)
	if err != nil {
		return nil, err
	}
	if path == "" {
		return nil, ErrNotFound
	}
	out, err := conn.call(secretsBus, path, secretsItem, "GetSecret", "o", session)
	if err != nil {
		return nil, unavailable(err)
	}
	fields, _ := out[0].([]any)
	if len(fields) != 4 {
		return nil, fmt.Errorf("%w: GetSecret reply", ErrUnavailable)
	}
	secret, _ := fields[2].([]byte)
	if len(secret) == 0 {
		return nil, ErrNotFound
	}
	return secret, nil
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
