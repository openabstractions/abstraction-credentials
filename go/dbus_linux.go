//go:build linux

package credentials

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// A minimal D-Bus client: EXTERNAL authentication over a unix socket, method
// calls and replies with the little-endian wire format, and the types the
// Secret Service calls use (y b u s o g v ay as a{sv} a{ss} ao (oayays)).

type variant struct {
	sig   string
	value any
}

type dbusConn struct {
	conn   net.Conn
	reader *bufio.Reader
	serial uint32
}

var errDBusProtocol = errors.New("credentials: d-bus protocol error")

func dialBus(address string, timeout time.Duration) (*dbusConn, error) {
	path := ""
	for _, part := range strings.Split(address, ";") {
		transport, params, ok := strings.Cut(part, ":")
		if !ok || transport != "unix" {
			continue
		}
		for _, kv := range strings.Split(params, ",") {
			k, v, _ := strings.Cut(kv, "=")
			switch k {
			case "path":
				path = unescapeAddress(v)
			case "abstract":
				path = "@" + unescapeAddress(v)
			}
		}
		if path != "" {
			break
		}
	}
	if path == "" {
		return nil, fmt.Errorf("%w: no unix session bus address", ErrUnavailable)
	}
	c, err := net.DialTimeout("unix", path, timeout)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	_ = c.SetDeadline(time.Now().Add(timeout))
	d := &dbusConn{conn: c, reader: bufio.NewReader(c)}
	uid := hex.EncodeToString([]byte(strconv.Itoa(os.Getuid())))
	if _, err := c.Write([]byte("\x00AUTH EXTERNAL " + uid + "\r\n")); err != nil {
		c.Close()
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	line, err := d.reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "OK ") {
		c.Close()
		return nil, fmt.Errorf("%w: d-bus authentication refused", ErrUnavailable)
	}
	if _, err := c.Write([]byte("BEGIN\r\n")); err != nil {
		c.Close()
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if _, err := d.call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "Hello", ""); err != nil {
		c.Close()
		return nil, err
	}
	return d, nil
}

func unescapeAddress(v string) string {
	var out strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] == '%' && i+2 < len(v) {
			if b, err := hex.DecodeString(v[i+1 : i+3]); err == nil {
				out.WriteByte(b[0])
				i += 2
				continue
			}
		}
		out.WriteByte(v[i])
	}
	return out.String()
}

func (d *dbusConn) Close() error { return d.conn.Close() }

// dbusError is an error reply; name is the D-Bus error name.
type dbusError struct{ name, message string }

func (e *dbusError) Error() string { return "d-bus " + e.name + ": " + e.message }

func (d *dbusConn) call(dest, path, iface, member, sig string, args ...any) ([]any, error) {
	d.serial++
	serial := d.serial
	var body encoder
	if err := body.values(sig, args); err != nil {
		return nil, err
	}
	fields := []any{
		[]any{byte(1), variant{"o", path}},
		[]any{byte(2), variant{"s", iface}},
		[]any{byte(3), variant{"s", member}},
		[]any{byte(6), variant{"s", dest}},
	}
	if sig != "" {
		fields = append(fields, []any{byte(8), variant{"g", sig}})
	}
	var msg encoder
	msg.buf = append(msg.buf, 'l', 1, 0, 1)
	msg.u32(uint32(len(body.buf)))
	msg.u32(serial)
	if err := msg.value("a(yv)", fields); err != nil {
		return nil, err
	}
	msg.align(8)
	msg.buf = append(msg.buf, body.buf...)
	if _, err := d.conn.Write(msg.buf); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	for {
		kind, replyTo, errName, replySig, payload, err := d.read()
		if err != nil {
			return nil, err
		}
		if (kind != 2 && kind != 3) || replyTo != serial {
			continue
		}
		dec := decoder{buf: payload}
		values, err := dec.values(replySig)
		if err != nil {
			return nil, err
		}
		if kind == 3 {
			message := ""
			if len(values) > 0 {
				message, _ = values[0].(string)
			}
			return nil, &dbusError{name: errName, message: message}
		}
		return values, nil
	}
}

func (d *dbusConn) read() (kind byte, replyTo uint32, errName, sig string, body []byte, err error) {
	head := make([]byte, 16)
	if _, err = io.ReadFull(d.reader, head); err != nil {
		return 0, 0, "", "", nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if head[0] != 'l' {
		return 0, 0, "", "", nil, errDBusProtocol
	}
	bodyLen := binary.LittleEndian.Uint32(head[4:8])
	fieldsLen := binary.LittleEndian.Uint32(head[12:16])
	if bodyLen > 1<<20 || fieldsLen > 1<<16 {
		return 0, 0, "", "", nil, errDBusProtocol
	}
	pad := (8 - (16+int(fieldsLen))%8) % 8
	rest := make([]byte, int(fieldsLen)+pad+int(bodyLen))
	if _, err = io.ReadFull(d.reader, rest); err != nil {
		return 0, 0, "", "", nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	all := append(head, rest...)
	dec := decoder{buf: all, pos: 12}
	fields, err := dec.value("a(yv)")
	if err != nil {
		return 0, 0, "", "", nil, err
	}
	for _, f := range fields.([]any) {
		pair := f.([]any)
		code, v := pair[0].(byte), pair[1].(variant)
		switch code {
		case 4:
			errName, _ = v.value.(string)
		case 5:
			replyTo, _ = v.value.(uint32)
		case 8:
			sig, _ = v.value.(string)
		}
	}
	return head[1], replyTo, errName, sig, all[16+int(fieldsLen)+pad:], nil
}

type encoder struct{ buf []byte }

func (e *encoder) align(n int) {
	for len(e.buf)%n != 0 {
		e.buf = append(e.buf, 0)
	}
}
func (e *encoder) u32(v uint32) { e.align(4); e.buf = binary.LittleEndian.AppendUint32(e.buf, v) }

func (e *encoder) values(sig string, args []any) error {
	types, err := splitSignature(sig)
	if err != nil || len(types) != len(args) {
		return fmt.Errorf("%w: arguments do not match signature %q", errDBusProtocol, sig)
	}
	for i, t := range types {
		if err := e.value(t, args[i]); err != nil {
			return err
		}
	}
	return nil
}

func (e *encoder) value(sig string, v any) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("%w: value does not match signature %q", errDBusProtocol, sig)
		}
	}()
	switch sig[0] {
	case 'y':
		e.buf = append(e.buf, v.(byte))
	case 'b':
		b := uint32(0)
		if v.(bool) {
			b = 1
		}
		e.u32(b)
	case 'u':
		e.u32(v.(uint32))
	case 's', 'o':
		s := v.(string)
		e.u32(uint32(len(s)))
		e.buf = append(append(e.buf, s...), 0)
	case 'g':
		s := v.(string)
		e.buf = append(append(append(e.buf, byte(len(s))), s...), 0)
	case 'v':
		x := v.(variant)
		if err := e.value("g", x.sig); err != nil {
			return err
		}
		return e.value(x.sig, x.value)
	case 'a':
		elem := sig[1:]
		if elem == "y" {
			b := v.([]byte)
			e.u32(uint32(len(b)))
			e.buf = append(e.buf, b...)
			return nil
		}
		e.u32(0)
		lenAt := len(e.buf) - 4
		e.align(alignment(elem[0]))
		start := len(e.buf)
		for _, item := range v.([]any) {
			if err := e.value(elem, item); err != nil {
				return err
			}
		}
		binary.LittleEndian.PutUint32(e.buf[lenAt:], uint32(len(e.buf)-start))
	case '(', '{':
		e.align(8)
		inner, err := splitSignature(sig[1 : len(sig)-1])
		if err != nil {
			return err
		}
		items := v.([]any)
		if len(items) != len(inner) {
			return errDBusProtocol
		}
		for i, t := range inner {
			if err := e.value(t, items[i]); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("%w: unsupported type %q", errDBusProtocol, sig)
	}
	return nil
}

func alignment(c byte) int {
	switch c {
	case 'y', 'g', 'v':
		return 1
	case 'b', 'u', 's', 'o', 'a':
		return 4
	default:
		return 8
	}
}

// splitSignature splits a signature into complete single types.
func splitSignature(sig string) ([]string, error) {
	var out []string
	for i := 0; i < len(sig); {
		n, err := typeLength(sig[i:])
		if err != nil {
			return nil, err
		}
		out = append(out, sig[i:i+n])
		i += n
	}
	return out, nil
}

func typeLength(sig string) (int, error) {
	if sig == "" {
		return 0, errDBusProtocol
	}
	switch sig[0] {
	case 'a':
		n, err := typeLength(sig[1:])
		return n + 1, err
	case '(', '{':
		closing := byte(')')
		if sig[0] == '{' {
			closing = '}'
		}
		i := 1
		for i < len(sig) && sig[i] != closing {
			n, err := typeLength(sig[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
		if i >= len(sig) {
			return 0, errDBusProtocol
		}
		return i + 1, nil
	default:
		return 1, nil
	}
}

type decoder struct {
	buf []byte
	pos int
}

func (d *decoder) align(n int) error {
	for d.pos%n != 0 {
		d.pos++
	}
	if d.pos > len(d.buf) {
		return errDBusProtocol
	}
	return nil
}

func (d *decoder) u32() (uint32, error) {
	if err := d.align(4); err != nil || d.pos+4 > len(d.buf) {
		return 0, errDBusProtocol
	}
	v := binary.LittleEndian.Uint32(d.buf[d.pos:])
	d.pos += 4
	return v, nil
}

func (d *decoder) values(sig string) ([]any, error) {
	types, err := splitSignature(sig)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(types))
	for _, t := range types {
		v, err := d.value(t)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (d *decoder) value(sig string) (any, error) {
	switch sig[0] {
	case 'y':
		if d.pos >= len(d.buf) {
			return nil, errDBusProtocol
		}
		d.pos++
		return d.buf[d.pos-1], nil
	case 'b':
		v, err := d.u32()
		return v == 1, err
	case 'u':
		return d.u32()
	case 'i':
		v, err := d.u32()
		return int32(v), err
	case 's', 'o':
		n, err := d.u32()
		if err != nil || d.pos+int(n)+1 > len(d.buf) {
			return nil, errDBusProtocol
		}
		s := string(d.buf[d.pos : d.pos+int(n)])
		d.pos += int(n) + 1
		return s, nil
	case 'g':
		if d.pos >= len(d.buf) {
			return nil, errDBusProtocol
		}
		n := int(d.buf[d.pos])
		if d.pos+1+n+1 > len(d.buf) {
			return nil, errDBusProtocol
		}
		s := string(d.buf[d.pos+1 : d.pos+1+n])
		d.pos += n + 2
		return s, nil
	case 'v':
		s, err := d.value("g")
		if err != nil {
			return nil, err
		}
		inner := s.(string)
		if n, err := typeLength(inner); err != nil || n != len(inner) {
			return nil, errDBusProtocol
		}
		v, err := d.value(inner)
		return variant{inner, v}, err
	case 'a':
		n, err := d.u32()
		if err != nil {
			return nil, err
		}
		elem := sig[1:]
		if err := d.align(alignment(elem[0])); err != nil {
			return nil, err
		}
		end := d.pos + int(n)
		if end > len(d.buf) {
			return nil, errDBusProtocol
		}
		if elem == "y" {
			b := append([]byte(nil), d.buf[d.pos:end]...)
			d.pos = end
			return b, nil
		}
		items := []any{}
		for d.pos < end {
			v, err := d.value(elem)
			if err != nil {
				return nil, err
			}
			items = append(items, v)
		}
		return items, nil
	case '(', '{':
		if err := d.align(8); err != nil {
			return nil, err
		}
		inner, err := splitSignature(sig[1 : len(sig)-1])
		if err != nil {
			return nil, err
		}
		items := make([]any, 0, len(inner))
		for _, t := range inner {
			v, err := d.value(t)
			if err != nil {
				return nil, err
			}
			items = append(items, v)
		}
		return items, nil
	default:
		return nil, fmt.Errorf("%w: unsupported type %q", errDBusProtocol, sig)
	}
}
