package client

import (
	"context"
	"errors"
	"time"

	credentials "github.com/openabstractions/abstraction-credentials/go"
	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
	"github.com/openabstractions/abstraction-identity/listen"
)

// SecretReader explicitly selects reader@1. Successful Read exports the saved
// value to this app; the app clears Value.Secret after use. No call retries or
// falls back to another credential profile.
type SecretReader struct{ transport listen.FrameClient }

func NewSecretReader(endpoint string) *SecretReader {
	return NewSecretReaderWithTransport(listen.FrameClient{Endpoint: endpoint})
}
func NewSecretReaderWithTransport(transport listen.FrameClient) *SecretReader {
	return &SecretReader{transport: transport.WithDefaults(5*time.Second, 1<<20)}
}

type sensitiveExchange struct {
	transport         wire.FrameExchanger
	request, response []byte
}

func (t *sensitiveExchange) ExchangeFrame(frame []byte) ([]byte, error) {
	t.request = frame
	reply, err := t.transport.ExchangeFrame(frame)
	t.response = reply
	return reply, err
}
func clear(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
func (t *sensitiveExchange) close() { clear(t.request); clear(t.response) }

func validateRead(v wire.SecretReadResult, name string) bool {
	if v.Outcome != wire.SecretReadOutcomeRead {
		return v.Value == nil
	}
	return v.Value != nil && v.Value.Name == name && v.Value.Revision != "" && len(v.Value.Revision) <= 128 && len(v.Value.Secret) >= 1 && len(v.Value.Secret) <= credentials.MaxSecretBytes
}

func (c *SecretReader) Read(ctx context.Context, name string) (SecretReadResult, error) {
	return readSecret(ctx, name, c.transport.WithContext(ctx))
}

func readSecret(ctx context.Context, name string, transport wire.FrameExchanger) (SecretReadResult, error) {
	if err := ctx.Err(); err != nil {
		return SecretReadResult{}, err
	}
	exchange := &sensitiveExchange{transport: transport}
	defer exchange.close()
	v, err := wire.NewSecretReaderClient(exchange).Read(name)
	if err == nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	if err == nil && !validateRead(v, name) {
		err = ErrInconsistent
	}
	if err != nil {
		if v.Value != nil {
			clear(v.Value.Secret)
		}
		var refusal *wire.Refusal
		if errors.As(err, &refusal) {
			return SecretReadResult{}, &wire.Refusal{Word: refusal.Word}
		}
		if errors.Is(err, ErrInconsistent) {
			return SecretReadResult{}, ErrInconsistent
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return SecretReadResult{}, err
		}
		var service *wire.ServiceError
		if errors.As(err, &service) && service.Code.Known() {
			return SecretReadResult{}, &wire.ServiceError{Code: service.Code}
		}
		// Service diagnostics on a raw-value route are never reflected to the
		// caller. A failure conveys no presumed value or successful disclosure.
		return SecretReadResult{}, errors.New("credentials client: raw read call failed")
	}
	return v, nil
}

type ScopedHolder struct{ transport listen.FrameClient }

func NewScopedHolder(endpoint string) *ScopedHolder {
	return NewScopedHolderWithTransport(listen.FrameClient{Endpoint: endpoint})
}
func NewScopedHolderWithTransport(transport listen.FrameClient) *ScopedHolder {
	return &ScopedHolder{transport: transport.WithDefaults(5*time.Second, 1<<20)}
}
func validateMetadata(m *wire.Metadata, name string) bool {
	return m != nil && m.Name == name && m.Revision != "" && len(m.Revision) <= 128
}
func (c *ScopedHolder) Store(ctx context.Context, expected string, reg Registration) (StoreResult, error) {
	if err := ctx.Err(); err != nil {
		return StoreResult{}, err
	}
	exchange := &sensitiveExchange{transport: c.transport.WithContext(ctx)}
	defer exchange.close()
	v, err := wire.NewScopedHolderClient(exchange).Store(expected, reg)
	if err == nil {
		evaluated := v.Outcome == wire.StoreOutcomeStored || v.Outcome == wire.StoreOutcomeConflict && v.Current != nil
		err = check((!evaluated && v.Current == nil && v.Revision == "") || (evaluated && validateMetadata(v.Current, reg.Name) && v.Revision == v.Current.Revision))
	}
	if err != nil {
		return StoreResult{}, err
	}
	return v, nil
}
func (c *ScopedHolder) Rotate(ctx context.Context, expected string, rotation Rotation) (RotateResult, error) {
	if err := ctx.Err(); err != nil {
		return RotateResult{}, err
	}
	exchange := &sensitiveExchange{transport: c.transport.WithContext(ctx)}
	defer exchange.close()
	v, err := wire.NewScopedHolderClient(exchange).Rotate(expected, rotation)
	if err == nil {
		evaluated := v.Outcome == wire.RotateOutcomeRotated || v.Outcome == wire.RotateOutcomeConflict
		err = check((evaluated && validateMetadata(v.Current, rotation.Name) && v.Revision == v.Current.Revision) || (!evaluated && v.Current == nil && v.Revision == ""))
	}
	if err != nil {
		return RotateResult{}, err
	}
	return v, nil
}
func (c *ScopedHolder) Revoke(ctx context.Context, expected, name string) (RevokeResult, error) {
	if err := ctx.Err(); err != nil {
		return RevokeResult{}, err
	}
	v, err := wire.NewScopedHolderClient(c.transport.WithContext(ctx)).Revoke(expected, name)
	if err == nil {
		evaluated := v.Outcome == wire.RevokeOutcomeRevoked || v.Outcome == wire.RevokeOutcomeConflict
		err = check(evaluated == (v.Revision != ""))
	}
	if err != nil {
		return RevokeResult{}, err
	}
	return v, nil
}
func (c *ScopedHolder) Metadata(ctx context.Context, name string) (MetadataReadResult, error) {
	if err := ctx.Err(); err != nil {
		return MetadataReadResult{}, err
	}
	v, err := wire.NewScopedHolderClient(c.transport.WithContext(ctx)).Metadata(name)
	if err == nil {
		err = check((v.Outcome == wire.MetadataReadOutcomeFound && validateMetadata(v.Current, name)) || (v.Outcome != wire.MetadataReadOutcomeFound && v.Current == nil))
	}
	if err != nil {
		return MetadataReadResult{}, err
	}
	return v, nil
}

type ScopedApplier struct{ transport listen.FrameClient }

func NewScopedApplier(endpoint string) *ScopedApplier {
	return NewScopedApplierWithTransport(listen.FrameClient{Endpoint: endpoint})
}
func NewScopedApplierWithTransport(transport listen.FrameClient) *ScopedApplier {
	return &ScopedApplier{transport: transport.WithDefaults(5*time.Second, 1<<20)}
}
func (c *ScopedApplier) Check(ctx context.Context, use Use) (CheckResult, error) {
	if err := ctx.Err(); err != nil {
		return CheckResult{}, err
	}
	return wire.NewScopedApplierClient(c.transport.WithContext(ctx)).Check(use)
}
func (c *ScopedApplier) Apply(ctx context.Context, use Use) (ApplyResult, error) {
	if err := ctx.Err(); err != nil {
		return ApplyResult{}, err
	}
	exchange := &sensitiveExchange{transport: c.transport.WithContext(ctx)}
	defer exchange.close()
	v, err := wire.NewScopedApplierClient(exchange).Apply(use)
	if err == nil {
		err = check((v.Outcome == wire.ApplyOutcomeApplied) == (len(v.Headers) > 0))
	}
	if err != nil {
		return ApplyResult{}, err
	}
	return v, nil
}
