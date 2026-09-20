// Package client binds explicitly selected credentials holder and applier
// services over shared framed IPC. A call failure preserves uncertainty; no
// call is retried.
package client

import (
	"context"
	"errors"
	"time"

	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
	"github.com/openabstractions/abstraction-identity/listen"
)

// ErrInconsistent is a reply whose outcome and fields contradict the contract.
var ErrInconsistent = errors.New("credentials client: inconsistent reply")

// Holder calls abstraction.credentials/holder@1.
type Holder struct{ transport listen.FrameClient }

// NewHolder binds an explicit endpoint.
func NewHolder(endpoint string) *Holder {
	return NewHolderWithTransport(listen.FrameClient{Endpoint: endpoint})
}

// NewHolderWithTransport retains the caller's endpoint, server trust and limits.
func NewHolderWithTransport(transport listen.FrameClient) *Holder {
	return &Holder{transport: transport.WithDefaults(5*time.Second, 1<<20)}
}

func check(ok bool) error {
	if ok {
		return nil
	}
	return ErrInconsistent
}

// Store registers one secret by name. The caller zeroes the secret after the
// call returns; the client keeps no copy.
func (c *Holder) Store(ctx context.Context, expectedRevision string, registration Registration) (wire.StoreResult, error) {
	if err := ctx.Err(); err != nil {
		return wire.StoreResult{}, err
	}
	v, err := wire.NewHolderClient(c.transport.WithContext(ctx)).Store(expectedRevision, registration)
	if err == nil {
		evaluated := v.Outcome == wire.StoreOutcomeStored || v.Outcome == wire.StoreOutcomeConflict
		err = check(evaluated == (v.Current != nil) && (v.Outcome != wire.StoreOutcomeStored || v.Revision != ""))
	}
	return v, err
}

// Rotate replaces the bytes and expiry of a registered name.
func (c *Holder) Rotate(ctx context.Context, expectedRevision string, rotation Rotation) (wire.RotateResult, error) {
	if err := ctx.Err(); err != nil {
		return wire.RotateResult{}, err
	}
	v, err := wire.NewHolderClient(c.transport.WithContext(ctx)).Rotate(expectedRevision, rotation)
	if err == nil {
		err = check(v.Outcome != wire.RotateOutcomeRotated || v.Revision != "")
	}
	return v, err
}

// Revoke destroys the bytes of a registered name and keeps its tombstone.
func (c *Holder) Revoke(ctx context.Context, expectedRevision, name string) (wire.RevokeResult, error) {
	if err := ctx.Err(); err != nil {
		return wire.RevokeResult{}, err
	}
	return wire.NewHolderClient(c.transport.WithContext(ctx)).Revoke(expectedRevision, name)
}

// List reads one page of metadata and the provider limits.
func (c *Holder) List(ctx context.Context, cursor string, limit int64) (wire.MetadataPage, error) {
	if err := ctx.Err(); err != nil {
		return wire.MetadataPage{}, err
	}
	v, err := wire.NewHolderClient(c.transport.WithContext(ctx)).List(cursor, limit)
	if err == nil {
		if v.Outcome == wire.PageOutcomePage {
			err = check(int64(len(v.Records)) <= limit && v.Complete == (v.Next == ""))
		} else {
			err = check(len(v.Records) == 0 && v.Next == "" && !v.Complete)
		}
	}
	return v, err
}

// Audit reads one page of the retained credential events.
func (c *Holder) Audit(ctx context.Context, cursor string, maxEntries int64) (wire.AuditPage, error) {
	if err := ctx.Err(); err != nil {
		return wire.AuditPage{}, err
	}
	v, err := wire.NewHolderClient(c.transport.WithContext(ctx)).Audit(cursor, maxEntries)
	if err == nil {
		err = check(int64(len(v.Entries)) <= maxEntries && (v.Outcome == wire.PageOutcomePage || len(v.Entries) == 0))
	}
	return v, err
}

// Applier calls abstraction.credentials/applier@1. Only a designated enforcer
// program receives anything except forbidden.
type Applier struct{ transport listen.FrameClient }

// NewApplier binds an explicit endpoint.
func NewApplier(endpoint string) *Applier {
	return NewApplierWithTransport(listen.FrameClient{Endpoint: endpoint})
}

// NewApplierWithTransport retains the caller's endpoint, server trust and limits.
func NewApplierWithTransport(transport listen.FrameClient) *Applier {
	return &Applier{transport: transport.WithDefaults(5*time.Second, 1<<20)}
}

// Check evaluates a use without reading the secret.
func (c *Applier) Check(ctx context.Context, usage Use) (wire.CheckResult, error) {
	if err := ctx.Err(); err != nil {
		return wire.CheckResult{}, err
	}
	return wire.NewApplierClient(c.transport.WithContext(ctx)).Check(usage)
}

// Apply returns headers for one request. The caller sends them once and keeps
// them out of every record, log and reply.
func (c *Applier) Apply(ctx context.Context, usage Use) (wire.ApplyResult, error) {
	if err := ctx.Err(); err != nil {
		return wire.ApplyResult{}, err
	}
	v, err := wire.NewApplierClient(c.transport.WithContext(ctx)).Apply(usage)
	if err == nil {
		err = check((v.Outcome == wire.ApplyOutcomeApplied) == (len(v.Headers) > 0))
	}
	return v, err
}
