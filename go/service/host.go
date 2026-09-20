// Package service hosts the credentials holder and applier contracts on one
// shared framed IPC endpoint.
package service

import (
	"context"
	"errors"
	"os/user"
	"runtime"
	"strconv"
	"sync"
	"time"

	credentials "github.com/openabstractions/abstraction-credentials/go"
	wire "github.com/openabstractions/abstraction-credentials/go/abstraction/credentials/api"
	identity "github.com/openabstractions/abstraction-identity"
	"github.com/openabstractions/abstraction-identity/listen"
)

const MaxFrameBytes = 1 << 20

// AuthorizeEnforcer designates the consuming service programs allowed to call
// Check and Apply for a consumer contract and credential name. It receives the
// Program-proven peer. It must honor ctx and be safe for concurrent calls.
type AuthorizeEnforcer func(ctx context.Context, peer *identity.Peer, consumer, name string) bool

type Host struct {
	lifecycle sync.Mutex
	serving   bool
	listener  listen.Listener
	owner     string
	holder    *credentials.Holder
	decide    credentials.Decider
	enforcer  AuthorizeEnforcer
	ctx       context.Context
	cancel    context.CancelFunc
	once      sync.Once
	workers   sync.WaitGroup
	slots     chan struct{}
	OnError   func(error)
	// Assign before Serve. Called when admission stops, before calls drain.
	OnStopped func()
}

// Listen requires an explicit holder and decision function. A nil enforcer
// designation refuses every Check and Apply.
func Listen(endpoint string, holder *credentials.Holder, decide credentials.Decider, enforcer AuthorizeEnforcer) (*Host, error) {
	if holder == nil || decide == nil {
		return nil, errors.New("credentials service: holder and decision function required")
	}
	owner, err := user.Current()
	if err != nil {
		return nil, err
	}
	if owner.Uid == "" {
		return nil, errors.New("credentials service: service principal unavailable")
	}
	l, err := listen.Listen(endpoint)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Host{listener: l, owner: owner.Uid, holder: holder, decide: decide, enforcer: enforcer, ctx: ctx, cancel: cancel, slots: make(chan struct{}, 32)}, nil
}

// ApplierAvailable reports whether an enforcer designation is configured.
func (h *Host) ApplierAvailable() bool { return h.enforcer != nil }

func (h *Host) Close() error {
	var err error
	h.once.Do(func() { h.cancel(); err = h.listener.Close() })
	return err
}

func (h *Host) Serve(ctx context.Context) error {
	h.lifecycle.Lock()
	if h.serving {
		h.lifecycle.Unlock()
		return errors.New("credentials service: host already served")
	}
	h.serving = true
	h.lifecycle.Unlock()
	stop := context.AfterFunc(ctx, func() { h.Close() })
	defer stop()
	defer h.workers.Wait()
	defer func() {
		if h.OnStopped != nil {
			h.OnStopped()
		}
	}()
	defer h.Close()
	for {
		conn, err := h.listener.Accept()
		if err != nil {
			if ctx.Err() != nil || h.ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case h.slots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		h.workers.Add(1)
		go func() {
			defer h.workers.Done()
			defer func() { <-h.slots }()
			defer conn.Close()
			callCtx, cancel := context.WithTimeout(h.ctx, 5*time.Second)
			defer cancel()
			call, err := listen.ReceiveFramed(callCtx, conn, listen.Program, MaxFrameBytes)
			if call != nil {
				defer call.Close()
			}
			if err == nil {
				base := receiver{host: h, call: call, ctx: callCtx}
				var reply []byte
				reply, err = wire.ServeEndpoint(call.Frame, "openabstractions", "",
					&wire.HolderDispatcher{Handler: &holderReceiver{base}},
					&wire.ApplierDispatcher{Handler: &applierReceiver{base}})
				if err == nil {
					err = call.Reply(reply)
				}
			}
			if err != nil && h.OnError != nil && h.ctx.Err() == nil {
				h.OnError(err)
			}
		}()
	}
}

type receiver struct {
	host *Host
	call *listen.FramedCall
	ctx  context.Context
}

// SubjectFromPeer binds account and program from Program proof.
func SubjectFromPeer(peer *identity.Peer) (wire.Subject, error) {
	if peer == nil {
		return wire.Subject{}, errors.New("credentials service: native subject evidence required")
	}
	if err := peer.Check(listen.Program); err != nil {
		return wire.Subject{}, err
	}
	u, err := peer.User.AtLeast(listen.Program.User)
	if err != nil {
		return wire.Subject{}, err
	}
	account := ""
	if u.Kind == "windows" {
		account = u.SID
	} else if u.Kind == "posix" && u.UID >= 0 {
		account = strconv.Itoa(u.UID)
	}
	program, err := identity.SubjectProgram(peer, listen.Program.Path)
	if err != nil || account == "" {
		return wire.Subject{}, errors.New("credentials service: native subject account/program unavailable")
	}
	return wire.Subject{Account: account, Program: program}, nil
}

func (r *receiver) caller() (wire.Subject, *identity.Peer, bool) {
	peer, err := r.call.Peer()
	if err != nil {
		return wire.Subject{}, nil, false
	}
	subject, err := SubjectFromPeer(peer)
	if err != nil || subject.Account != r.host.owner {
		return wire.Subject{}, nil, false
	}
	return subject, peer, true
}

type holderReceiver struct{ receiver }

// authorize returns the bound subject and "" for a permit, or the refusal word.
func (r *holderReceiver) authorize(action string) (wire.Subject, string) {
	subject, _, ok := r.caller()
	if !ok {
		return wire.Subject{}, "forbidden"
	}
	word, err := r.host.decide(r.ctx, subject, action, credentials.ResourceAccount)
	if err != nil || r.ctx.Err() != nil {
		if err != nil && r.host.OnError != nil {
			r.host.OnError(err)
		}
		return wire.Subject{}, "unavailable"
	}
	switch word {
	case "permitted":
	case "denied", "not_granted", "unknown_action":
		return wire.Subject{}, "forbidden"
	default:
		return wire.Subject{}, "unavailable"
	}
	if r.call.Recheck() != nil {
		return wire.Subject{}, "forbidden"
	}
	return subject, ""
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func storeRefusal(word string) wire.StoreOutcome {
	switch word {
	case "forbidden":
		return wire.StoreOutcomeForbidden
	case "unavailable":
		return wire.StoreOutcomeUnavailable
	}
	return 0
}
func rotateRefusal(word string) wire.RotateOutcome {
	switch word {
	case "forbidden":
		return wire.RotateOutcomeForbidden
	case "unavailable":
		return wire.RotateOutcomeUnavailable
	}
	return 0
}
func revokeRefusal(word string) wire.RevokeOutcome {
	switch word {
	case "forbidden":
		return wire.RevokeOutcomeForbidden
	case "unavailable":
		return wire.RevokeOutcomeUnavailable
	}
	return 0
}
func pageRefusal(word string) wire.PageOutcome {
	switch word {
	case "forbidden":
		return wire.PageOutcomeForbidden
	case "unavailable":
		return wire.PageOutcomeUnavailable
	}
	return 0
}

func (r *holderReceiver) Store(expected string, reg wire.Registration) (wire.StoreResult, error) {
	subject, refusal := r.authorize(credentials.ActionManage)
	if refusal != "" {
		zero(reg.Secret)
		return wire.StoreResult{Outcome: storeRefusal(refusal)}, nil
	}
	return r.host.holder.Store(subject, expected, reg), nil
}

func (r *holderReceiver) Rotate(expected string, rotation wire.Rotation) (wire.RotateResult, error) {
	subject, refusal := r.authorize(credentials.ActionManage)
	if refusal != "" {
		zero(rotation.Secret)
		return wire.RotateResult{Outcome: rotateRefusal(refusal)}, nil
	}
	return r.host.holder.Rotate(subject, expected, rotation), nil
}

func (r *holderReceiver) Revoke(expected, name string) (wire.RevokeResult, error) {
	subject, refusal := r.authorize(credentials.ActionManage)
	if refusal != "" {
		return wire.RevokeResult{Outcome: revokeRefusal(refusal)}, nil
	}
	return r.host.holder.Revoke(subject, expected, name), nil
}

func (r *holderReceiver) List(cursor string, limit int64) (wire.MetadataPage, error) {
	subject, refusal := r.authorize(credentials.ActionRead)
	if refusal != "" {
		return credentials.RefusedMetadataPage(pageRefusal(refusal)), nil
	}
	return r.host.holder.List(subject.Account, cursor, limit), nil
}

func (r *holderReceiver) Audit(cursor string, maxEntries int64) (wire.AuditPage, error) {
	subject, refusal := r.authorize(credentials.ActionRead)
	if refusal != "" {
		return wire.AuditPage{Outcome: pageRefusal(refusal), Entries: []wire.AuditEntry{}, Next: cursor}, nil
	}
	return r.host.holder.Audit(subject.Account, cursor, maxEntries), nil
}

type applierReceiver struct{ receiver }

func (r *applierReceiver) designated(use wire.Use) bool {
	if runtime.GOOS == "darwin" || r.host.enforcer == nil {
		return false
	}
	_, peer, ok := r.caller()
	if !ok || use.Subject.Account != r.host.owner {
		return false
	}
	if !r.host.enforcer(r.ctx, peer, use.Consumer, use.Name) || r.ctx.Err() != nil {
		return false
	}
	return r.call.Recheck() == nil
}

func (r *applierReceiver) Check(use wire.Use) (wire.CheckResult, error) {
	if !r.designated(use) {
		return wire.CheckResult{Outcome: wire.ApplyOutcomeForbidden}, nil
	}
	return r.host.holder.Check(r.ctx, use, r.host.decide), nil
}

func (r *applierReceiver) Apply(use wire.Use) (wire.ApplyResult, error) {
	if !r.designated(use) {
		return wire.ApplyResult{Outcome: wire.ApplyOutcomeForbidden}, nil
	}
	return r.host.holder.Apply(r.ctx, use, r.host.decide), nil
}
