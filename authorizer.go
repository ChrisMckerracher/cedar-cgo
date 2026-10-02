package cedar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wasmhost"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
	"github.com/jackc/puddle/v2"
)

// Default per-authorizer limits.
const (
	DefaultCallTimeout        = time.Second
	DefaultLoadTimeout        = 30 * time.Second
	DefaultMaxRequestBytes    = 1 << 20
	DefaultRecycleMemoryBytes = 64 << 20
)

// Decision is the outcome of an authorization request. The zero value is
// Deny.
type Decision int

const (
	// Deny means the request is not authorized.
	Deny Decision = iota
	// Allow means the request is authorized.
	Allow
)

// String returns "allow" or "deny".
func (d Decision) String() string {
	if d == Allow {
		return "allow"
	}
	return "deny"
}

// Request is one authorization request.
type Request struct {
	Principal EntityUID
	Action    EntityUID
	Resource  EntityUID
	// Context is the request context. The zero value is the empty record.
	Context Context
	// Entities, if not zero, adds entities for this request only. Cedar
	// merges them with the authorizer's entities and recomputes the
	// ancestor closure. An entity that is in both, with different data,
	// is an error.
	Entities Entities
}

// Response is the result of an authorization request.
type Response struct {
	Decision Decision
	// Reasons lists the IDs of the policies that determined the decision,
	// sorted.
	Reasons []string
	// Errors lists the policies whose evaluation failed, sorted by ID.
	// Cedar skips those policies; the decision stands.
	Errors []PolicyMessage
}

// Limits bounds the resources of an [Authorizer]. A zero field selects its
// default.
type Limits struct {
	// MaxInstances caps the number of module instances, and so the number
	// of concurrent calls. The default is runtime.GOMAXPROCS(0).
	MaxInstances int
	// CallTimeout bounds the module's work on one Authorize call. The
	// caller's context bounds the whole call, including the wait for a free
	// instance, which may include creating one. The default is
	// [DefaultCallTimeout]. A negative value disables it.
	CallTimeout time.Duration
	// LoadTimeout bounds the creation of one instance, which parses the
	// schema, the policies and the entities. The default is
	// [DefaultLoadTimeout].
	LoadTimeout time.Duration
	// MaxRequestBytes caps the encoded size of one request, with its
	// context and entities. The default is [DefaultMaxRequestBytes].
	MaxRequestBytes int
	// RecycleMemoryBytes replaces an instance after a call that leaves its
	// linear memory larger than this, because WebAssembly memory does not
	// shrink. The default is [DefaultRecycleMemoryBytes].
	RecycleMemoryBytes uint64
}

func (l Limits) withDefaults() Limits {
	if l.MaxInstances <= 0 {
		l.MaxInstances = runtime.GOMAXPROCS(0)
	}
	if l.CallTimeout == 0 {
		l.CallTimeout = DefaultCallTimeout
	}
	if l.LoadTimeout <= 0 {
		l.LoadTimeout = DefaultLoadTimeout
	}
	if l.MaxRequestBytes <= 0 {
		l.MaxRequestBytes = DefaultMaxRequestBytes
	}
	if l.RecycleMemoryBytes == 0 {
		l.RecycleMemoryBytes = DefaultRecycleMemoryBytes
	}
	return l
}

// Config is the state and the limits of an [Authorizer].
type Config struct {
	// Schema, if not nil, makes Cedar check entities, contexts and requests
	// against it, and adds the schema's action entities. It does not
	// validate the policies; call [Runtime.Validate] for that.
	Schema *Schema
	// Policies is the policy set to evaluate.
	Policies PolicySet
	// Entities are available to every request.
	Entities Entities
	Limits   Limits
}

// Authorizer evaluates requests against one schema, policy set and entity
// set. It is safe for concurrent use.
//
// It keeps a pool of module instances. Each instance holds its own parsed
// copy of the configuration. A call that faults returns Deny, and its
// instance is discarded; the pool creates a fresh one when needed.
type Authorizer struct {
	rt        *Runtime
	load      []byte
	limits    Limits
	pool      *puddle.Pool[*wasmhost.Instance]
	created   atomic.Uint64
	discarded atomic.Uint64
}

type loadInput struct {
	Schema   *wire.Source `json:"schema"`
	Policies wire.Source  `json:"policies"`
	Entities Entities     `json:"entities,omitzero"`
}

type loadOutput struct {
	Policies *int        `json:"policies"`
	Error    *wire.Error `json:"error"`
}

// NewAuthorizer parses the configuration in one module instance, and
// returns an [*Error] if Cedar rejects it.
func (rt *Runtime) NewAuthorizer(ctx context.Context, cfg Config) (*Authorizer, error) {
	load, err := json.Marshal(loadInput{Schema: optionalSchema(cfg.Schema), Policies: cfg.Policies.wire(), Entities: cfg.Entities})
	if err != nil {
		return nil, &Error{Kind: KindInput, Message: err.Error()}
	}
	if len(load) > rt.maxSourceBytes {
		return nil, limitError("schema, policies and entities", len(load), rt.maxSourceBytes)
	}
	a := &Authorizer{rt: rt, load: load, limits: cfg.Limits.withDefaults()}
	pool, err := puddle.NewPool(&puddle.Config[*wasmhost.Instance]{
		Constructor: a.newInstance,
		Destructor:  func(i *wasmhost.Instance) { _ = i.Close(context.Background()) },
		MaxSize:     int32(min(a.limits.MaxInstances, 1<<30)),
	})
	if err != nil {
		return nil, fmt.Errorf("cedar: %w", err)
	}
	a.pool = pool
	res, err := pool.Acquire(ctx)
	if err != nil {
		pool.Close()
		return nil, err
	}
	res.Release()
	return a, nil
}

// newInstance creates and loads one instance. puddle calls it.
func (a *Authorizer) newInstance(ctx context.Context) (*wasmhost.Instance, error) {
	ctx, cancel := context.WithTimeout(ctx, a.limits.LoadTimeout)
	defer cancel()
	inst, err := a.rt.module.Instantiate(ctx)
	if err != nil {
		return nil, faultError(err)
	}
	out, err := inst.Call(ctx, "cgw_load", a.load, a.rt.maxResponse)
	if err == nil {
		var resp loadOutput
		switch err = json.Unmarshal(out, &resp); {
		case err != nil:
			err = faultError(fmt.Errorf("decode load response: %w", err))
		case resp.Error != nil:
			err = moduleError(resp.Error)
		case resp.Policies == nil:
			err = faultError(errors.New("load response has no result"))
		}
	} else {
		err = faultError(err)
	}
	if err != nil {
		_ = inst.Close(context.WithoutCancel(ctx))
		return nil, err
	}
	a.created.Add(1)
	return inst, nil
}

type authorizeInput struct {
	Principal wire.UID `json:"principal"`
	Action    wire.UID `json:"action"`
	Resource  wire.UID `json:"resource"`
	Context   Context  `json:"context"`
	Entities  Entities `json:"entities,omitzero"`
}

type authorizeOutput struct {
	Decision string          `json:"decision"`
	Reasons  []string        `json:"reasons"`
	Errors   []PolicyMessage `json:"errors"`
	Error    *wire.Error     `json:"error"`
}

// Authorize evaluates one request. On any error it returns a Response with
// the Deny decision, and the error.
func (a *Authorizer) Authorize(ctx context.Context, req Request) (Response, error) {
	in, err := json.Marshal(authorizeInput{
		Principal: req.Principal.wire(),
		Action:    req.Action.wire(),
		Resource:  req.Resource.wire(),
		Context:   req.Context,
		Entities:  req.Entities,
	})
	if err != nil {
		return Response{}, &Error{Kind: KindInput, Message: err.Error()}
	}
	if len(in) > a.limits.MaxRequestBytes {
		return Response{}, limitError("request", len(in), a.limits.MaxRequestBytes)
	}
	res, err := a.pool.Acquire(ctx)
	if err != nil {
		return Response{}, fmt.Errorf("cedar: acquire instance: %w", err)
	}
	if a.limits.CallTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, a.limits.CallTimeout)
		defer cancel()
	}
	inst := res.Value()
	out, err := inst.Call(ctx, "cgw_authorize", in, a.rt.maxResponse)
	if err != nil {
		a.finish(res)
		return Response{}, faultError(err)
	}
	resp, err := decodeAuthorize(out)
	var cerr *Error
	if errors.As(err, &cerr) && cerr.Kind == KindFault {
		inst.MarkFaulted()
	}
	a.finish(res)
	return resp, err
}

func decodeAuthorize(out []byte) (Response, error) {
	var w authorizeOutput
	if err := json.Unmarshal(out, &w); err != nil {
		return Response{}, faultError(fmt.Errorf("decode authorize response: %w", err))
	}
	if w.Error != nil {
		return Response{}, moduleError(w.Error)
	}
	var d Decision
	switch w.Decision {
	case "allow":
		d = Allow
	case "deny":
		d = Deny
	default:
		return Response{}, faultError(fmt.Errorf("authorize response has decision %q", w.Decision))
	}
	return Response{Decision: d, Reasons: w.Reasons, Errors: w.Errors}, nil
}

// finish returns an instance to the pool, or discards it if it faulted or
// grew past the recycle threshold.
func (a *Authorizer) finish(res *puddle.Resource[*wasmhost.Instance]) {
	inst := res.Value()
	if inst.Faulted() || inst.MemoryBytes() > a.limits.RecycleMemoryBytes {
		a.discarded.Add(1)
		res.Destroy()
		return
	}
	res.Release()
}

// Stats counts module instances.
type Stats struct {
	// Created counts instances created and loaded.
	Created uint64
	// Discarded counts instances discarded after a fault or after their
	// memory grew past Limits.RecycleMemoryBytes.
	Discarded uint64
	// Idle is the number of instances ready for a call.
	Idle int
}

// Stats returns instance counts.
func (a *Authorizer) Stats() Stats {
	return Stats{Created: a.created.Load(), Discarded: a.discarded.Load(), Idle: int(a.pool.Stat().IdleResources())}
}

// Close releases the authorizer's instances. It waits for calls in
// progress to finish.
func (a *Authorizer) Close() {
	a.pool.Close()
}
