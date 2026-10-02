package cedar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wasmhost"
	"github.com/jackc/puddle/v2"
)

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
