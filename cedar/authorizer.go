package cedar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wasmhost"
	"github.com/jackc/puddle/v2"
	"sync/atomic"
)

// Authorizer is safe for concurrent use; pooled instances each own their parsed state.
// Faulted instances are discarded and replaced on demand.
type Authorizer struct {
	rt        *Runtime
	load      []byte
	limits    Limits
	pool      *puddle.Pool[*wasmhost.Instance]
	created   atomic.Uint64
	discarded atomic.Uint64
}

// Authorize returns Deny on every error so callers fail closed.
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

// Close waits for calls in progress before releasing their instances.
func (a *Authorizer) Close() {
	a.pool.Close()
}
