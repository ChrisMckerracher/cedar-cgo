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

// Close releases the authorizer's instances. It waits for calls in
// progress to finish.
func (a *Authorizer) Close() {
	a.pool.Close()
}
