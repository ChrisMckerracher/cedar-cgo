package execution

import (
	puddle "github.com/jackc/puddle/v2"

	"context"
	"errors"
	"fmt"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/native"

	"sync/atomic"
	"time"
)

const (
	DefaultCallTimeout     = time.Second
	DefaultLoadTimeout     = 30 * time.Second
	DefaultMaxRequestBytes = 1 << 20
	DefaultMaxInstances    = 8
)

// Limits selects explicit native concurrency, deadlines, and encoded request bounds.
type Limits struct {
	// MaxInstances bounds this session; the runtime also enforces its shared call cap.
	MaxInstances    int
	CallTimeout     time.Duration
	LoadTimeout     time.Duration
	MaxRequestBytes int
}

func (l Limits) WithDefaults() Limits {
	if l.MaxInstances <= 0 {
		l.MaxInstances = DefaultMaxInstances
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
	return l
}

type Session struct {
	Runtime            *Runtime
	Load               []byte
	Limits             Limits
	Pool               *puddle.Pool[*native.Instance]
	created, discarded atomic.Uint64
}

func NewSession(ctx context.Context, rt *Runtime, load []byte, limits Limits) (*Session, error) {
	a := &Session{Runtime: rt, Load: append([]byte(nil), load...), Limits: limits.WithDefaults()}
	pool, e := puddle.NewPool(&puddle.Config[*native.Instance]{Constructor: a.NewInstance, Destructor: func(i *native.Instance) { _ = i.Close(context.Background()) }, MaxSize: int32(min(a.Limits.MaxInstances, 1<<30))})
	if e != nil {
		return nil, e
	}
	a.Pool = pool
	r, e := pool.Acquire(ctx)
	if e != nil {
		pool.Close()
		return nil, e
	}
	r.Release()
	return a, nil
}
func (a *Session) Call(ctx context.Context, op string, in []byte, decode func([]byte) error) error {
	if len(in) > a.Limits.MaxRequestBytes {
		return diagnostic.LimitError("request", len(in), a.Limits.MaxRequestBytes)
	}
	r, e := a.Pool.Acquire(ctx)
	if e != nil {
		return fmt.Errorf("cedar: acquire instance: %w", e)
	}
	defer a.Finish(r)
	if a.Limits.CallTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, a.Limits.CallTimeout)
		defer cancel()
	}
	release, e := a.Runtime.Acquire(ctx)
	if e != nil {
		return diagnostic.FaultError(e)
	}
	defer release()
	i := r.Value()
	out, e := i.Call(ctx, op, in, a.Runtime.MaxResponse)
	if e != nil {
		return diagnostic.FaultError(e)
	}
	e = CompletionError(ctx, decode(out))
	if errors.Is(e, diagnostic.ErrFault) {
		i.MarkFaulted()
	}
	return e
}
