package lifetime

import (
	"context"
	"errors"
	"io"
	"sync"
)

var ErrClosed = errors.New("analysis: analyzer is closed")

// Owner registers calls before resource creation and waits for late constructors.
type Owner struct {
	mu     sync.Mutex
	closed bool
	leases map[*Lease]struct{}
	once   sync.Once
	err    error
}

type Lease struct {
	owner   *Owner
	Context context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	child   io.Closer
	cleanup error
}

func (o *Owner) Begin(ctx context.Context) (*Lease, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if o.closed {
		return nil, ErrClosed
	}
	ctx, cancel := context.WithCancel(ctx)
	l := &Lease{owner: o, Context: ctx, cancel: cancel, done: make(chan struct{})}
	if o.leases == nil {
		o.leases = make(map[*Lease]struct{})
	}
	o.leases[l] = struct{}{}
	return l, nil
}

// Finish releases a call or records cleanup failure from a canceled constructor.
func (l *Lease) Finish(cleanup error) {
	l.cancel()
	l.owner.mu.Lock()
	l.cleanup = cleanup
	delete(l.owner.leases, l)
	close(l.done)
	l.owner.mu.Unlock()
}

func (l *Lease) Keep(child io.Closer) {
	l.owner.mu.Lock()
	l.child = child
	close(l.done)
	l.owner.mu.Unlock()
}

func (l *Lease) Release() {
	l.cancel()
	l.owner.mu.Lock()
	delete(l.owner.leases, l)
	l.owner.mu.Unlock()
}

func (o *Owner) Close() error {
	o.once.Do(func() {
		o.mu.Lock()
		o.closed = true
		leases := make([]*Lease, 0, len(o.leases))
		for lease := range o.leases {
			leases = append(leases, lease)
		}
		o.mu.Unlock()
		for _, lease := range leases {
			lease.cancel()
		}
		for _, lease := range leases {
			<-lease.done
			if lease.child != nil {
				o.err = errors.Join(o.err, lease.child.Close())
			}
			o.err = errors.Join(o.err, lease.cleanup)
		}
	})
	return o.err
}
