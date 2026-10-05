package execution

import (
	"context"
	"fmt"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/native"
)

const (
	DefaultMaxSourceBytes     = 64 << 20
	DefaultMaxResponseBytes   = 16 << 20
	DefaultMaxConcurrentCalls = 8
)

type Runtime struct {
	Module         *native.Module
	MaxSourceBytes int
	MaxResponse    uint32
	gate           chan struct{}
}
type Config struct {
	MaxSourceBytes     int
	MaxResponseBytes   uint32
	MaxConcurrentCalls int
	Unsupported        string
}
type Option func(*Config)

func WithMaxSourceBytes(n int) Option      { return func(c *Config) { c.MaxSourceBytes = n } }
func WithMaxResponseBytes(n uint32) Option { return func(c *Config) { c.MaxResponseBytes = n } }
func WithMaxConcurrentCalls(n int) Option  { return func(c *Config) { c.MaxConcurrentCalls = n } }
func WithMemoryLimit(n uint64) Option      { return func(c *Config) { c.Unsupported = "WithMemoryLimit" } }
func WithCompilationCache(_ any) Option {
	return func(c *Config) { c.Unsupported = "WithCompilationCache" }
}
func New(ctx context.Context, opts ...Option) (*Runtime, error) {
	c := Config{MaxSourceBytes: DefaultMaxSourceBytes, MaxResponseBytes: DefaultMaxResponseBytes, MaxConcurrentCalls: DefaultMaxConcurrentCalls}
	for _, o := range opts {
		o(&c)
	}
	if c.Unsupported != "" {
		return nil, fmt.Errorf("cedar: %s is unsupported by native execution", c.Unsupported)
	}
	if c.MaxSourceBytes <= 0 || c.MaxResponseBytes == 0 || c.MaxConcurrentCalls <= 0 {
		return nil, fmt.Errorf("cedar: source, response and concurrency limits must be positive")
	}
	m, e := native.New(ctx, "authorizer")
	if e != nil {
		return nil, e
	}
	return &Runtime{Module: m, MaxSourceBytes: c.MaxSourceBytes, MaxResponse: c.MaxResponseBytes, gate: make(chan struct{}, c.MaxConcurrentCalls)}, nil
}
func (rt *Runtime) Close(ctx context.Context) error { return rt.Module.Close(ctx) }
func (rt *Runtime) Acquire(ctx context.Context) (func(), error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	select {
	case rt.gate <- struct{}{}:
		return func() { <-rt.gate }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (rt *Runtime) CallOnce(ctx context.Context, op string, input []byte) ([]byte, error) {
	release, e := rt.Acquire(ctx)
	if e != nil {
		return nil, diagnostic.FaultError(e)
	}
	defer release()
	i, e := rt.Module.Instantiate(ctx)
	if e != nil {
		return nil, diagnostic.FaultError(e)
	}
	defer i.Close(context.WithoutCancel(ctx))
	out, e := i.Call(ctx, op, input, rt.MaxResponse)
	if e != nil {
		return nil, diagnostic.FaultError(e)
	}
	return out, nil
}

type Caller interface {
	CallOnce(context.Context, string, []byte) ([]byte, error)
	SourceLimit() int
}

func (rt *Runtime) SourceLimit() int { return rt.MaxSourceBytes }
