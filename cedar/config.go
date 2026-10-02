package cedar

import (
	"runtime"
	"time"
)

const (
	DefaultCallTimeout        = time.Second
	DefaultLoadTimeout        = 30 * time.Second
	DefaultMaxRequestBytes    = 1 << 20
	DefaultRecycleMemoryBytes = 64 << 20
)

// Limits uses the corresponding Default constant for zero fields, except MaxInstances.
type Limits struct {
	// MaxInstances bounds concurrency; the default is runtime.GOMAXPROCS(0).
	MaxInstances int
	// CallTimeout excludes waiting for an instance; the caller's context bounds
	// the whole call. A negative value disables this timeout.
	CallTimeout time.Duration
	// LoadTimeout includes parsing the schema, policies and entities.
	LoadTimeout time.Duration
	// MaxRequestBytes includes the encoded context and request-specific entities.
	MaxRequestBytes int
	// RecycleMemoryBytes replaces oversized instances because Wasm memory cannot shrink.
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

type Config struct {
	// Schema checks entities, contexts and requests, and supplies action entities.
	// Policy validation requires [Runtime.Validate].
	Schema   *Schema
	Policies PolicySet
	// Entities are available to every request.
	Entities Entities
	Limits   Limits
}
