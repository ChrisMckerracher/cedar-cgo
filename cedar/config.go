package cedar

import (
	"runtime"
	"time"
)

// Default per-authorizer limits.
const (
	DefaultCallTimeout        = time.Second
	DefaultLoadTimeout        = 30 * time.Second
	DefaultMaxRequestBytes    = 1 << 20
	DefaultRecycleMemoryBytes = 64 << 20
)

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
