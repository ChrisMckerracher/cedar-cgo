package wasmhost

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/capbuf"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"io"
)

// stderrLimit bounds the guest stderr that an instance keeps. Rust writes a
// panic message there before it aborts.
const stderrLimit = 4096

// Instance is one instantiation of a [Module]. It is not safe for
// concurrent use.
type Instance struct {
	module *Module
	mod    api.Module
	alloc  api.Function
	free   api.Function
	ops    map[string]api.Function
	stack  []uint64
	stderr *capbuf.Buffer
	// faulted is set after any trap, exit or ABI violation. A faulted
	// instance must be closed.
	faulted bool
}

// Instantiate creates a fresh instance. The instance gets crypto/rand as its
// random source, which Rust's hash maps use for their seeds. It gets no
// arguments, no environment variables, no files, no network, no real clock
// and no stdin. Its stdout is discarded and its stderr is kept, bounded, for
// fault messages.
func (m *Module) Instantiate(ctx context.Context) (*Instance, error) {
	stderr := &capbuf.Buffer{Limit: stderrLimit}
	cfg := wazero.NewModuleConfig().
		WithName("").
		WithStartFunctions("_initialize").
		WithRandSource(rand.Reader).
		WithStdout(io.Discard).
		WithStderr(stderr)
	mod, err := m.runtime.InstantiateModule(ctx, m.compiled, cfg)
	if err != nil {
		return nil, &Fault{Module: m.name, Op: "instantiate", Err: err, Stderr: stderr.String()}
	}
	inst := &Instance{
		module: m,
		mod:    mod,
		alloc:  mod.ExportedFunction("cgw_alloc"),
		free:   mod.ExportedFunction("cgw_free"),
		ops:    make(map[string]api.Function, len(m.exports)),
		stack:  make([]uint64, 2),
		stderr: stderr,
	}
	for _, name := range m.exports {
		inst.ops[name] = mod.ExportedFunction(name)
	}
	version, err := mod.ExportedFunction("cgw_abi_version").Call(ctx)
	if err != nil || len(version) != 1 || version[0] != ABIVersion {
		_ = mod.Close(ctx)
		return nil, &Fault{Module: m.name, Op: "cgw_abi_version", Err: fmt.Errorf("ABI version %v, want %d (%v)", version, ABIVersion, err)}
	}
	return inst, nil
}

// Close releases the instance.
func (i *Instance) Close(ctx context.Context) error {
	return i.mod.Close(ctx)
}

// Faulted reports whether a call on this instance faulted.
func (i *Instance) Faulted() bool { return i.faulted }

// MemoryBytes returns the current size of the instance's linear memory.
func (i *Instance) MemoryBytes() uint64 {
	return uint64(i.mod.Memory().Size())
}

// Module returns the underlying wazero module, for host functions.
func (i *Instance) Module() api.Module { return i.mod }

// Call runs operation op with input and returns its response. The response
// is a copy that outlives the instance. Any error from Call is a [*Fault],
// and it marks the instance as faulted.
func (i *Instance) Call(ctx context.Context, op string, input []byte, maxResponse uint32) ([]byte, error) {
	if i.faulted {
		return nil, i.fault(op, errors.New("instance already faulted"))
	}
	fn, ok := i.ops[op]
	if !ok {
		return nil, i.fault(op, errors.New("unknown operation"))
	}
	if uint64(len(input)) > uint64(^uint32(0)) {
		return nil, i.fault(op, errors.New("input exceeds 4 GiB"))
	}
	n := uint32(len(input))
	i.stack[0] = uint64(n)
	if err := i.alloc.CallWithStack(ctx, i.stack); err != nil {
		return nil, i.fault(op, err)
	}
	ptr := uint32(i.stack[0])
	if ptr == 0 {
		return nil, i.fault(op, errors.New("guest allocation failed"))
	}
	if !i.mod.Memory().Write(ptr, input) {
		return nil, i.fault(op, errors.New("input buffer out of range"))
	}
	i.stack[0], i.stack[1] = uint64(ptr), uint64(n)
	if err := fn.CallWithStack(ctx, i.stack); err != nil {
		return nil, i.fault(op, err)
	}
	packed := i.stack[0]
	rptr, rlen := uint32(packed>>32), uint32(packed)
	if rptr == 0 || rlen == 0 {
		return nil, i.fault(op, errors.New("empty response"))
	}
	if rlen > maxResponse {
		return nil, i.fault(op, fmt.Errorf("response of %d bytes exceeds the %d byte limit", rlen, maxResponse))
	}
	view, ok := i.mod.Memory().Read(rptr, rlen)
	if !ok {
		return nil, i.fault(op, errors.New("response buffer out of range"))
	}
	out := bytes.Clone(view)
	i.stack[0], i.stack[1] = uint64(rptr), uint64(rlen)
	if err := i.free.CallWithStack(ctx, i.stack); err != nil {
		return nil, i.fault(op, err)
	}
	return out, nil
}

// MarkFaulted marks the instance as faulted, for errors that the caller
// finds in a response, such as invalid JSON.
func (i *Instance) MarkFaulted() { i.faulted = true }

func (i *Instance) fault(op string, err error) *Fault {
	i.faulted = true
	return &Fault{Module: i.module.name, Op: op, Err: err, Stderr: i.stderr.String()}
}
