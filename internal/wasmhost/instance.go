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

// Retain enough stderr for Rust panic diagnostics without unbounded host allocation.
const stderrLimit = 4096

// Instance requires exclusive use; its call stack and guest state are mutable.
type Instance struct {
	module *Module
	mod    api.Module
	alloc  api.Function
	free   api.Function
	ops    map[string]api.Function
	stack  []uint64
	stderr *capbuf.Buffer
	// Faulted state is untrusted, so discard the instance.
	faulted bool
}

// Instantiate grants randomness for Rust hash seeds and bounded stderr for panic diagnostics.
// Other WASI capabilities retain wazero's isolated defaults.
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

func (i *Instance) Close(ctx context.Context) error {
	return i.mod.Close(ctx)
}

func (i *Instance) Faulted() bool { return i.faulted }

func (i *Instance) MemoryBytes() uint64 {
	return uint64(i.mod.Memory().Size())
}

func (i *Instance) Module() api.Module { return i.mod }

// Call copies responses out of guest memory so they outlive the instance.
// Every error is a [*Fault] and makes the instance unusable.
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

// MarkFaulted prevents reuse when a caller detects an invalid response, such as malformed JSON.
func (i *Instance) MarkFaulted() { i.faulted = true }

func (i *Instance) fault(op string, err error) *Fault {
	i.faulted = true
	return &Fault{Module: i.module.name, Op: op, Err: err, Stderr: i.stderr.String()}
}
