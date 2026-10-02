// Package wasmhost runs the cedar-go-wasm guest modules under wazero.
//
// It compiles a module once, checks its SHA-256 and its imports, and creates
// instances that grant no WASI capabilities beyond the ones listed in
// [Config.AllowedImports]. Each instance runs one call at a time.
package wasmhost

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/ChrisMckerracher/cedar-go-wasm/internal/capbuf"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"
)

// ABIVersion is the guest ABI version that this host speaks.
const ABIVersion = 1

// wasmPageSize is the size of one WebAssembly memory page.
const wasmPageSize = 65536

// stderrLimit bounds the guest stderr that an instance keeps. Rust writes a
// panic message there before it aborts.
const stderrLimit = 4096

// Config configures a [Module].
type Config struct {
	// Name labels the module in errors.
	Name string
	// Wasm is the module binary.
	Wasm []byte
	// SHA256 is the expected hex SHA-256 of Wasm.
	SHA256 string
	// MemoryLimitBytes caps the linear memory of each instance.
	MemoryLimitBytes uint64
	// Cache, if not nil, stores compiled machine code across runtimes.
	Cache wazero.CompilationCache
	// AllowedImports lists every function the module may import, as
	// "module.name". Compilation fails if the module imports anything else.
	AllowedImports []string
	// HostModules, if not nil, defines host modules before compilation.
	HostModules func(ctx context.Context, r wazero.Runtime) error
	// Exports lists the operation exports the module must have.
	Exports []string
}

// Module is a compiled guest module and the runtime that owns it.
type Module struct {
	name     string
	runtime  wazero.Runtime
	compiled wazero.CompiledModule
	exports  []string
}

// Compile verifies and compiles a guest module.
func Compile(ctx context.Context, cfg Config) (*Module, error) {
	sum := sha256.Sum256(cfg.Wasm)
	if got := hex.EncodeToString(sum[:]); got != cfg.SHA256 {
		return nil, fmt.Errorf("%s module: SHA-256 is %s, want %s", cfg.Name, got, cfg.SHA256)
	}
	if cfg.MemoryLimitBytes < wasmPageSize {
		return nil, fmt.Errorf("%s module: memory limit %d is below one page", cfg.Name, cfg.MemoryLimitBytes)
	}
	pages := cfg.MemoryLimitBytes / wasmPageSize
	if pages > 65536 {
		pages = 65536
	}
	rc := wazero.NewRuntimeConfig().
		WithCloseOnContextDone(true).
		WithMemoryLimitPages(uint32(pages))
	if cfg.Cache != nil {
		rc = rc.WithCompilationCache(cfg.Cache)
	}
	r := wazero.NewRuntimeWithConfig(ctx, rc)
	m, err := compile(ctx, r, cfg)
	if err != nil {
		_ = r.Close(ctx)
		return nil, err
	}
	return m, nil
}

func compile(ctx context.Context, r wazero.Runtime, cfg Config) (*Module, error) {
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, r); err != nil {
		return nil, fmt.Errorf("%s module: instantiate WASI: %w", cfg.Name, err)
	}
	if cfg.HostModules != nil {
		if err := cfg.HostModules(ctx, r); err != nil {
			return nil, fmt.Errorf("%s module: host functions: %w", cfg.Name, err)
		}
	}
	compiled, err := r.CompileModule(ctx, cfg.Wasm)
	if err != nil {
		return nil, fmt.Errorf("%s module: compile: %w", cfg.Name, err)
	}
	allowed := make(map[string]bool, len(cfg.AllowedImports))
	for _, name := range cfg.AllowedImports {
		allowed[name] = true
	}
	for _, f := range compiled.ImportedFunctions() {
		mod, name, _ := f.Import()
		if !allowed[mod+"."+name] {
			return nil, fmt.Errorf("%s module: imports %s.%s, which is not allowed", cfg.Name, mod, name)
		}
	}
	if n := len(compiled.ImportedMemories()); n != 0 {
		return nil, fmt.Errorf("%s module: imports %d memories", cfg.Name, n)
	}
	exports := compiled.ExportedFunctions()
	for _, name := range append([]string{"cgw_abi_version", "cgw_alloc", "cgw_free"}, cfg.Exports...) {
		if _, ok := exports[name]; !ok {
			return nil, fmt.Errorf("%s module: missing export %s", cfg.Name, name)
		}
	}
	return &Module{name: cfg.Name, runtime: r, compiled: compiled, exports: cfg.Exports}, nil
}

// Close releases the runtime and every instance of the module.
func (m *Module) Close(ctx context.Context) error {
	return m.runtime.Close(ctx)
}

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

// Fault reports a trap, a guest exit, a timeout or an ABI violation.
type Fault struct {
	Module string
	Op     string
	Err    error
	// Stderr holds the start of the guest's stderr, such as a panic message.
	Stderr string
}

// Error returns the first line of the cause, without wazero's stack trace,
// and the guest's stderr.
func (f *Fault) Error() string {
	cause, _, _ := strings.Cut(f.Err.Error(), "\n")
	msg := fmt.Sprintf("%s module: %s: %s", f.Module, f.Op, cause)
	if f.Stderr != "" {
		msg += ": guest stderr: " + f.Stderr
	}
	return msg
}

// Unwrap returns the cause. A timeout unwraps to [context.DeadlineExceeded]
// and a cancellation to [context.Canceled].
func (f *Fault) Unwrap() error {
	var exit *sys.ExitError
	if errors.As(f.Err, &exit) {
		switch exit.ExitCode() {
		case sys.ExitCodeDeadlineExceeded:
			return context.DeadlineExceeded
		case sys.ExitCodeContextCanceled:
			return context.Canceled
		}
	}
	return f.Err
}
