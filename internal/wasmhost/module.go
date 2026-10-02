package wasmhost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// ABIVersion is the guest ABI version that this host speaks.
const ABIVersion = 1

// wasmPageSize is the size of one WebAssembly memory page.
const wasmPageSize = 65536

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
