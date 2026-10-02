package analysis

import (
	"context"
	"errors"
	"fmt"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"io"
)

const (
	hostModuleName      = "cgw_host"
	solverWriteFunction = "solver_write"
	solverReadFunction  = "solver_read"
	solverReadChunk     = 1 << 16
)

// analysisImports lists every function the analysis module may import.
var analysisImports = []string{
	hostModuleName + "." + solverWriteFunction,
	hostModuleName + "." + solverReadFunction,
	"wasi_snapshot_preview1.random_get",
	"wasi_snapshot_preview1.environ_get",
	"wasi_snapshot_preview1.environ_sizes_get",
	"wasi_snapshot_preview1.clock_time_get",
	"wasi_snapshot_preview1.fd_write",
	"wasi_snapshot_preview1.poll_oneoff",
	"wasi_snapshot_preview1.proc_exit",
}

type sessionKey struct{}

// sessionState is the solver session of one call, which the host functions
// find through the call's context.
type sessionState struct {
	session Session
	read    int64
	limit   int64
	err     error
}

func defineHostModule(ctx context.Context, r wazero.Runtime) error {
	_, err := r.NewHostModuleBuilder(hostModuleName).
		NewFunctionBuilder().WithFunc(solverWrite).Export(solverWriteFunction).
		NewFunctionBuilder().WithFunc(solverRead).Export(solverReadFunction).
		Instantiate(ctx)
	return err
}

// solverWrite copies guest bytes to the solver's input.
func solverWrite(ctx context.Context, m api.Module, ptr, n uint32) int32 {
	s, _ := ctx.Value(sessionKey{}).(*sessionState)
	if s == nil || s.err != nil {
		return -1
	}
	buf, ok := m.Memory().Read(ptr, n)
	if !ok {
		s.err = errors.New("solver input buffer out of range")
		return -1
	}
	if _, err := s.session.Write(buf); err != nil {
		s.err = fmt.Errorf("write to solver: %w", err)
		return -1
	}
	return 0
}

// solverRead copies solver output into guest memory. It returns the byte
// count, 0 at end of stream, or -1 on error.
func solverRead(ctx context.Context, m api.Module, ptr, n uint32) int32 {
	s, _ := ctx.Value(sessionKey{}).(*sessionState)
	if s == nil || s.err != nil {
		return -1
	}
	buf := make([]byte, min(n, solverReadChunk))
	k, err := s.session.Read(buf)
	if k > 0 {
		s.read += int64(k)
		if s.read > s.limit {
			s.err = fmt.Errorf("solver output exceeds %d bytes", s.limit)
			return -1
		}
		if !m.Memory().Write(ptr, buf[:k]) {
			s.err = errors.New("solver output buffer out of range")
			return -1
		}
		return int32(k)
	}
	if errors.Is(err, io.EOF) {
		return 0
	}
	if err != nil {
		s.err = fmt.Errorf("read from solver: %w", err)
	}
	return -1
}
