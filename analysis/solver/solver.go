package solver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ChrisMckerracher/cedar-cgo/internal/capbuf"
)

// Solver sessions serve stateless calls or explicitly owned compiled sessions.
type Solver interface {
	// Start must provide interactive SMT-LIB 2 replies, as "cvc5 --lang smt" does.
	Start(ctx context.Context) (Session, error)
}

// Session writes solver input and reads solver output.
// Close must unblock current Read and Write operations.
type Session interface {
	io.Reader
	io.Writer
	io.Closer
}

// Command runs a solver with an empty environment and kills it when the context ends.
type Command struct {
	Path string
	Args []string
}

// CVC5 configures a caller-provided executable; Cedar tests SymCC with cvc5 1.3.1.
func CVC5(path string) *Command {
	return &Command{Path: path, Args: []string{"--lang", "smt"}}
}

const stderrLimit = 4096

func (c *Command) Start(ctx context.Context) (Session, error) {
	cmd := exec.CommandContext(ctx, c.Path, c.Args...)
	cmd.Env = []string{}
	cmd.WaitDelay = time.Second
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr := &capbuf.Buffer{Limit: stderrLimit}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start solver %s: %w", c.Path, err)
	}
	return &process{cmd: cmd, stdin: stdin, stdout: stdout, stderr: stderr}, nil
}

type process struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	stderr *capbuf.Buffer
	once   sync.Once
	err    error
	reaped atomic.Bool
}

func (p *process) Read(b []byte) (int, error)  { return p.stdout.Read(b) }
func (p *process) Write(b []byte) (int, error) { return p.stdin.Write(b) }

func (p *process) Close() error {
	p.once.Do(func() {
		_ = p.stdin.Close()
		_ = p.cmd.Process.Kill()
		err := p.cmd.Wait()
		p.reaped.Store(p.cmd.ProcessState != nil)
		_, exited := errors.AsType[*exec.ExitError](err)
		if err != nil && !exited {
			// CommandContext can report cancellation after the process exits successfully.
			canceled := err == context.Canceled || err == context.DeadlineExceeded
			if state := p.cmd.ProcessState; !canceled || state == nil || !state.Success() {
				p.err = err
			}
		}
	})
	return p.err
}

func (p *process) Stderr() string { return p.stderr.String() }

// Reaped reports whether Close waited for the solver process to finish.
func (p *process) Reaped() bool { return p.reaped.Load() }
