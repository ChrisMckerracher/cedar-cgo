package analysis

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"

	"github.com/ChrisMckerracher/cedar-go-wasm/internal/capbuf"
)

// Solver starts SMT solver sessions. Each analysis call starts one session
// and closes it when the call returns.
type Solver interface {
	// Start starts a session. The session reads SMT-LIB 2 commands and
	// answers each one as an interactive solver does, such as
	// "cvc5 --lang smt" reading from a pipe.
	Start(ctx context.Context) (Session, error)
}

// Session is one running solver. Writes go to the solver's input, and
// reads come from its output.
type Session interface {
	io.Reader
	io.Writer
	io.Closer
}

// Command is a [Solver] that runs an executable, with an empty environment,
// and speaks to it over its standard input and output. The process is
// killed when the analysis context ends.
type Command struct {
	// Path is the solver executable.
	Path string
	// Args are its arguments.
	Args []string
}

// CVC5 returns a [Command] for the cvc5 executable at path. Cedar tests
// SymCC with cvc5 1.3.1. This package does not include cvc5: install it
// yourself, for example from https://github.com/cvc5/cvc5/releases.
//
// cvc5's default build links GMP, which is licensed under the LGPL-3.0.
func CVC5(path string) *Command {
	return &Command{Path: path, Args: []string{"--lang", "smt"}}
}

// stderrLimit bounds the solver stderr that a session keeps.
const stderrLimit = 4096

// Start implements [Solver].
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
}

func (p *process) Read(b []byte) (int, error)  { return p.stdout.Read(b) }
func (p *process) Write(b []byte) (int, error) { return p.stdin.Write(b) }

// Close ends the solver: it closes the solver's input, then kills the
// process if it has not exited.
func (p *process) Close() error {
	p.once.Do(func() {
		_ = p.stdin.Close()
		_ = p.cmd.Process.Kill()
		err := p.cmd.Wait()
		var exit *exec.ExitError
		if err != nil && !errors.As(err, &exit) {
			p.err = err
		}
	})
	return p.err
}

// Stderr returns the start of the solver's stderr.
func (p *process) Stderr() string { return p.stderr.String() }
