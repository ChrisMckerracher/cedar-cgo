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

// Solver sessions are created and closed per analysis call.
type Solver interface {
	// Start must provide interactive SMT-LIB 2 replies, as "cvc5 --lang smt" does.
	Start(ctx context.Context) (Session, error)
}

// Session writes solver input and reads solver output.
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
}

func (p *process) Read(b []byte) (int, error)  { return p.stdout.Read(b) }
func (p *process) Write(b []byte) (int, error) { return p.stdin.Write(b) }

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

func (p *process) Stderr() string { return p.stderr.String() }
