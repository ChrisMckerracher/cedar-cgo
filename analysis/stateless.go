package analysis

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ChrisMckerracher/cedar-go-wasm/analysis/internal/report"
	"github.com/ChrisMckerracher/cedar-go-wasm/analysis/solver"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	policy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	schemas "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	syntax "github.com/ChrisMckerracher/cedar-go-wasm/cedar/syntax"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/native"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

type analyzeInput struct {
	Schema wire.Source `json:"schema"`
	A      wire.Source `json:"a"`
	B      wire.Source `json:"b"`
	Query  string      `json:"query"`
}

type Error struct {
	Kind    string
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("analysis: %s: %s", e.Kind, e.Message) }

func source(f syntax.Format, text string) wire.Source {
	return wire.Source{Format: f.String(), Text: text}
}

// swap restores the caller's argument order after a reversed implication query.
func (a *Analyzer) run(ctx context.Context, query string, schema schemas.Schema, pa, pb policy.PolicySet, swap bool) (Report, error) {
	in, err := json.Marshal(analyzeInput{
		Schema: source(schema.Format(), schema.Text()),
		A:      source(pa.Format(), pa.Text()),
		B:      source(pb.Format(), pb.Text()),
		Query:  query,
	})
	if err != nil {
		return Report{}, &Error{Kind: string(diagnostic.KindInput), Message: err.Error()}
	}
	if len(in) > a.maxSourceBytes {
		return Report{}, fmt.Errorf("analysis: input is %d bytes, above the limit of %d", len(in), a.maxSourceBytes)
	}
	ctx, finish, err := a.beginCall(ctx)
	if err != nil {
		return Report{}, err
	}
	defer finish()
	if a.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, a.timeout)
		defer cancel()
	}
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	session, err := a.solver.Start(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("analysis: %w", err)
	}
	state := &sessionState{session: session, limit: a.maxSolverOutput}
	closed := make(chan struct{})
	stopCancellation := context.AfterFunc(ctx, func() { _ = session.Close(); close(closed) })
	defer func() {
		if !stopCancellation() {
			<-closed
		}
		_ = session.Close()
	}()

	inst, err := a.module.Instantiate(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("analysis: %w", err)
	}
	defer inst.Close(context.WithoutCancel(ctx))
	out, err := inst.Call(native.WithCallback(context.WithValue(ctx, sessionKey{}, state), state), "cgw_analyze", in, defaultMaxResponseBytes)
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		return Report{}, a.withSolverDetail(fmt.Errorf("analysis: %w", err), state, session)
	}
	var w struct {
		Error *wire.Error `json:"error"`
	}
	if err := json.Unmarshal(out, &w); err != nil {
		return Report{}, fmt.Errorf("analysis: decode response: %w", err)
	}
	if w.Error != nil {
		return Report{}, a.withSolverDetail(&Error{Kind: w.Error.Kind, Message: w.Error.Message}, state, session)
	}
	result, err := report.Decode(out, swap, query)
	if err != nil {
		return Report{}, err
	}
	if err := ctx.Err(); err != nil {
		return Report{}, fmt.Errorf("analysis: %w", err)
	}
	return result, nil
}

func (a *Analyzer) withSolverDetail(err error, state *sessionState, session solver.Session) error {
	if state.err != nil {
		err = fmt.Errorf("%w (host: %v)", err, state.err)
	}
	if p, ok := session.(interface{ Stderr() string }); ok {
		if s := p.Stderr(); s != "" {
			err = fmt.Errorf("%w (solver stderr: %s)", err, s)
		}
	}
	return err
}
