package analysis

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"

	decoded "github.com/ChrisMckerracher/cedar-cgo/analysis/internal/report"
	"github.com/ChrisMckerracher/cedar-cgo/analysis/internal/settings"
	"github.com/ChrisMckerracher/cedar-cgo/analysis/internal/transport"
	"github.com/ChrisMckerracher/cedar-cgo/analysis/report"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	policy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	schemas "github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
	"github.com/ChrisMckerracher/cedar-cgo/internal/native"
	"github.com/ChrisMckerracher/cedar-cgo/internal/wire"
)

type analyzeInput struct {
	Schema wire.Source `json:"schema"`
	A      wire.Source `json:"a"`
	B      wire.Source `json:"b"`
	Query  string      `json:"query"`
}

// swap restores the caller's argument order after a reversed implication query.
func (a *Analyzer) run(ctx context.Context, query string, schema schemas.Schema, pa, pb policy.PolicySet, swap bool) (report.Report, error) {
	in, err := json.Marshal(analyzeInput{
		Schema: wire.Source{Format: schema.Format().String(), Text: schema.Text()},
		A:      wire.Source{Format: pa.Format().String(), Text: pa.Text()},
		B:      wire.Source{Format: pb.Format().String(), Text: pb.Text()},
		Query:  query,
	},
		jsontext.EscapeForHTML(true),
		jsontext.EscapeForJS(true),
		jsontext.PreserveRawStrings(true),
	)
	if err != nil {
		return report.Report{}, &report.Error{Kind: string(diagnostic.KindInput), Message: err.Error()}
	}
	if len(in) > a.config.MaxSourceBytes {
		return report.Report{}, fmt.Errorf("analysis: input is %d bytes, above the limit of %d", len(in), a.config.MaxSourceBytes)
	}
	lease, err := a.owner.Begin(ctx)
	if err != nil {
		return report.Report{}, err
	}
	ctx = lease.Context
	defer lease.Finish(nil)
	if a.config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, a.config.Timeout)
		defer cancel()
	}
	if err := ctx.Err(); err != nil {
		return report.Report{}, err
	}
	session, err := a.solver.Start(ctx)
	if err != nil {
		return report.Report{}, fmt.Errorf("analysis: %w", err)
	}
	state := transport.New(session, a.config.MaxSolverOutput)
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
		return report.Report{}, fmt.Errorf("analysis: %w", err)
	}
	defer inst.Close(context.WithoutCancel(ctx))
	out, err := inst.Call(native.WithCallback(ctx, state), "cgw_analyze", in, settings.MaxResponseBytes)
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		return report.Report{}, state.Detail(fmt.Errorf("analysis: %w", err))
	}
	var w struct {
		Error *wire.Error `json:"error"`
	}
	if err := json.Unmarshal(out, &w); err != nil {
		return report.Report{}, fmt.Errorf("analysis: decode response: %w", err)
	}
	if w.Error != nil {
		return report.Report{}, state.Detail(&report.Error{Kind: w.Error.Kind, Message: w.Error.Message})
	}
	result, err := decoded.Decode(out, swap, query)
	if err != nil {
		return report.Report{}, err
	}
	if err := ctx.Err(); err != nil {
		return report.Report{}, fmt.Errorf("analysis: %w", err)
	}
	return result, nil
}
