package compiled

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/ChrisMckerracher/cedar-cgo/analysis/internal/settings"
	callback "github.com/ChrisMckerracher/cedar-cgo/analysis/internal/transport"
	"github.com/ChrisMckerracher/cedar-cgo/analysis/report"
	"github.com/ChrisMckerracher/cedar-cgo/internal/native"
	"github.com/ChrisMckerracher/cedar-cgo/internal/wire"
)

func ordinaryCompiledError(kind string) bool {
	switch kind {
	case "input", "schema", "policies", "compile_a", "compile_b", "handle", "handle_limit":
		return true
	}
	return false
}

func (s *Session) execute(ctx context.Context, input []byte, validate func() error, decode func([]byte) error) error {
	if s == nil || s.gate == nil {
		return ErrClosed
	}
	if err := s.acquire(ctx); err != nil {
		return err
	}
	defer func() {
		select {
		case <-s.done:
			<-s.abortDone
			s.closeNative()
		default:
		}
		<-s.gate
	}()
	if validate != nil {
		if err := validate(); err != nil {
			return err
		}
	}
	callCtx, cancel := context.WithCancel(ctx)
	stopLifetime := context.AfterFunc(s.lifetime, cancel)
	if s.config.Timeout > 0 {
		var stop context.CancelFunc
		callCtx, stop = context.WithTimeout(callCtx, s.config.Timeout)
		defer stop()
	}
	stopCancellation := context.AfterFunc(callCtx, func() { s.abort(callCtx.Err()) })
	defer func() { stopCancellation(); stopLifetime(); cancel() }()
	if err := s.initialize(callCtx); err != nil {
		s.abort(err)
		return err
	}
	s.mu.Lock()
	transport := s.transport
	s.mu.Unlock()
	state := callback.New(transport, s.config.MaxSolverOutput)
	out, err := s.instance.Call(native.WithCallback(callCtx, state), "cgw_compiled", input, settings.MaxResponseBytes)
	if callCtx.Err() != nil {
		err = callCtx.Err()
	} else if s.lifetime.Err() != nil {
		err = s.lifetime.Err()
	}
	if err != nil {
		s.abort(err)
		return state.Detail(fmt.Errorf("analysis: %w", err))
	}
	if state.Err() != nil {
		s.abort(state.Err())
		return fmt.Errorf("analysis: %w", state.Err())
	}
	var envelope map[string]jsontext.Value
	if !utf8.Valid(out) {
		err := errors.New("compiled response is not valid UTF-8")
		s.abort(err)
		return fmt.Errorf("analysis: decode compiled response: %w", err)
	}
	if err := json.Unmarshal(out, &envelope); err != nil {
		s.abort(err)
		return fmt.Errorf("analysis: decode compiled response: %w", err)
	}
	if len(envelope) != 1 {
		err := errors.New("compiled response has an invalid envelope")
		s.abort(err)
		return fmt.Errorf("analysis: decode compiled response: %w", err)
	}
	if data, present := envelope["error"]; present {
		var result *wire.Error
		if err := json.Unmarshal(data, &result); err != nil {
			s.abort(err)
			return fmt.Errorf("analysis: decode compiled response: %w", err)
		}
		if result == nil || result.Kind == "" || result.Message == "" {
			err := errors.New("compiled response has an incomplete error")
			s.abort(err)
			return fmt.Errorf("analysis: decode compiled response: %w", err)
		}
		err := &report.Error{Kind: result.Kind, Message: result.Message}
		if !ordinaryCompiledError(err.Kind) {
			s.abort(err)
		}
		return state.Detail(err)
	}
	if err := decode(out); err != nil {
		s.abort(err)
		return fmt.Errorf("analysis: decode compiled response: %w", err)
	}
	if err := callCtx.Err(); err != nil {
		s.abort(err)
		return fmt.Errorf("analysis: %w", err)
	}
	if err := s.lifetime.Err(); err != nil {
		s.abort(err)
		return fmt.Errorf("analysis: %w", err)
	}
	return nil
}
