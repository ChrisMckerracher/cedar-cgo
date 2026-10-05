package analysis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/ChrisMckerracher/cedar-go-wasm/internal/native"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

func ordinaryCompiledError(kind string) bool {
	switch kind {
	case "input", "schema", "policies", "compile_a", "compile_b", "handle", "handle_limit":
		return true
	}
	return false
}

func (s *CompiledSession) execute(ctx context.Context, input []byte, validate func() error, decode func([]byte) error) error {
	if s == nil || s.analyzer == nil {
		return ErrCompiledClosed
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
	if s.analyzer.timeout > 0 {
		var stop context.CancelFunc
		callCtx, stop = context.WithTimeout(callCtx, s.analyzer.timeout)
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
	state := &sessionState{session: transport, limit: s.analyzer.maxSolverOutput}
	out, err := s.instance.Call(native.WithCallback(context.WithValue(callCtx, sessionKey{}, state), state), "cgw_compiled", input, defaultMaxResponseBytes)
	if callCtx.Err() != nil {
		err = callCtx.Err()
	}
	if err != nil {
		s.abort(err)
		return s.analyzer.withSolverDetail(fmt.Errorf("analysis: %w", err), state, transport)
	}
	if state.err != nil {
		s.abort(state.err)
		return fmt.Errorf("analysis: %w", state.err)
	}
	var envelope map[string]json.RawMessage
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
		err := &Error{Kind: result.Kind, Message: result.Message}
		if !ordinaryCompiledError(err.Kind) {
			s.abort(err)
		}
		return s.analyzer.withSolverDetail(err, state, transport)
	}
	if err := decode(out); err != nil {
		s.abort(err)
		return fmt.Errorf("analysis: decode compiled response: %w", err)
	}
	if err := callCtx.Err(); err != nil {
		s.abort(err)
		return fmt.Errorf("analysis: %w", err)
	}
	return nil
}
