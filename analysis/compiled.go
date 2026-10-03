package analysis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"unicode/utf8"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

var ErrCompiledClosed = errors.New("analysis: compiled session is closed")

// RequestEnvironment identifies one schema-defined principal/action/resource combination.
type RequestEnvironment struct {
	PrincipalType string          `json:"principal_type"`
	Action        cedar.EntityUID `json:"action"`
	ResourceType  string          `json:"resource_type"`
}

// MarshalJSON preserves flat action UIDs and rejects invalid UTF-8 before encoding.
func (env RequestEnvironment) MarshalJSON() ([]byte, error) {
	if err := wire.CheckUTF8(env.PrincipalType, env.ResourceType); err != nil {
		return nil, err
	}
	return json.Marshal(compiledEnvironment{
		PrincipalType: env.PrincipalType,
		Action:        wire.UID{Type: env.Action.Type, ID: env.Action.ID},
		ResourceType:  env.ResourceType,
	})
}

// CompiledPolicySet is an opaque handle owned by one CompiledSession.
// Release removes its native data. Handles cannot move between sessions.
type CompiledPolicySet struct {
	session *CompiledSession
	id      uint64
}

type compiledInstance interface {
	Call(context.Context, string, []byte, uint32) ([]byte, error)
	Close(context.Context) error
}

// CompiledSession reuses native compilation and one solver transport.
// Calls are serialized. Close releases all handles, the guest, and the solver.
type CompiledSession struct {
	analyzer  *Analyzer
	lifetime  context.Context
	cancel    context.CancelFunc
	gate      chan struct{}
	done      chan struct{}
	abortDone chan struct{}
	mu        sync.Mutex
	closed    bool
	reason    error
	transport Session
	closeErr  error
	// The gate protects guest access and the active handle map.
	instance     compiledInstance
	handles      map[uint64]struct{}
	environments []RequestEnvironment
	lastHandle   uint64
}

type compiledEnvironment struct {
	PrincipalType string   `json:"principal_type"`
	Action        wire.UID `json:"action"`
	ResourceType  string   `json:"resource_type"`
}

type compiledInput struct {
	Operation    string                 `json:"operation"`
	Schema       *wire.Source           `json:"schema,omitempty"`
	Environments *[]compiledEnvironment `json:"environments,omitempty"`
	Policies     *wire.Source           `json:"policies,omitempty"`
	First        uint64                 `json:"first,omitempty"`
	Second       uint64                 `json:"second,omitempty"`
	Handle       uint64                 `json:"handle,omitempty"`
	Query        string                 `json:"query,omitempty"`
}

func (a *Analyzer) encodeCompiled(input compiledInput) ([]byte, error) {
	if input.Environments != nil {
		for _, env := range *input.Environments {
			if err := wire.CheckUTF8(env.PrincipalType, env.ResourceType); err != nil {
				return nil, &Error{Kind: "input", Message: err.Error()}
			}
		}
	}
	data, err := json.Marshal(input)
	if err != nil {
		return nil, &Error{Kind: "input", Message: err.Error()}
	}
	if len(data) > a.maxSourceBytes {
		return nil, fmt.Errorf("analysis: input is %d bytes, above the limit of %d", len(data), a.maxSourceBytes)
	}
	return data, nil
}

// OpenCompiled creates a reusable session tied to the constructor context.
// A nil selection includes all environments. An empty selection includes none.
func (a *Analyzer) OpenCompiled(ctx context.Context, schema cedar.Schema, selection []RequestEnvironment) (*CompiledSession, error) {
	source := source(schema.Format(), schema.Text())
	input := compiledInput{Operation: "open", Schema: &source}
	if selection != nil {
		selected := make([]compiledEnvironment, len(selection))
		for i, env := range selection {
			selected[i] = compiledEnvironment{env.PrincipalType, wire.UID{Type: env.Action.Type, ID: env.Action.ID}, env.ResourceType}
		}
		input.Environments = &selected
	}
	encoded, err := a.encodeCompiled(input)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	lifetime, cancel := context.WithCancel(ctx)
	s := &CompiledSession{analyzer: a, lifetime: lifetime, cancel: cancel, gate: make(chan struct{}, 1), done: make(chan struct{}), abortDone: make(chan struct{}), handles: make(map[uint64]struct{})}
	// Register before starting resources so Analyzer.Close can cancel construction.
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		cancel()
		return nil, ErrCompiledClosed
	}
	if a.sessions == nil {
		a.sessions = make(map[*CompiledSession]struct{})
	}
	a.sessions[s] = struct{}{}
	a.mu.Unlock()
	context.AfterFunc(lifetime, func() { _ = s.closeWithReason(lifetime.Err()) })
	// Construction owns the same gate used by later calls.
	err = s.execute(ctx, encoded, nil, s.decodeOpen)
	if err != nil {
		return nil, errors.Join(err, s.closeWithReason(err))
	}
	return s, nil
}

func (s *CompiledSession) decodeOpen(data []byte) error {
	var result struct {
		Environments []struct {
			PrincipalType string `json:"principal_type"`
			Action        struct {
				Type *string `json:"type"`
				ID   *string `json:"id"`
			} `json:"action"`
			ResourceType string `json:"resource_type"`
		} `json:"environments"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return err
	}
	if result.Environments == nil {
		return errors.New("compiled session response has no environments")
	}
	environments := make([]RequestEnvironment, len(result.Environments))
	for i, env := range result.Environments {
		if env.PrincipalType == "" || env.Action.Type == nil || *env.Action.Type == "" || env.Action.ID == nil || env.ResourceType == "" {
			return errors.New("compiled session response has an incomplete environment")
		}
		environments[i] = RequestEnvironment{env.PrincipalType, cedar.NewEntityUID(*env.Action.Type, *env.Action.ID), env.ResourceType}
	}
	s.environments = environments
	return nil
}

func (s *CompiledSession) initialize(ctx context.Context) error {
	if s.instance != nil {
		return nil
	}
	transport, err := s.analyzer.solver.Start(s.lifetime)
	if err != nil {
		return fmt.Errorf("analysis: %w", err)
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		closeErr := transport.Close()
		s.mu.Lock()
		s.closeErr = errors.Join(s.closeErr, closeErr)
		s.mu.Unlock()
		return s.closedError()
	}
	s.transport = transport
	s.mu.Unlock()
	instance, err := s.analyzer.module.Instantiate(ctx)
	if err != nil {
		return fmt.Errorf("analysis: %w", err)
	}
	s.instance = instance
	return nil
}

// Environments returns a copy of the session's fixed native environment selection.
func (s *CompiledSession) Environments() []RequestEnvironment {
	return append([]RequestEnvironment{}, s.environments...)
}

func (s *CompiledSession) closedError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reason == nil || errors.Is(s.reason, ErrCompiledClosed) {
		return ErrCompiledClosed
	}
	return errors.Join(ErrCompiledClosed, s.reason)
}

func (s *CompiledSession) abort(reason error) {
	s.mu.Lock()
	if s.closed {
		done := s.abortDone
		s.mu.Unlock()
		<-done
		return
	}
	s.closed, s.reason = true, reason
	transport := s.transport
	close(s.done)
	s.mu.Unlock()
	s.cancel()
	if transport != nil {
		if err := transport.Close(); err != nil {
			s.mu.Lock()
			s.closeErr = errors.Join(s.closeErr, err)
			s.mu.Unlock()
		}
	}

	close(s.abortDone)
}

func (s *CompiledSession) closeGuest() {
	if s.instance != nil {
		err := s.instance.Close(context.WithoutCancel(s.lifetime))
		s.instance = nil
		s.mu.Lock()
		s.closeErr = errors.Join(s.closeErr, err)
		s.mu.Unlock()
	}
	if s.analyzer != nil {
		s.analyzer.mu.Lock()
		delete(s.analyzer.sessions, s)
		s.analyzer.mu.Unlock()
	}
}

func (s *CompiledSession) closeWithReason(reason error) error {
	s.abort(reason)
	s.gate <- struct{}{}
	s.closeGuest()
	<-s.gate
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeErr
}

// Close interrupts an active call and waits for its guest resources to close.
func (s *CompiledSession) Close() error {
	if s == nil || s.analyzer == nil {
		return nil
	}
	return s.closeWithReason(ErrCompiledClosed)
}

func (s *CompiledSession) acquire(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return s.closedError()
	case s.gate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-s.gate
			return err
		}
		select {
		case <-s.done:
			<-s.gate
			return s.closedError()
		default:
			return nil
		}
	}
}

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
			s.closeGuest()
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
	out, err := s.instance.Call(context.WithValue(callCtx, sessionKey{}, state), "cgw_compiled", input, defaultMaxResponseBytes)
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

// Compile creates one native compiled set per selected request environment.
func (s *CompiledSession) Compile(ctx context.Context, policies cedar.PolicySet) (CompiledPolicySet, error) {
	if s == nil || s.analyzer == nil {
		return CompiledPolicySet{}, ErrCompiledClosed
	}
	value := source(policies.Format(), policies.Text())
	input, err := s.analyzer.encodeCompiled(compiledInput{Operation: "compile", Policies: &value})
	if err != nil {
		return CompiledPolicySet{}, err
	}
	var handle CompiledPolicySet
	err = s.execute(ctx, input, nil, func(data []byte) error {
		var result struct {
			Handle *uint64 `json:"handle"`
		}
		if err := json.Unmarshal(data, &result); err != nil {
			return err
		}
		if result.Handle == nil || *result.Handle == 0 {
			return errors.New("compiled response has no handle")
		}
		if *result.Handle <= s.lastHandle {
			return errors.New("compiled response reused a handle ID")
		}
		s.handles[*result.Handle] = struct{}{}
		s.lastHandle = *result.Handle
		handle = CompiledPolicySet{session: s, id: *result.Handle}
		return nil
	})
	if err != nil {
		return CompiledPolicySet{}, err
	}
	return handle, nil
}

func (s *CompiledSession) validateHandle(handle CompiledPolicySet) error {
	if handle.session != s || handle.id == 0 {
		return &Error{Kind: "handle", Message: "handle belongs to another session or is zero"}
	}
	if _, exists := s.handles[handle.id]; !exists {
		return &Error{Kind: "handle", Message: "handle is released"}
	}
	return nil
}

// Release removes the handle's original and compiled native policy data.
func (s *CompiledSession) Release(ctx context.Context, handle CompiledPolicySet) error {
	if s == nil || s.analyzer == nil {
		return ErrCompiledClosed
	}
	input, err := s.analyzer.encodeCompiled(compiledInput{Operation: "release", Handle: handle.id})
	if err != nil {
		return err
	}
	return s.execute(ctx, input, func() error { return s.validateHandle(handle) }, func(data []byte) error {
		var result struct {
			Released *bool `json:"released"`
		}
		if err := json.Unmarshal(data, &result); err != nil {
			return err
		}
		if result.Released == nil || !*result.Released {
			return errors.New("compiled response did not release the handle")
		}
		delete(s.handles, handle.id)
		return nil
	})
}

func (s *CompiledSession) check(ctx context.Context, query string, first, second CompiledPolicySet) (Report, error) {
	if s == nil || s.analyzer == nil {
		return Report{}, ErrCompiledClosed
	}
	input, err := s.analyzer.encodeCompiled(compiledInput{Operation: "check", Query: query, First: first.id, Second: second.id})
	if err != nil {
		return Report{}, err
	}
	var report Report
	err = s.execute(ctx, input, func() error {
		if err := s.validateHandle(first); err != nil {
			return err
		}
		return s.validateHandle(second)
	}, func(data []byte) error {
		var result struct {
			Report json.RawMessage `json:"report"`
		}
		if err := json.Unmarshal(data, &result); err != nil {
			return err
		}
		var output analyzeOutput
		if len(result.Report) == 0 {
			return errors.New("compiled response has no report")
		}
		if err := json.Unmarshal(result.Report, &output); err != nil {
			return err
		}
		var envelope map[string]json.RawMessage
		if err := json.Unmarshal(result.Report, &envelope); err != nil {
			return err
		}
		if _, present := envelope["results"]; !present || len(envelope) != 1 {
			return errors.New("compiled report has an invalid envelope")
		}
		if output.Results == nil || len(output.Results) != len(s.environments) {
			return errors.New("compiled response has the wrong environment count")
		}
		for i, result := range output.Results {
			env := s.environments[i]
			if result.PrincipalType != env.PrincipalType || result.Action.Type != env.Action.Type || result.Action.ID == nil || *result.Action.ID != env.Action.ID || result.ResourceType != env.ResourceType {
				return errors.New("compiled response has the wrong environment")
			}
		}
		var err error
		report, err = decodePropertyReport(output, false, query)
		return err
	})
	if err != nil {
		return Report{}, err
	}
	return report, nil
}

// Implies checks whether every request allowed by first is also allowed by second.
func (s *CompiledSession) Implies(ctx context.Context, first, second CompiledPolicySet) (Report, error) {
	return s.check(ctx, "implies", first, second)
}

// Equivalent checks whether both compiled policy sets always produce the same decision.
func (s *CompiledSession) Equivalent(ctx context.Context, first, second CompiledPolicySet) (Report, error) {
	return s.check(ctx, "equivalent", first, second)
}

// Disjoint checks whether no request is allowed by both compiled policy sets.
func (s *CompiledSession) Disjoint(ctx context.Context, first, second CompiledPolicySet) (Report, error) {
	return s.check(ctx, "disjoint", first, second)
}
