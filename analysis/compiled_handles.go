package analysis

import (
	"context"
	"encoding/json"
	"errors"

	policy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
)

// Compile creates one native compiled set per selected request environment.
func (s *CompiledSession) Compile(ctx context.Context, policies policy.PolicySet) (CompiledPolicySet, error) {
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
