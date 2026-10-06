package compiled

import (
	"context"
	"encoding/json/v2"
	"errors"

	"github.com/ChrisMckerracher/cedar-cgo/analysis/report"
	policy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	"github.com/ChrisMckerracher/cedar-cgo/internal/wire"
)

// PolicySet is an opaque handle owned by one Session.
// Release removes its native data. Handles cannot move between sessions.
type PolicySet struct {
	session *Session
	id      uint64
}

// Compile creates one native compiled set per selected request environment.
func (s *Session) Compile(ctx context.Context, policies policy.PolicySet) (PolicySet, error) {
	if s == nil || s.gate == nil {
		return PolicySet{}, ErrClosed
	}
	value := wire.Source{Format: policies.Format().String(), Text: policies.Text()}
	input, err := s.encodeCompiled(compiledInput{Operation: "compile", Policies: &value})
	if err != nil {
		return PolicySet{}, err
	}
	var handle PolicySet
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
		handle = PolicySet{session: s, id: *result.Handle}
		return nil
	})
	if err != nil {
		return PolicySet{}, err
	}
	return handle, nil
}

func (s *Session) validateHandle(handle PolicySet) error {
	if handle.session != s || handle.id == 0 {
		return &report.Error{Kind: "handle", Message: "handle belongs to another session or is zero"}
	}
	if _, exists := s.handles[handle.id]; !exists {
		return &report.Error{Kind: "handle", Message: "handle is released"}
	}
	return nil
}

// Release removes the handle's original and compiled native policy data.
func (s *Session) Release(ctx context.Context, handle PolicySet) error {
	if s == nil || s.gate == nil {
		return ErrClosed
	}
	input, err := s.encodeCompiled(compiledInput{Operation: "release", Handle: handle.id})
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
