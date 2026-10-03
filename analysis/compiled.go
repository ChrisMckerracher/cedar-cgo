package analysis

import (
	"context"
	"encoding/json"
	"errors"
	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
	"sync"
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
