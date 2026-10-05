package batched

import (
	context "context"
	json "encoding/json"

	fmt "fmt"
	request "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	execution "github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"
	native "github.com/ChrisMckerracher/cedar-go-wasm/internal/native"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

const (
	DefaultMaxBatchBytes  = 1 << 20
	DefaultMaxLoaderBytes = 16 << 20
	// MaxBatchedIterations bounds native work even when a loader makes no progress.
	MaxBatchedIterations                      = 1024
	KindLoader           diagnostic.ErrorKind = "loader"
	KindBatched          diagnostic.ErrorKind = "batched"
)

// EntityLoader loads concrete entities for Rust's experimental type-aware evaluator.
// Calls are synchronous and serial within one authorization, but concurrent authorizations
// may share a loader. Implementations must honor ctx; Go cannot interrupt a blocked callback.
type EntityLoader interface {
	LoadEntities(ctx context.Context, uids []entityuid.EntityUID) (EntityLoadResult, error)
}

// EntityLoaderFunc adapts a function to EntityLoader.
type EntityLoaderFunc func(context.Context, []entityuid.EntityUID) (EntityLoadResult, error)

func (f EntityLoaderFunc) LoadEntities(ctx context.Context, uids []entityuid.EntityUID) (EntityLoadResult, error) {
	return f(ctx, uids)
}

// EntityLoadResult distinguishes absent entities from data deferred to another iteration.
// Entities is a Cedar JSON entity array. Parents must include every ancestor, as required
// by Rust's EntityLoader. Extra entities are allowed; duplicate or conflicting UIDs fail.
type EntityLoadResult struct {
	Entities json.RawMessage
	// Missing explicitly marks nonexistent entities. Omitted UIDs remain unknown.
	Missing []entityuid.EntityUID
}

// BatchedOptions bounds an experimental on-demand authorization.
type BatchedOptions struct {
	// MaxIterations counts Rust loader rounds, including rounds served from preloaded entities.
	// Zero performs initial partial evaluation only; unresolved requests fail.
	MaxIterations uint32
	// MaxBatchBytes caps each encoded callback request and result. Zero uses DefaultMaxBatchBytes.
	MaxBatchBytes int
	// MaxLoaderBytes caps cumulative callback request and result bytes. Zero uses DefaultMaxLoaderBytes.
	MaxLoaderBytes int
}

// AuthorizeBatched uses upstream PolicySet::is_authorized_batched, an experimental API.
// A schema and strictly valid policies are required. Every error returns Deny.
// Loaded and request entities serve as a call-local cache; callback data never persists.
// The loader owns its requested UID slice and may retain it. Returned data must remain
// immutable until this method returns. CallTimeout includes callbacks but excludes pool wait.
// Callbacks must not close or recursively call this authorizer (which can deadlock its pool).
func (a *Client) AuthorizeBatched(ctx context.Context, req request.Request, loader EntityLoader, opts BatchedOptions) (request.Decision, error) {
	if loader == nil {
		return request.Deny, &diagnostic.Error{Kind: diagnostic.KindInput, Message: "entity loader is required"}
	}
	if opts.MaxIterations > MaxBatchedIterations {
		return request.Deny, &diagnostic.Error{Kind: diagnostic.KindLimit, Message: "iteration bound exceeds 1024"}
	}
	if opts.MaxBatchBytes == 0 {
		opts.MaxBatchBytes = DefaultMaxBatchBytes
	}
	if opts.MaxLoaderBytes == 0 {
		opts.MaxLoaderBytes = DefaultMaxLoaderBytes
	}
	if opts.MaxBatchBytes < 1 || opts.MaxBatchBytes > execution.DefaultMaxSourceBytes || opts.MaxLoaderBytes < 1 {
		return request.Deny, &diagnostic.Error{Kind: diagnostic.KindInput, Message: "loader byte limits must be positive; max batch bytes cannot exceed 64 MiB"}
	}
	in, err := execution.Encode(struct {
		request.AuthorizeInput
		MaxIterations uint32 `json:"max_iterations"`
		MaxBatchBytes int    `json:"max_batch_bytes"`
	}{request.AuthorizeInput{Principal: req.Principal.Wire(), Action: req.Action.Wire(), Resource: req.Resource.Wire(), Context: req.Context, Entities: req.Entities}, opts.MaxIterations, opts.MaxBatchBytes}, "request", a.session.Limits.MaxRequestBytes)
	if err != nil {
		return request.Deny, err
	}
	state := &EntityLoaderState{loader: loader, maxBatch: opts.MaxBatchBytes, remaining: opts.MaxLoaderBytes, maxCalls: opts.MaxIterations}
	ctx = native.WithCallback(ctx, state)
	var decision request.Decision
	err = a.session.Call(ctx, "cgw_authorize_batched", in, func(out []byte) error {
		if state.err != nil {
			return state.err
		}
		var result struct {
			Decision string      `json:"decision"`
			Error    *wire.Error `json:"error"`
		}
		if err := json.Unmarshal(out, &result); err != nil {
			return diagnostic.FaultError(err)
		}
		if result.Error != nil {
			if result.Error.Kind == string(KindBatched) || result.Error.Kind == string(KindLoader) {
				return &diagnostic.Error{Kind: diagnostic.ErrorKind(result.Error.Kind), Message: result.Error.Message}
			}
			return diagnostic.ModuleError(result.Error)
		}
		switch result.Decision {
		case "allow":
			decision = request.Allow
		case "deny":
			decision = request.Deny
		default:
			return diagnostic.FaultError(fmt.Errorf("batched response has decision %q", result.Decision))
		}
		return nil
	})
	if state.err != nil {
		return request.Deny, state.err
	}
	if err != nil {
		return request.Deny, err
	}
	return decision, nil
}

type EntityLoaderState struct {
	loader              EntityLoader
	maxBatch, remaining int
	maxCalls, calls     uint32
	pending             []byte
	err                 error
}

func (s *EntityLoaderState) fail(err error) int { s.err = err; s.pending = nil; return -1 }
