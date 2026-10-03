package cedar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

const (
	DefaultMaxBatchBytes  = 1 << 20
	DefaultMaxLoaderBytes = 16 << 20
	// MaxBatchedIterations bounds guest work even when a loader makes no progress.
	MaxBatchedIterations           = 1024
	KindLoader           ErrorKind = "loader"
	KindBatched          ErrorKind = "batched"
)

// EntityLoader loads concrete entities for Rust's experimental type-aware evaluator.
// Calls are synchronous and serial within one authorization, but concurrent authorizations
// may share a loader. Implementations must honor ctx; Go cannot interrupt a blocked callback.
type EntityLoader interface {
	LoadEntities(ctx context.Context, uids []EntityUID) (EntityLoadResult, error)
}

// EntityLoaderFunc adapts a function to EntityLoader.
type EntityLoaderFunc func(context.Context, []EntityUID) (EntityLoadResult, error)

func (f EntityLoaderFunc) LoadEntities(ctx context.Context, uids []EntityUID) (EntityLoadResult, error) {
	return f(ctx, uids)
}

// EntityLoadResult distinguishes absent entities from data deferred to another iteration.
// Entities is a Cedar JSON entity array. Parents must include every ancestor, as required
// by Rust's EntityLoader. Extra entities are allowed; duplicate or conflicting UIDs fail.
type EntityLoadResult struct {
	Entities json.RawMessage
	// Missing explicitly marks nonexistent entities. Omitted UIDs remain unknown.
	Missing []EntityUID
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
func (a *Authorizer) AuthorizeBatched(ctx context.Context, req Request, loader EntityLoader, opts BatchedOptions) (Decision, error) {
	if loader == nil {
		return Deny, &Error{Kind: KindInput, Message: "entity loader is required"}
	}
	if opts.MaxIterations > MaxBatchedIterations {
		return Deny, &Error{Kind: KindLimit, Message: "iteration bound exceeds 1024"}
	}
	if opts.MaxBatchBytes == 0 {
		opts.MaxBatchBytes = DefaultMaxBatchBytes
	}
	if opts.MaxLoaderBytes == 0 {
		opts.MaxLoaderBytes = DefaultMaxLoaderBytes
	}
	if opts.MaxBatchBytes < 1 || opts.MaxBatchBytes > DefaultMaxSourceBytes || opts.MaxLoaderBytes < 1 {
		return Deny, &Error{Kind: KindInput, Message: "loader byte limits must be positive; max batch bytes cannot exceed 64 MiB"}
	}
	in, err := json.Marshal(struct {
		authorizeInput
		MaxIterations uint32 `json:"max_iterations"`
		MaxBatchBytes int    `json:"max_batch_bytes"`
	}{authorizeInput{req.Principal.wire(), req.Action.wire(), req.Resource.wire(), req.Context, req.Entities}, opts.MaxIterations, opts.MaxBatchBytes})
	if err != nil {
		return Deny, &Error{Kind: KindInput, Message: err.Error()}
	}
	if len(in) > a.limits.MaxRequestBytes {
		return Deny, limitError("request", len(in), a.limits.MaxRequestBytes)
	}
	res, err := a.pool.Acquire(ctx)
	if err != nil {
		return Deny, fmt.Errorf("cedar: acquire instance: %w", err)
	}
	defer a.finish(res)
	if a.limits.CallTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, a.limits.CallTimeout)
		defer cancel()
	}
	state := &entityLoaderState{loader: loader, maxBatch: opts.MaxBatchBytes, remaining: opts.MaxLoaderBytes, maxCalls: opts.MaxIterations}
	ctx = context.WithValue(ctx, entityLoaderKey{}, state)
	inst := res.Value()
	out, err := inst.Call(ctx, "cgw_authorize_batched", in, a.rt.maxResponse)
	if state.err != nil {
		inst.MarkFaulted()
		return Deny, state.err
	}
	if err != nil {
		return Deny, faultError(err)
	}
	var result struct {
		Decision string      `json:"decision"`
		Error    *wire.Error `json:"error"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		inst.MarkFaulted()
		return Deny, faultError(err)
	}
	if result.Error != nil {
		if result.Error.Kind == string(KindBatched) || result.Error.Kind == string(KindLoader) {
			return Deny, &Error{Kind: ErrorKind(result.Error.Kind), Message: result.Error.Message}
		}
		err := moduleError(result.Error)
		if errors.Is(err, ErrFault) {
			inst.MarkFaulted()
		}
		return Deny, err
	}
	switch result.Decision {
	case "allow":
		return Allow, nil
	case "deny":
		return Deny, nil
	default:
		inst.MarkFaulted()
		return Deny, faultError(fmt.Errorf("batched response has decision %q", result.Decision))
	}
}

type entityLoaderKey struct{}
type entityLoaderState struct {
	loader              EntityLoader
	maxBatch, remaining int
	maxCalls, calls     uint32
	pending             []byte
	err                 error
}

func defineEntityLoaderModule(ctx context.Context, r wazero.Runtime) error {
	_, err := r.NewHostModuleBuilder("cgw_entity_loader").
		NewFunctionBuilder().WithFunc(loadEntityBatch).Export("load").
		NewFunctionBuilder().WithFunc(readEntityBatch).Export("read").Instantiate(ctx)
	return err
}

func (s *entityLoaderState) fail(ctx context.Context, m api.Module, err error) int32 {
	s.err = err
	s.pending = nil
	// Closing terminates Rust promptly despite EntityLoader's infallible callback signature.
	_ = m.CloseWithExitCode(ctx, 1)
	return -1
}

func (s *entityLoaderState) charge(n int) error {
	if n > s.maxBatch {
		return limitError("loader batch", n, s.maxBatch)
	}
	if n > s.remaining {
		return limitError("loader cumulative data", n, s.remaining)
	}
	s.remaining -= n
	return nil
}

func loadEntityBatch(ctx context.Context, m api.Module, ptr, n uint32) (result int32) {
	s, _ := ctx.Value(entityLoaderKey{}).(*entityLoaderState)
	if s == nil || s.err != nil {
		return -1
	}
	defer func() {
		if recover() != nil {
			result = s.fail(ctx, m, &Error{Kind: KindLoader, Message: "entity loader panicked"})
		}
	}()
	if err := ctx.Err(); err != nil {
		return s.fail(ctx, m, faultError(err))
	}
	if s.pending != nil || s.calls >= s.maxCalls {
		return s.fail(ctx, m, faultError(errors.New("invalid loader call sequence")))
	}
	if uint64(n) > uint64(s.maxBatch) {
		return s.fail(ctx, m, &Error{Kind: KindLimit, Message: "loader request exceeds batch limit"})
	}
	if err := s.charge(int(n)); err != nil {
		return s.fail(ctx, m, err)
	}
	buf, ok := m.Memory().Read(ptr, n)
	if !ok {
		return s.fail(ctx, m, faultError(errors.New("loader request out of range")))
	}
	var ids []wire.UID
	if err := json.Unmarshal(buf, &ids); err != nil {
		return s.fail(ctx, m, faultError(err))
	}
	uids := make([]EntityUID, len(ids))
	for i, id := range ids {
		uids[i] = EntityUID{Type: id.Type, ID: id.ID}
	}
	s.calls++
	loaded, err := s.loader.LoadEntities(ctx, uids)
	if ctx.Err() != nil {
		return s.fail(ctx, m, faultError(ctx.Err()))
	}
	if err != nil {
		return s.fail(ctx, m, &Error{Kind: KindLoader, Message: err.Error(), Err: err})
	}
	body, err := encodeEntityLoadResult(loaded, min(s.maxBatch, s.remaining))
	if err != nil {
		return s.fail(ctx, m, err)
	}
	if err := s.charge(len(body)); err != nil {
		return s.fail(ctx, m, err)
	}
	s.pending = body
	return int32(len(body))
}

func encodeEntityLoadResult(result EntityLoadResult, limit int) ([]byte, error) {
	if len(result.Entities) == 0 {
		result.Entities = json.RawMessage("[]")
	}
	// Check raw lengths before allocation or JSON validation; encoded escaping is checked below.
	remaining := limit - len(result.Entities)
	if remaining < 0 || len(result.Missing) > remaining/19 {
		return nil, &Error{Kind: KindLimit, Message: "loader result exceeds byte limit"}
	}
	if err := wire.CheckUTF8(string(result.Entities)); err != nil {
		return nil, &Error{Kind: KindInput, Message: err.Error()}
	}
	missing := make([]wire.UID, len(result.Missing))
	for i, uid := range result.Missing {
		if len(uid.Type) > remaining {
			return nil, &Error{Kind: KindLimit, Message: "loader UID exceeds byte limit"}
		}
		remaining -= len(uid.Type)
		if len(uid.ID) > remaining {
			return nil, &Error{Kind: KindLimit, Message: "loader UID exceeds byte limit"}
		}
		remaining -= len(uid.ID)
		if err := wire.CheckUTF8(uid.Type, uid.ID); err != nil {
			return nil, &Error{Kind: KindInput, Message: err.Error()}
		}
		missing[i] = uid.wire()
	}
	body, err := json.Marshal(struct {
		Entities json.RawMessage `json:"entities"`
		Missing  []wire.UID      `json:"missing"`
	}{result.Entities, missing})
	if err != nil {
		return nil, &Error{Kind: KindLoader, Message: err.Error(), Err: err}
	}
	if len(body) > limit {
		return nil, limitError("loader result", len(body), limit)
	}
	return body, nil
}

func readEntityBatch(ctx context.Context, m api.Module, ptr, n uint32) int32 {
	s, _ := ctx.Value(entityLoaderKey{}).(*entityLoaderState)
	if s == nil || s.err != nil {
		return -1
	}
	if ctx.Err() != nil {
		return s.fail(ctx, m, faultError(ctx.Err()))
	}
	if s.pending == nil || uint64(n) != uint64(len(s.pending)) {
		return s.fail(ctx, m, faultError(errors.New("invalid loader read sequence")))
	}
	if !m.Memory().Write(ptr, s.pending) {
		return s.fail(ctx, m, faultError(errors.New("loader result out of range")))
	}
	s.pending = nil
	return 0
}
