package batched

import (
	context "context"
	json "encoding/json"
	errors "errors"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

func (s *EntityLoaderState) Call(ctx context.Context, op uint32, data []byte) (result int, err error) {
	defer func() {
		if recover() != nil {
			result = s.fail(&diagnostic.Error{Kind: diagnostic.KindLoader, Message: "entity loader panicked"})
			err = s.err
		}
	}()
	switch op {
	case 1:
		result = LoadEntityBatch(ctx, s, data)
	case 2:
		result = ReadEntityBatch(ctx, s, data)
	default:
		result = s.fail(diagnostic.FaultError(errors.New("invalid loader callback operation")))
	}
	return result, s.err
}

func (s *EntityLoaderState) charge(n int) error {
	if n > s.maxBatch {
		return diagnostic.LimitError("loader batch", n, s.maxBatch)
	}
	if n > s.remaining {
		return diagnostic.LimitError("loader cumulative data", n, s.remaining)
	}
	s.remaining -= n
	return nil
}

func LoadEntityBatch(ctx context.Context, s *EntityLoaderState, buf []byte) (result int) {
	n := len(buf)
	if s == nil || s.err != nil {
		return -1
	}
	if err := ctx.Err(); err != nil {
		return s.fail(diagnostic.FaultError(err))
	}
	if s.pending != nil || s.calls >= s.maxCalls {
		return s.fail(diagnostic.FaultError(errors.New("invalid loader call sequence")))
	}
	if uint64(n) > uint64(s.maxBatch) {
		return s.fail(&diagnostic.Error{Kind: diagnostic.KindLimit, Message: "loader request exceeds batch limit"})
	}
	if err := s.charge(int(n)); err != nil {
		return s.fail(err)
	}
	var ids []wire.UID
	if err := json.Unmarshal(buf, &ids); err != nil {
		return s.fail(diagnostic.FaultError(err))
	}
	uids := make([]entityuid.EntityUID, len(ids))
	for i, id := range ids {
		uids[i] = entityuid.EntityUID{Type: id.Type, ID: id.ID}
	}
	s.calls++
	loaded, err := s.loader.LoadEntities(ctx, uids)
	if ctx.Err() != nil {
		return s.fail(diagnostic.FaultError(ctx.Err()))
	}
	if err != nil {
		return s.fail(&diagnostic.Error{Kind: diagnostic.KindLoader, Message: err.Error(), Err: err})
	}
	body, err := EncodeEntityLoadResult(loaded, min(s.maxBatch, s.remaining))
	if err != nil {
		return s.fail(err)
	}
	if err := s.charge(len(body)); err != nil {
		return s.fail(err)
	}
	s.pending = body
	return len(body)
}

func EncodeEntityLoadResult(result EntityLoadResult, limit int) ([]byte, error) {
	if len(result.Entities) == 0 {
		result.Entities = json.RawMessage("[]")
	}
	// Check raw lengths before allocation or JSON validation; encoded escaping is checked below.
	remaining := limit - len(result.Entities)
	if remaining < 0 || len(result.Missing) > remaining/19 {
		return nil, &diagnostic.Error{Kind: diagnostic.KindLimit, Message: "loader result exceeds byte limit"}
	}
	if err := wire.CheckUTF8(string(result.Entities)); err != nil {
		return nil, &diagnostic.Error{Kind: diagnostic.KindInput, Message: err.Error()}
	}
	missing := make([]wire.UID, len(result.Missing))
	for i, uid := range result.Missing {
		if len(uid.Type) > remaining {
			return nil, &diagnostic.Error{Kind: diagnostic.KindLimit, Message: "loader UID exceeds byte limit"}
		}
		remaining -= len(uid.Type)
		if len(uid.ID) > remaining {
			return nil, &diagnostic.Error{Kind: diagnostic.KindLimit, Message: "loader UID exceeds byte limit"}
		}
		remaining -= len(uid.ID)
		if err := wire.CheckUTF8(uid.Type, uid.ID); err != nil {
			return nil, &diagnostic.Error{Kind: diagnostic.KindInput, Message: err.Error()}
		}
		missing[i] = uid.Wire()
	}
	body, err := json.Marshal(struct {
		Entities json.RawMessage `json:"entities"`
		Missing  []wire.UID      `json:"missing"`
	}{result.Entities, missing})
	if err != nil {
		return nil, &diagnostic.Error{Kind: diagnostic.KindLoader, Message: err.Error(), Err: err}
	}
	if len(body) > limit {
		return nil, diagnostic.LimitError("loader result", len(body), limit)
	}
	return body, nil
}

func ReadEntityBatch(ctx context.Context, s *EntityLoaderState, data []byte) int {
	if s == nil || s.err != nil {
		return -1
	}
	if ctx.Err() != nil {
		return s.fail(diagnostic.FaultError(ctx.Err()))
	}
	if s.pending == nil || len(data) != len(s.pending) {
		return s.fail(diagnostic.FaultError(errors.New("invalid loader read sequence")))
	}
	copy(data, s.pending)
	s.pending = nil
	return 0
}
