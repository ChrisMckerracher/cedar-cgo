package execution

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/native"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

func (a *Session) NewInstance(ctx context.Context) (*native.Instance, error) {
	return a.newInstance(ctx, decodeLoad)
}

func (a *Session) newInstance(ctx context.Context, decode func([]byte) error) (*native.Instance, error) {
	ctx, cancel := context.WithTimeout(ctx, a.Limits.LoadTimeout)
	defer cancel()
	release, err := a.Runtime.Acquire(ctx)
	if err != nil {
		return nil, diagnostic.FaultError(err)
	}
	defer release()
	instance, err := a.Runtime.Module.Instantiate(ctx)
	if err != nil {
		return nil, diagnostic.FaultError(err)
	}
	out, err := instance.Call(ctx, "cgw_load", a.Load, a.Runtime.MaxResponse)
	if err == nil {
		err = CompletionError(ctx, decode(out))
	} else {
		err = diagnostic.FaultError(err)
	}
	if err != nil {
		_ = instance.Close(context.WithoutCancel(ctx))
		return nil, err
	}
	a.created.Add(1)
	return instance, nil
}

func decodeLoad(out []byte) error {
	var result struct {
		Policies *int        `json:"policies"`
		Error    *wire.Error `json:"error"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		return diagnostic.FaultError(err)
	}
	if result.Error != nil {
		return diagnostic.ModuleError(result.Error)
	}
	if result.Policies == nil {
		return diagnostic.FaultError(errors.New("load response has no result"))
	}
	return nil
}
