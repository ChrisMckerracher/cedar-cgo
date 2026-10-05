package authorization

import (
	entity "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

type LoadInput struct {
	Schema   *wire.Source    `json:"schema"`
	Policies wire.Source     `json:"policies"`
	Entities entity.Entities `json:"entities,omitzero"`
}

type LoadOutput struct {
	Policies *int        `json:"policies"`
	Error    *wire.Error `json:"error"`
}
