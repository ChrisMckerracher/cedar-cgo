package authorization

import (
	entity "github.com/ChrisMckerracher/cedar-cgo/cedar/entity"
	policy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	schema "github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
	execution "github.com/ChrisMckerracher/cedar-cgo/internal/execution"
)

type Config struct {
	// Schema checks entities, contexts and requests, and supplies action entities.
	// Use the validation client to check policies before ordinary authorization.
	Schema   *schema.Schema
	Policies policy.PolicySet
	// Entities are available to every request.
	Entities entity.Entities
	Limits   execution.Limits
}

type Limits = execution.Limits
type Stats = execution.Stats

const (
	DefaultCallTimeout     = execution.DefaultCallTimeout
	DefaultLoadTimeout     = execution.DefaultLoadTimeout
	DefaultMaxRequestBytes = execution.DefaultMaxRequestBytes
	DefaultMaxInstances    = execution.DefaultMaxInstances
)
