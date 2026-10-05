package cedar

import (
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"
)

type RuntimeOption = execution.Option

var WithMaxSourceBytes = execution.WithMaxSourceBytes
var WithMaxResponseBytes = execution.WithMaxResponseBytes
var WithMaxConcurrentCalls = execution.WithMaxConcurrentCalls
var WithMemoryLimit = execution.WithMemoryLimit
var WithCompilationCache = execution.WithCompilationCache

const (
	DefaultMaxSourceBytes     = execution.DefaultMaxSourceBytes
	DefaultMaxResponseBytes   = execution.DefaultMaxResponseBytes
	DefaultMaxConcurrentCalls = execution.DefaultMaxConcurrentCalls
)
