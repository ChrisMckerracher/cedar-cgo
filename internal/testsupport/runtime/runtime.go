// Package testruntime shares a native runtime within each test binary.
package testruntime

import (
	"context"
	"sync"
	"testing"

	"github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

var (
	shared *cedar.Runtime
	once   sync.Once
	err    error
)

func New(t testing.TB) *cedar.Runtime {
	t.Helper()
	once.Do(func() { shared, err = cedar.NewRuntime(context.Background()) })
	if err != nil {
		t.Fatal(err)
	}
	return shared
}
