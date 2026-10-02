package cedar_test

import (
	"context"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm"
	"github.com/tetratelabs/wazero"
)

// BenchmarkAuthorizeJoy measures one decision over the 45-policy joy set,
// from the Go request to the Go response.
func BenchmarkAuthorizeJoy(b *testing.B) {
	a := newJoyAuthorizer(b, cedar.Limits{MaxInstances: 1})
	req := joyRequest()
	ctx := context.Background()
	b.ResetTimer()
	for b.Loop() {
		resp, err := a.Authorize(ctx, req)
		if err != nil || resp.Decision != cedar.Allow {
			b.Fatal(resp, err)
		}
	}
}

// BenchmarkValidateJoy measures strict validation of the joy set, which
// creates and closes one module instance.
func BenchmarkValidateJoy(b *testing.B) {
	d := loadJoy(b)
	rt := testRuntime(b)
	for b.Loop() {
		res, err := rt.Validate(context.Background(), d.schema, d.old)
		if err != nil || !res.Passed {
			b.Fatal(res, err)
		}
	}
}

// BenchmarkNewAuthorizerJoy measures creating an authorizer, which creates
// one instance and parses the schema, the policies and the entities in it.
func BenchmarkNewAuthorizerJoy(b *testing.B) {
	d := loadJoy(b)
	rt := testRuntime(b)
	for b.Loop() {
		a, err := rt.NewAuthorizer(context.Background(), cedar.Config{Schema: &d.schema, Policies: d.old, Entities: d.entities})
		if err != nil {
			b.Fatal(err)
		}
		a.Close()
	}
}

// BenchmarkAuthorizeJoyParallel measures throughput with one instance per
// CPU.
func BenchmarkAuthorizeJoyParallel(b *testing.B) {
	a := newJoyAuthorizer(b, cedar.Limits{})
	req := joyRequest()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, err := a.Authorize(context.Background(), req)
			if err != nil || resp.Decision != cedar.Allow {
				b.Error(resp, err)
				return
			}
		}
	})
}

// BenchmarkNewRuntime measures compiling the authorization module with no
// cache.
func BenchmarkNewRuntime(b *testing.B) {
	for b.Loop() {
		rt, err := cedar.NewRuntime(context.Background())
		if err != nil {
			b.Fatal(err)
		}
		_ = rt.Close(context.Background())
	}
}

// BenchmarkNewRuntimeCached measures NewRuntime with a warm compilation
// cache on disk, as on the second start of a process.
func BenchmarkNewRuntimeCached(b *testing.B) {
	dir := b.TempDir()
	cache, err := wazero.NewCompilationCacheWithDir(dir)
	if err != nil {
		b.Fatal(err)
	}
	rt, err := cedar.NewRuntime(context.Background(), cedar.WithCompilationCache(cache))
	if err != nil {
		b.Fatal(err)
	}
	_ = rt.Close(context.Background())
	for b.Loop() {
		// A new cache object over the same directory reads the code from
		// disk, as a new process would.
		cache, err := wazero.NewCompilationCacheWithDir(dir)
		if err != nil {
			b.Fatal(err)
		}
		rt, err := cedar.NewRuntime(context.Background(), cedar.WithCompilationCache(cache))
		if err != nil {
			b.Fatal(err)
		}
		_ = rt.Close(context.Background())
	}
}
