package cedar_test

import (
	"context"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	"github.com/tetratelabs/wazero"
)

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

func BenchmarkNewRuntime(b *testing.B) {
	for b.Loop() {
		rt, err := cedar.NewRuntime(context.Background())
		if err != nil {
			b.Fatal(err)
		}
		_ = rt.Close(context.Background())
	}
}

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
		// Reopen the disk cache to model a process restart.
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
