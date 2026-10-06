package integration_test

import (
	context "context"
	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	request "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	joy "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/joy"
	testruntime "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/runtime"

	testing "testing"
)

func BenchmarkAuthorizeJoy(b *testing.B) {
	a := joy.NewJoyAuthorizer(b, authorization.Limits{MaxInstances: 1})
	req := joy.JoyRequest()
	ctx := context.Background()
	for b.Loop() {
		resp, err := a.Authorize(ctx, req)
		if err != nil || resp.Decision != request.Allow {
			b.Fatal(resp, err)
		}
	}
}

func BenchmarkValidateJoy(b *testing.B) {
	d := joy.LoadJoy(b)
	rt := testruntime.New(b)
	for b.Loop() {
		res, err := rt.Validation().Validate(context.Background(), d.Schema, d.Old)
		if err != nil || !res.Passed {
			b.Fatal(res, err)
		}
	}
}

func BenchmarkNewAuthorizerJoy(b *testing.B) {
	d := joy.LoadJoy(b)
	rt := testruntime.New(b)
	for b.Loop() {
		a, err := rt.NewAuthorizer(context.Background(), authorization.Config{Schema: &d.Schema, Policies: d.Old, Entities: d.Entities})
		if err != nil {
			b.Fatal(err)
		}
		a.Close()
	}
}

func BenchmarkAuthorizeJoyParallel(b *testing.B) {
	a := joy.NewJoyAuthorizer(b, authorization.Limits{})
	req := joy.JoyRequest()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, err := a.Authorize(context.Background(), req)
			if err != nil || resp.Decision != request.Allow {
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

// Native runtime construction has no guest compilation or disk cache.
func BenchmarkNewRuntimeParallel(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			runtime, err := cedar.NewRuntime(context.Background())
			if err != nil {
				b.Error(err)
				return
			}
			if err := runtime.Close(context.Background()); err != nil {
				b.Error(err)
				return
			}
		}
	})
}
