package performance

import (
	"context"
	"testing"

	"github.com/ChrisMckerracher/cedar-cgo/cedar"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
)

func checkJoyResponse(b *testing.B, response request.Response, err error) {
	b.Helper()
	if err != nil || response.Decision != request.Allow || len(response.Errors) != 0 || len(response.Reasons) != 1 || response.Reasons[0] != "policy1" {
		b.Fatalf("Joy response: %+v, error: %v", response, err)
	}
}

func BenchmarkRustCgoAuthorize(b *testing.B) {
	authorizer := benchmarkAuthorizer(b)
	req := joyRequest()
	ctx := context.Background()
	response, err := authorizer.Authorize(ctx, req)
	checkJoyResponse(b, response, err)
	b.ReportAllocs()
	for b.Loop() {
		response, err := authorizer.Authorize(ctx, req)
		checkJoyResponse(b, response, err)
	}
	reportStats(b, authorizer)
}

func BenchmarkRustCgoLoad(b *testing.B) {
	runtime, err := cedar.NewRuntime(context.Background(), cedar.WithMaxConcurrentCalls(2))
	if err != nil {
		b.Fatal(err)
	}
	defer runtime.Close(context.Background())
	config := joyConfig(b)
	authorizer := benchmarkAuthorizer(b)
	response, err := authorizer.Authorize(context.Background(), joyRequest())
	checkJoyResponse(b, response, err)
	b.ReportAllocs()
	for b.Loop() {
		authorizer, err := runtime.NewAuthorizer(context.Background(), config)
		if err != nil {
			b.Fatal(err)
		}
		stats := authorizer.Stats()
		if stats.Created != 1 || stats.Discarded != 0 {
			b.Fatalf("authorizer stats: %+v", stats)
		}
		authorizer.Close()
	}
}

func BenchmarkRustCgoValidate(b *testing.B) {
	runtime, err := cedar.NewRuntime(context.Background(), cedar.WithMaxConcurrentCalls(2))
	if err != nil {
		b.Fatal(err)
	}
	defer runtime.Close(context.Background())
	config := joyConfig(b)
	b.ReportAllocs()
	for b.Loop() {
		result, err := runtime.Validation().Validate(context.Background(), *config.Schema, config.Policies)
		if err != nil || !result.Passed || len(result.Errors) != 0 || len(result.Warnings) != 0 || len(result.SchemaWarnings) != 0 {
			b.Fatalf("Joy validation: %+v, error: %v", result, err)
		}
	}
}
