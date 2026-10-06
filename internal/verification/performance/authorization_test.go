package performance

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ChrisMckerracher/cedar-cgo/cedar"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/authorization"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/entity"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
)

func joyConfig(t testing.TB) authorization.Config {
	t.Helper()
	read := func(name string) []byte {
		root := os.Getenv("CEDAR_BENCH_FIXTURES")
		if root == "" {
			root = "../../../testdata"
		}
		data, err := os.ReadFile(filepath.Join(root, "joy", name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	source := schema.SchemaFromCedar(string(read("joy.cedarschema")))
	return authorization.Config{Schema: &source, Policies: policy.PoliciesFromCedar(string(read("old.cedar"))), Entities: entity.EntitiesFromJSON(read("entities.json")), Limits: authorization.Limits{MaxInstances: 2}}
}

func joyRequest() request.Request {
	return request.Request{Principal: uid.NewEntityUID("Joy::Device", "phone1"), Action: uid.NewEntityUID("Joy::Action", "session.write"), Resource: uid.NewEntityUID("Joy::Session", "s1"), Context: request.ContextFromJSON([]byte(`{"deviceLevel":1,"platform":{"os":"ios","model":"iPhone17,1","securityLevel":3},"sessionId":"s1","now":{"__extn":{"fn":"datetime","arg":"2026-10-01T12:00:00Z"}},"machineAttested":true,"sourceIp":{"__extn":{"fn":"ip","arg":"10.1.2.3"}}}`))}
}

func benchmarkAuthorizer(b *testing.B) *authorization.Authorizer {
	b.Helper()
	rt, err := cedar.NewRuntime(context.Background(), cedar.WithMaxConcurrentCalls(2))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = rt.Close(context.Background()) })
	authorizer, err := rt.NewAuthorizer(context.Background(), joyConfig(b))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(authorizer.Close)
	return authorizer
}

func reportStats(b *testing.B, authorizer *authorization.Authorizer) {
	stats := authorizer.Stats()
	b.ReportMetric(float64(stats.Created), "created")
	b.ReportMetric(float64(stats.Discarded), "discarded")
	b.ReportMetric(float64(stats.Idle), "idle")
}

func BenchmarkControlledSerial(b *testing.B) {
	authorizer := benchmarkAuthorizer(b)
	req := joyRequest()
	b.ReportAllocs()
	for b.Loop() {
		response, err := authorizer.Authorize(context.Background(), req)
		if err != nil || response.Decision != request.Allow {
			b.Fatal(response, err)
		}
	}
	reportStats(b, authorizer)
}

func BenchmarkControlledParallel(b *testing.B) {
	authorizer := benchmarkAuthorizer(b)
	req := joyRequest()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			response, err := authorizer.Authorize(context.Background(), req)
			if err != nil || response.Decision != request.Allow {
				b.Error(response, err)
				return
			}
		}
	})
	b.StopTimer()
	reportStats(b, authorizer)
}

func BenchmarkControlledRuntime(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		runtime, err := cedar.NewRuntime(context.Background(), cedar.WithMaxConcurrentCalls(2))
		if err != nil {
			b.Fatal(err)
		}
		if err := runtime.Close(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkControlledLoad(b *testing.B) {
	runtime, err := cedar.NewRuntime(context.Background(), cedar.WithMaxConcurrentCalls(2))
	if err != nil {
		b.Fatal(err)
	}
	defer runtime.Close(context.Background())
	config := joyConfig(b)
	created, discarded := uint64(0), uint64(0)
	b.ReportAllocs()
	for b.Loop() {
		authorizer, err := runtime.NewAuthorizer(context.Background(), config)
		if err != nil {
			b.Fatal(err)
		}
		stats := authorizer.Stats()
		created, discarded = created+stats.Created, discarded+stats.Discarded
		authorizer.Close()
	}
	b.ReportMetric(float64(created), "created")
	b.ReportMetric(float64(discarded), "discarded")
}
