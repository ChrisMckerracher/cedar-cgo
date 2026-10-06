package performance

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"

	"github.com/ChrisMckerracher/cedar-cgo/cedar"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/authorization"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/batched"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
)

const callbackEntities = `[{"uid":{"type":"User","id":"alice"},"attrs":{"enabled":true},"parents":[]}]`

func callbackConfig() authorization.Config {
	source := schema.SchemaFromCedar("entity User = {enabled: Bool}; entity Document; action read appliesTo {principal: User, resource: Document, context: {}};")
	return authorization.Config{Schema: &source, Policies: policy.PoliciesFromCedar("permit(principal,action,resource) when {principal.enabled};"), Limits: authorization.Limits{MaxInstances: 2}}
}

func callbackRequest() request.Request {
	return request.Request{Principal: uid.NewEntityUID("User", "alice"), Action: uid.NewEntityUID("Action", "read"), Resource: uid.NewEntityUID("Document", "guide")}
}

func BenchmarkControlledCallback(b *testing.B) {
	runtime, err := cedar.NewRuntime(context.Background(), cedar.WithMaxConcurrentCalls(2))
	if err != nil {
		b.Fatal(err)
	}
	defer runtime.Close(context.Background())
	authorizer, err := runtime.NewAuthorizer(context.Background(), callbackConfig())
	if err != nil {
		b.Fatal(err)
	}
	defer authorizer.Close()
	var calls atomic.Uint64
	loader := batched.EntityLoaderFunc(func(context.Context, []uid.EntityUID) (batched.EntityLoadResult, error) {
		calls.Add(1)
		return batched.EntityLoadResult{Entities: json.RawMessage(callbackEntities)}, nil
	})
	b.ReportAllocs()
	for b.Loop() {
		decision, err := authorizer.Batched().AuthorizeBatched(context.Background(), callbackRequest(), loader, batched.BatchedOptions{MaxIterations: 4})
		if err != nil || decision != request.Allow {
			b.Fatal(decision, err)
		}
	}
	b.ReportMetric(float64(calls.Load()), "loader-calls")
	reportStats(b, authorizer)
}
