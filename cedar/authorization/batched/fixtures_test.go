package batched_test

import (
	fixture "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/fixture"
	testruntime "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/runtime"

	context "context"
	json "encoding/json"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	batched "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/batched"
	request "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"

	testing "testing"
)

type BatchUID struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

func (u BatchUID) Uid() entityuid.EntityUID { return entityuid.NewEntityUID(u.Type, u.ID) }

type BatchFixture struct {
	Name, Schema, Policies string
	MaxIterations          uint32 `json:"max_iterations"`
	Request                struct {
		Principal, Action, Resource BatchUID
		Context                     json.RawMessage
	}
	Batches []struct {
		Entities json.RawMessage
		Missing  []BatchUID
	}
}

func BatchedFixtures(t testing.TB) []BatchFixture {
	t.Helper()
	data, err := fixture.ReadFile("../testdata/parity/batched/input.json")
	if err != nil {
		t.Fatal(err)
	}
	var out []BatchFixture
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func BatchAuthorizer(t testing.TB, f BatchFixture, limits authorization.Limits) *authorization.Authorizer {
	t.Helper()
	schema := cedarschema.SchemaFromCedar(f.Schema)
	a, err := testruntime.New(t).NewAuthorizer(context.Background(), authorization.Config{Schema: &schema, Policies: cedarpolicy.PoliciesFromCedar(f.Policies), Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a
}

func BatchRequest(f BatchFixture) request.Request {
	return request.Request{Principal: f.Request.Principal.Uid(), Action: f.Request.Action.Uid(), Resource: f.Request.Resource.Uid(), Context: request.ContextFromJSON(f.Request.Context)}
}

func FixtureBatch(f BatchFixture, n int) batched.EntityLoadResult {
	if n >= len(f.Batches) {
		return batched.EntityLoadResult{}
	}
	b := f.Batches[n]
	out := batched.EntityLoadResult{Entities: b.Entities}
	for _, uid := range b.Missing {
		out.Missing = append(out.Missing, uid.Uid())
	}
	return out
}
