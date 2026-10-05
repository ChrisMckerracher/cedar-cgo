package testsupport

import (
	fixture "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/fixture"

	context "context"
	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	request "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	cedarentity "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	cedarvalue "github.com/ChrisMckerracher/cedar-go-wasm/cedar/value"

	sync "sync"
	testing "testing"
)

var (
	SharedRuntime     *cedar.Runtime
	SharedRuntimeOnce sync.Once
	SharedRuntimeErr  error
)

// Compile once per test binary; the disk cache also spares fuzz workers the startup cost.
func TestRuntime(t testing.TB) *cedar.Runtime {
	t.Helper()
	SharedRuntimeOnce.Do(func() { SharedRuntime, SharedRuntimeErr = cedar.NewRuntime(context.Background()) })
	if SharedRuntimeErr != nil {
		t.Fatal(SharedRuntimeErr)
	}
	return SharedRuntime
}

func ReadFile(t testing.TB, name string) []byte {
	t.Helper()
	b, err := fixture.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type JoyData struct {
	Schema   cedarschema.Schema
	Old      cedarpolicy.PolicySet
	New      cedarpolicy.PolicySet
	Tight    cedarpolicy.PolicySet
	Entities cedarentity.Entities
}

func LoadJoy(t testing.TB) JoyData {
	return JoyData{
		Schema:   cedarschema.SchemaFromCedar(string(ReadFile(t, "../testdata/joy/joy.cedarschema"))),
		Old:      cedarpolicy.PoliciesFromCedar(string(ReadFile(t, "../testdata/joy/old.cedar"))),
		New:      cedarpolicy.PoliciesFromCedar(string(ReadFile(t, "../testdata/joy/new.cedar"))),
		Tight:    cedarpolicy.PoliciesFromCedar(string(ReadFile(t, "../testdata/joy/tight.cedar"))),
		Entities: cedarentity.EntitiesFromJSON(ReadFile(t, "../testdata/joy/entities.json")),
	}
}

func JoyContext() request.Context {
	return request.NewContext(cedarvalue.Record{
		"deviceLevel":     cedarvalue.Long(1),
		"platform":        cedarvalue.Record{"os": cedarvalue.String("ios"), "model": cedarvalue.String("iPhone17,1"), "securityLevel": cedarvalue.Long(3)},
		"sessionId":       cedarvalue.String("s1"),
		"now":             cedarvalue.Datetime("2026-10-01T12:00:00Z"),
		"machineAttested": cedarvalue.Bool(true),
		"sourceIp":        cedarvalue.IPAddr("10.1.2.3"),
	})
}

func JoyRequest() request.Request {
	return request.Request{
		Principal: entityuid.NewEntityUID("Joy::Device", "phone1"),
		Action:    entityuid.NewEntityUID("Joy::Action", "session.write"),
		Resource:  entityuid.NewEntityUID("Joy::Session", "s1"),
		Context:   JoyContext(),
	}
}

func NewJoyAuthorizer(t testing.TB, limits authorization.Limits) *authorization.Authorizer {
	t.Helper()
	d := LoadJoy(t)
	a, err := TestRuntime(t).NewAuthorizer(context.Background(), authorization.Config{
		Schema:   &d.Schema,
		Policies: d.Old,
		Entities: d.Entities,
		Limits:   limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a
}
