package integration_test

import (
	context "context"
	json "encoding/json"
	errors "errors"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	cedarpartial "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/partial"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	cedarentity "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarvalue "github.com/ChrisMckerracher/cedar-go-wasm/cedar/value"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	testing "testing"
)

func TestAuthorizeRejectsInvalidUTF8Identity(t *testing.T) {
	a, err := testsupport.TestRuntime(t).NewAuthorizer(context.Background(), authorization.Config{
		Policies: cedarpolicy.PoliciesFromCedar(`permit(principal == User::"\u{fffd}", action, resource);`),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	req := cedarrequest.Request{
		Principal: entityuid.NewEntityUID("User", string([]byte{0xff})),
		Action:    entityuid.NewEntityUID("Action", "view"),
		Resource:  entityuid.NewEntityUID("Resource", "item"),
	}
	resp, err := a.Authorize(context.Background(), req)
	var ce *diagnostic.Error
	if resp.Decision != cedarrequest.Deny || !errors.As(err, &ce) || ce.Kind != diagnostic.KindInput {
		t.Fatalf("malformed identity: decision=%s error=%v; want deny and KindInput", resp.Decision, err)
	}
	req.Principal.ID = "\ufffd"
	resp, err = a.Authorize(context.Background(), req)
	if err != nil || resp.Decision != cedarrequest.Allow {
		t.Fatalf("valid replacement character: decision=%s error=%v; want allow", resp.Decision, err)
	}
}

func TestRejectInvalidUTF8Values(t *testing.T) {
	bad := string([]byte{0xff})
	uid := entityuid.NewEntityUID("User", bad)
	record := cedarvalue.Record{bad: cedarvalue.Bool(true)}
	cases := map[string]any{
		"UID type": entityuid.NewEntityUID(bad, "a"), "UID ID": uid,
		"string": cedarvalue.String(bad), "decimal": cedarvalue.Decimal(bad),
		"IP": cedarvalue.IPAddr(bad), "datetime": cedarvalue.Datetime(bad), "duration": cedarvalue.Duration(bad),
		"record key": record, "nested set": cedarvalue.Set{cedarvalue.Record{"a": cedarvalue.Set{cedarvalue.String(bad)}}},
		"entity UID":       cedarentity.Entity{UID: uid},
		"entity parent":    cedarentity.Entity{UID: entityuid.NewEntityUID("User", "a"), Parents: []entityuid.EntityUID{uid}},
		"entity attribute": cedarentity.Entity{Attrs: cedarvalue.Record{"a": cedarvalue.String(bad)}},
		"entity tag":       cedarentity.Entity{Tags: record},
		"raw entities":     cedarentity.EntitiesFromJSON([]byte(`[{"uid":{"type":"User","id":"` + bad + `"}}]`)),
		"raw context":      cedarrequest.ContextFromJSON([]byte(`{"a":"` + bad + `"}`)),
		"partial UID type": cedarpartial.UnknownEntityUID(bad), "partial UID ID": cedarpartial.KnownEntityUID(uid),
		"partial entity UID":        cedarpartial.PartialEntity{UID: uid},
		"partial entity parent":     cedarpartial.PartialEntity{Parents: []entityuid.EntityUID{uid}},
		"partial entity attributes": cedarpartial.PartialEntity{Attrs: &record},
		"partial entity tags":       cedarpartial.PartialEntity{Tags: &record},
		"raw partial entities":      cedarpartial.PartialEntitiesFromJSON([]byte(`[{"uid":{"type":"User","id":"` + bad + `"}}]`)),
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := json.Marshal(value)
			if err == nil {
				t.Fatal("malformed UTF-8 encoded without an error")
			}
		})
	}
}
