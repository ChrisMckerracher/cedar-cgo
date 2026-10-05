package analysis

import (
	"context"
	"encoding/json"
	"testing"

	uids "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	schemas "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
)

func TestCompiledEnvironmentJSONRoundTrip(t *testing.T) {
	want := RequestEnvironment{PrincipalType: "User", Action: uids.NewEntityUID("Action", "view"), ResourceType: "Document"}
	data, err := json.Marshal([]RequestEnvironment{want})
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `[{"principal_type":"User","action":{"type":"Action","id":"view"},"resource_type":"Document"}]` {
		t.Fatalf("selection JSON: %s", data)
	}
	var got []RequestEnvironment
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("selection round trip: %+v", got)
	}
	for _, env := range []RequestEnvironment{
		{PrincipalType: string([]byte{255}), Action: want.Action, ResourceType: want.ResourceType},
		{PrincipalType: want.PrincipalType, Action: uids.NewEntityUID("Action", string([]byte{255})), ResourceType: want.ResourceType},
		{PrincipalType: want.PrincipalType, Action: want.Action, ResourceType: string([]byte{255})},
	} {
		if _, err := json.Marshal(env); err == nil {
			t.Fatal("environment JSON replaced invalid UTF-8")
		}
	}
}

func TestCompiledOpenRequiresEnvironmentFields(t *testing.T) {
	for _, response := range []string{
		`{}`,
		`{"environments":null}`,
		`{"environments":[{"principal_type":"User","action":{"type":"Action"},"resource_type":"Document"}]}`,
		`{"environments":[{"principal_type":"User","action":{"type":"Action","id":null},"resource_type":"Document"}]}`,
		`{"environments":[{"principal_type":"User","action":{"id":""},"resource_type":"Document"}]}`,
		`{"environments":[{"principal_type":"User","action":{"type":null,"id":""},"resource_type":"Document"}]}`,
		`{"environments":[{"principal_type":"User","action":{"type":"","id":""},"resource_type":"Document"}]}`,
		`{"environments":[{"action":{"type":"Action","id":""},"resource_type":"Document"}]}`,
		`{"environments":[{"principal_type":"User","action":{"type":"Action","id":""}}]}`,
	} {
		t.Run(response, func(t *testing.T) {
			s, _, transport := testCompiledSession(t, func(context.Context, []byte) ([]byte, error) {
				return []byte(response), nil
			})
			if err := s.execute(context.Background(), nil, nil, s.decodeOpen); err == nil {
				t.Fatal("incomplete environment accepted")
			}
			if transport.closes.Load() != 1 {
				t.Fatal("environment fault kept solver alive")
			}
		})
	}
	for _, response := range []string{
		`{"environments":[]}`,
		`{"environments":[{"principal_type":"User","action":{"type":"Action","id":""},"resource_type":"Document"}]}`,
	} {
		t.Run(response, func(t *testing.T) {
			s, _, transport := testCompiledSession(t, func(context.Context, []byte) ([]byte, error) {
				return []byte(response), nil
			})
			if err := s.execute(context.Background(), nil, nil, s.decodeOpen); err != nil {
				t.Fatal(err)
			}
			if s.environments == nil || transport.closes.Load() != 0 {
				t.Fatal("valid environment response invalidated session")
			}
			if len(s.environments) == 1 && s.environments[0].Action != uids.NewEntityUID("Action", "") {
				t.Fatalf("empty action ID changed: %+v", s.environments)
			}
		})
	}
}

func TestCompiledEnvironmentUTF8BeforeGuest(t *testing.T) {
	a := &Analyzer{maxSourceBytes: 1 << 20}
	for _, env := range []RequestEnvironment{
		{PrincipalType: string([]byte{255}), Action: uids.NewEntityUID("Action", "view"), ResourceType: "Doc"},
		{PrincipalType: "User", Action: uids.NewEntityUID("Action", string([]byte{255})), ResourceType: "Doc"},
		{PrincipalType: "User", Action: uids.NewEntityUID("Action", "view"), ResourceType: string([]byte{255})},
	} {
		if _, err := a.OpenCompiled(context.Background(), schemas.SchemaFromCedar(querySchemaForUTF8), []RequestEnvironment{env}); err == nil {
			t.Fatal("invalid UTF-8 reached native execution")
		}
	}
}

const querySchemaForUTF8 = `entity User; entity Doc; action view appliesTo {principal: User, resource: Doc, context: {}};`
