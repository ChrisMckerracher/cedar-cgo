package slicing_test

import (
	bytes "bytes"
	json "encoding/json"
	request "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	cedarentity "github.com/ChrisMckerracher/cedar-cgo/cedar/entity"
	slicing "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/slicing"
	entityuid "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
	fixture "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/fixture"
	sort "sort"
	testing "testing"
)

type SliceFixture struct {
	Name     string
	Schema   json.RawMessage
	Policies string
	Entities json.RawMessage
	Request  struct {
		Principal entityuid.EntityUID
		Action    entityuid.EntityUID
		Resource  entityuid.EntityUID
		Context   json.RawMessage
	}
}

func (f SliceFixture) Input() (slicing.SliceConfig, request.Request) {
	schema := cedarschema.SchemaFromJSON(f.Schema)
	var TextValue string
	if json.Unmarshal(f.Schema, &TextValue) == nil {
		schema = cedarschema.SchemaFromCedar(TextValue)
	}
	return slicing.SliceConfig{Schema: schema, Policies: cedarpolicy.PoliciesFromCedar(f.Policies), Entities: cedarentity.EntitiesFromJSON(f.Entities)},
		request.Request{Principal: f.Request.Principal, Action: f.Request.Action, Resource: f.Request.Resource, Context: request.ContextFromJSON(f.Request.Context)}
}

func SliceFixtures(t testing.TB) []SliceFixture {
	t.Helper()
	var fixtures []SliceFixture
	if err := json.Unmarshal(fixture.MustReadFile(t, "../testdata/parity/slicing/cases.json"), &fixtures); err != nil {
		t.Fatal(err)
	}
	return fixtures
}

func CanonicalEntities(t testing.TB, raw []byte) string {
	t.Helper()
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	var canonical func(any)
	canonical = func(v any) {
		switch v := v.(type) {
		case []any:
			for _, item := range v {
				canonical(item)
			}
			sort.Slice(v, func(i, j int) bool {
				a, _ := json.Marshal(v[i])
				b, _ := json.Marshal(v[j])
				return string(a) < string(b)
			})
		case map[string]any:
			for _, item := range v {
				canonical(item)
			}
		}
	}
	canonical(value)
	out, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}
