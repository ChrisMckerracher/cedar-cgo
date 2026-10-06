package schema_test

import (
	context "context"
	json "encoding/json"
	errors "errors"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	cedarschema "github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
	syntax "github.com/ChrisMckerracher/cedar-cgo/cedar/syntax"
	testruntime "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/runtime"

	testing "testing"
)

func TestSchemaErrors(t *testing.T) {
	rt := testruntime.New(t)
	ctx := context.Background()
	for _, test := range []struct {
		Fragments []cedarschema.SchemaFragment
		Kind      diagnostic.ErrorKind
	}{
		{[]cedarschema.SchemaFragment{cedarschema.SchemaFragmentFromCedar("invalid")}, diagnostic.KindSchema},
		{[]cedarschema.SchemaFragment{cedarschema.SchemaFragmentFromJSON([]byte(`{}`)), cedarschema.SchemaFragmentFromCedar(string([]byte{0xff}))}, diagnostic.KindInput},
		{[]cedarschema.SchemaFragment{cedarschema.SchemaFragmentFromCedar("entity User;"), cedarschema.SchemaFragmentFromCedar("entity User;")}, diagnostic.KindSchema},
		{[]cedarschema.SchemaFragment{cedarschema.SchemaFragmentFromCedar("type A = B;"), cedarschema.SchemaFragmentFromCedar("type B = A;")}, diagnostic.KindSchema},
		{[]cedarschema.SchemaFragment{cedarschema.SchemaFragmentFromCedar("action A in B;"), cedarschema.SchemaFragmentFromCedar("action B in A;")}, diagnostic.KindSchema},
	} {
		_, err := rt.Schemas().ComposeSchema(ctx, test.Fragments...)
		var ce *diagnostic.Error
		if !errors.As(err, &ce) || ce.Kind != test.Kind {
			t.Fatalf("composition error: %v", err)
		}
	}
	_, err := rt.Schemas().ConvertSchemaFragment(ctx, cedarschema.SchemaFragmentFromCedar(""), syntax.Format(99))
	var ce *diagnostic.Error
	if !errors.As(err, &ce) || ce.Kind != diagnostic.KindInput {
		t.Fatalf("invalid format: %v", err)
	}
}

func TestSchemaCompositionNamespaceAnnotations(t *testing.T) {
	rt := testruntime.New(t)
	schema, err := rt.Schemas().ComposeSchema(context.Background(),
		cedarschema.SchemaFragmentFromCedar(`@doc("first") namespace App { entity User; }`),
		cedarschema.SchemaFragmentFromCedar(`@doc("second") namespace App { entity Photo; }`))
	if err != nil {
		t.Fatal(err)
	}
	var declarations map[string]struct {
		Annotations map[string]string
	}
	if err := json.Unmarshal([]byte(schema.Text()), &declarations); err != nil {
		t.Fatal(err)
	}
	if declarations["App"].Annotations["doc"] != "second" {
		t.Fatalf("namespace annotation order: %s", schema.Text())
	}
}
