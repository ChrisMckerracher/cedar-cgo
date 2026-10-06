package schema

import (
	execution "github.com/ChrisMckerracher/cedar-cgo/internal/execution"

	context "context"
	errors "errors"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	syntax "github.com/ChrisMckerracher/cedar-cgo/cedar/syntax"
	testing "testing"
)

func TestSchemaLimitsBeforeGuest(t *testing.T) {
	rt := &Client{runtime: &execution.Runtime{MaxSourceBytes: 1}}
	ctx := context.Background()
	for _, operation := range []func() error{
		func() error { _, err := rt.ComposeSchema(ctx); return err },
		func() error {
			_, err := rt.ConvertSchemaFragment(ctx, SchemaFragmentFromCedar("entity User;"), syntax.FormatJSON)
			return err
		},
		func() error { _, err := rt.InspectSchema(ctx, SchemaFromCedar("")); return err },
		func() error { _, err := rt.ActionEntities(ctx, SchemaFromCedar("")); return err },
	} {
		var ce *diagnostic.Error
		if err := operation(); !errors.As(err, &ce) || ce.Kind != diagnostic.KindLimit {
			t.Fatalf("source limit: %v", err)
		}
	}
	rt.runtime.MaxSourceBytes = 1024
	bad := string([]byte{0xff})
	for _, operation := range []func() error{
		func() error {
			_, err := rt.ConvertSchemaFragment(ctx, SchemaFragmentFromCedar(bad), syntax.FormatJSON)
			return err
		},
		func() error { _, err := rt.ComposeSchema(ctx, SchemaFragmentFromCedar(bad)); return err },
		func() error { _, err := rt.InspectSchema(ctx, SchemaFromCedar(bad)); return err },
		func() error { _, err := rt.ActionEntities(ctx, SchemaFromCedar(bad)); return err },
	} {
		var ce *diagnostic.Error
		if err := operation(); !errors.As(err, &ce) || ce.Kind != diagnostic.KindInput {
			t.Fatalf("UTF-8 guard: %v", err)
		}
	}
}
