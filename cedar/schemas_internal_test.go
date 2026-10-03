package cedar

import (
	"context"
	"errors"
	"testing"
)

func TestSchemaLimitsBeforeGuest(t *testing.T) {
	rt := &Runtime{maxSourceBytes: 1}
	ctx := context.Background()
	for _, operation := range []func() error{
		func() error { _, err := rt.ComposeSchema(ctx); return err },
		func() error {
			_, err := rt.ConvertSchemaFragment(ctx, SchemaFragmentFromCedar("entity User;"), FormatJSON)
			return err
		},
		func() error { _, err := rt.InspectSchema(ctx, SchemaFromCedar("")); return err },
		func() error { _, err := rt.ActionEntities(ctx, SchemaFromCedar("")); return err },
	} {
		var ce *Error
		if err := operation(); !errors.As(err, &ce) || ce.Kind != KindLimit {
			t.Fatalf("source limit: %v", err)
		}
	}
	rt.maxSourceBytes = 1024
	bad := string([]byte{0xff})
	for _, operation := range []func() error{
		func() error {
			_, err := rt.ConvertSchemaFragment(ctx, SchemaFragmentFromCedar(bad), FormatJSON)
			return err
		},
		func() error { _, err := rt.ComposeSchema(ctx, SchemaFragmentFromCedar(bad)); return err },
		func() error { _, err := rt.InspectSchema(ctx, SchemaFromCedar(bad)); return err },
		func() error { _, err := rt.ActionEntities(ctx, SchemaFromCedar(bad)); return err },
	} {
		var ce *Error
		if err := operation(); !errors.As(err, &ce) || ce.Kind != KindInput {
			t.Fatalf("UTF-8 guard: %v", err)
		}
	}
}
