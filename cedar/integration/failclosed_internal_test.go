package integration

import (
	"context"
	"errors"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/native"
	"testing"
)

func TestModuleChecks(t *testing.T) {
	ctx := context.Background()
	if _, err := native.New(ctx, "missing"); err == nil {
		t.Fatal("unknown native module accepted")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := native.New(canceled, "authorizer"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled module construction: %v", err)
	}
	module, err := native.New(ctx, "authorizer")
	if err != nil {
		t.Fatal(err)
	}
	defer module.Close(ctx)
	instance, err := module.Instantiate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = instance.Call(ctx, "cgw_missing", []byte(`{}`), 1024)
	var fault *native.Fault
	if !errors.As(err, &fault) {
		t.Fatalf("unknown native operation accepted: %v", err)
	}
}
