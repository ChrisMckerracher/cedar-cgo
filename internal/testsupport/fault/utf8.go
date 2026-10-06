package fault

import (
	errors "errors"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	testing "testing"
)

func RequireUTF8InputError(t testing.TB, err error) {
	t.Helper()
	var ce *diagnostic.Error
	if !errors.As(err, &ce) || ce.Kind != diagnostic.KindInput {
		t.Fatalf("got %v; want KindInput", err)
	}
}
