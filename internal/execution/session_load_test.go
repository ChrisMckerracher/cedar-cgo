package execution

import (
	"context"
	"errors"
	"testing"

	"github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
)

func TestLoadCancellationDuringDecode(t *testing.T) {
	background := context.Background()
	runtime, err := New(background)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close(background)
	session := &Session{Runtime: runtime, Limits: Limits{}.WithDefaults(), Load: []byte(`{"policies":{"format":"cedar","text":"permit(principal, action, resource);"},"entities":[]}`)}
	ctx, cancel := context.WithCancel(background)
	defer cancel()
	decoded := false
	instance, err := session.newInstance(ctx, func(data []byte) error {
		decodeErr := decodeLoad(data)
		decoded = decodeErr == nil
		cancel()
		return decodeErr
	})
	if !decoded || instance != nil || !errors.Is(err, context.Canceled) || !errors.Is(err, diagnostic.ErrFault) {
		t.Fatalf("canceled load: decoded=%t, instance=%v, error=%v", decoded, instance, err)
	}
	if created := session.created.Load(); created != 0 {
		t.Fatalf("canceled load counted as successful: %d", created)
	}
	instance, err = session.NewInstance(background)
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close(background)
	if session.created.Load() != 1 {
		t.Fatal("successful replacement load was not counted")
	}
}
