package cedar

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ChrisMckerracher/cedar-go-wasm/internal/modules/authorizer"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wasmhost"
)

// TestFailClosedOnCorruptInstance overwrites the whole linear memory of an
// idle instance. The next call on it must fault, return Deny, and discard
// the instance, even though the policy allows every request.
func TestFailClosedOnCorruptInstance(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	a, err := rt.NewAuthorizer(ctx, Config{
		Policies: PoliciesFromCedar("permit(principal, action, resource);"),
		Limits:   Limits{MaxInstances: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	req := Request{
		Principal: NewEntityUID("User", "alice"),
		Action:    NewEntityUID("Action", "view"),
		Resource:  NewEntityUID("Photo", "p1"),
	}
	if resp, err := a.Authorize(ctx, req); err != nil || resp.Decision != Allow {
		t.Fatalf("before corruption: %+v, %v", resp, err)
	}

	res, err := a.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mem := res.Value().Module().Memory()
	if !mem.Write(0, bytes.Repeat([]byte{0xA5}, int(mem.Size()))) {
		t.Fatal("cannot overwrite guest memory")
	}
	res.Release()

	resp, err := a.Authorize(ctx, req)
	if resp.Decision != Deny || !errors.Is(err, ErrFault) {
		t.Fatalf("corrupt instance: %+v, %v; want deny and a fault", resp, err)
	}
	if s := a.Stats(); s.Discarded != 1 || s.Idle != 0 {
		t.Fatalf("corrupt instance was not discarded: %+v", s)
	}
	if resp, err := a.Authorize(ctx, req); err != nil || resp.Decision != Allow {
		t.Fatalf("after corruption: %+v, %v; want allow from a fresh instance", resp, err)
	}
	if s := a.Stats(); s.Created != 2 {
		t.Fatalf("stats %+v, want 2 instances created", s)
	}
}

func TestModuleChecks(t *testing.T) {
	ctx := context.Background()
	base := wasmhost.Config{
		Name:             "authorizer",
		Wasm:             authorizer.Wasm,
		SHA256:           authorizer.SHA256,
		MemoryLimitBytes: DefaultMemoryLimitBytes,
		AllowedImports:   authorizerImports,
		Exports:          []string{"cgw_load", "cgw_authorize", "cgw_validate"},
	}
	cases := map[string]struct {
		mutate func(*wasmhost.Config)
		want   string
	}{
		"hash mismatch": {func(c *wasmhost.Config) {
			c.Wasm = append(bytes.Clone(c.Wasm), 0)
		}, "SHA-256"},
		"import not allowed": {func(c *wasmhost.Config) {
			c.AllowedImports = c.AllowedImports[1:]
		}, "not allowed"},
		"missing export": {func(c *wasmhost.Config) {
			c.Exports = append(c.Exports, "cgw_missing")
		}, "missing export"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := base
			tc.mutate(&cfg)
			m, err := wasmhost.Compile(ctx, cfg)
			if err == nil {
				_ = m.Close(ctx)
				t.Fatal("compile succeeded")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}
