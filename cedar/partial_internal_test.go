package cedar

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
)

func TestPartialDecodeFaults(t *testing.T) {
	for _, input := range []string{
		`null`, `{}`, `[]`, `{"decision":"Allow"}`, `{"decision":"allow","reasons":[],"residuals":null}`,
		`{"decision":"allow","reasons":null,"residuals":[]}`,
		`{"decision":"allow","reasons":[],"residuals":[{"effect":"permit","state":"unknown","cedar":"p"}]}`,
		`{"decision":"allow","reasons":[],"residuals":[{"effect":"other","state":"true","cedar":"p"}]}`,
		`{"decision":"allow","reasons":[],"residuals":[{"effect":"permit","state":"true","cedar":""}]}`,
		`{"decision":"allow","reasons":[],"residuals":[{"effect":"permit","state":"true","cedar":"p"},{"effect":"permit","state":"true","cedar":"p"}]}`,
		`{"error":{"kind":"unexpected","message":"x"}}`,
	} {
		r, err := decodePartial([]byte(input))
		if r.Decision != Undecided || !errors.Is(err, ErrFault) {
			t.Fatalf("%s: %+v %v", input, r, err)
		}
	}
}

func TestPartialFaultRecovery(t *testing.T) {
	ctx := context.Background()
	cache := wazero.NewCompilationCache()
	defer cache.Close(ctx)
	rt, err := NewRuntime(ctx, WithMemoryLimit(16<<20), WithCompilationCache(cache))
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	schema := SchemaFromCedar(`entity User; entity Photo; action view appliesTo {principal: User, resource: Photo, context: {mfa: Bool, payload?: String}};`)
	a, err := rt.NewAuthorizer(ctx, Config{Schema: &schema, Policies: PoliciesFromCedar(`permit(principal, action, resource) when { context.mfa };`), Limits: Limits{MaxInstances: 1, MaxRequestBytes: 8 << 20, CallTimeout: 5 * time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	req := PartialRequest{Principal: UnknownEntityUID("User"), Action: NewEntityUID("Action", "view"), Resource: UnknownEntityUID("Photo")}
	continuation, err := a.PartialAuthorize(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	concrete := Request{Principal: NewEntityUID("User", "alice"), Action: req.Action, Resource: NewEntityUID("Photo", "one"), Context: NewContext(Record{"mfa": Bool(true)})}
	recover := func(t *testing.T) {
		t.Helper()
		r, err := continuation.Reauthorize(ctx, concrete)
		if err != nil || r.Decision != Allow {
			t.Fatalf("recovery: %+v %v", r, err)
		}
	}
	t.Run("waiting_cancellation", func(t *testing.T) {
		res, err := a.pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Release()
		for _, resume := range []bool{false, true} {
			cctx, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
			if resume {
				r, e := continuation.Reauthorize(cctx, concrete)
				if r.Decision != Deny || !errors.Is(e, context.DeadlineExceeded) {
					t.Fatalf("%+v %v", r, e)
				}
			} else {
				r, e := a.PartialAuthorize(cctx, req)
				if r.Decision != Undecided || !errors.Is(e, context.DeadlineExceeded) {
					t.Fatalf("%+v %v", r, e)
				}
			}
			cancel()
		}
	})
	for _, resume := range []bool{false, true} {
		for _, fault := range []string{"response_limit", "corruption", "memory_limit"} {
			t.Run(fault+map[bool]string{false: "_partial", true: "_reauthorize"}[resume], func(t *testing.T) {
				before := a.Stats().Discarded
				preq, creq := req, concrete
				switch fault {
				case "response_limit":
					rt.maxResponse = 8
				case "corruption":
					res, err := a.pool.Acquire(ctx)
					if err != nil {
						t.Fatal(err)
					}
					mem := res.Value().Module().Memory()
					if !mem.Write(0, bytes.Repeat([]byte{0xA5}, int(mem.Size()))) {
						t.Fatal("overwrite failed")
					}
					res.Release()
				case "memory_limit":
					big := NewContext(Record{"mfa": Bool(true), "payload": String(strings.Repeat("x", 4<<20))})
					preq.Context, creq.Context = &big, big
				}
				if resume {
					r, e := continuation.Reauthorize(ctx, creq)
					if r.Decision != Deny || !errors.Is(e, ErrFault) {
						t.Fatalf("%+v %v", r, e)
					}
				} else {
					r, e := a.PartialAuthorize(ctx, preq)
					if r.Decision != Undecided || !errors.Is(e, ErrFault) {
						t.Fatalf("%+v %v", r, e)
					}
				}
				rt.maxResponse = DefaultMaxResponseBytes
				if a.Stats().Discarded != before+1 {
					t.Fatalf("fault retained: %+v", a.Stats())
				}
				recover(t)
			})
		}
	}
}
