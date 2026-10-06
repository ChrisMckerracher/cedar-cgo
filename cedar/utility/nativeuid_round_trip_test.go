package utility_test

import (
	context "context"
	errors "errors"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	testruntime "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/runtime"

	testing "testing"
	utf8 "unicode/utf8"
)

func FuzzNativeUIDRoundTrip(f *testing.F) {
	rt := testruntime.New(f)
	for _, id := range []string{"", "雪😀", "\x00\a\b\f\n\r\t\"\\", "plain", string([]byte{0xff})} {
		f.Add(id)
	}
	f.Fuzz(func(t *testing.T, id string) {
		if len(id) > 4096 {
			t.Skip()
		}
		uid := entityuid.NewEntityUID("NS::User", id)
		TextValue, err := uid.CedarText(context.Background(), rt.Utilities())
		if !utf8.ValidString(id) {
			var ce *diagnostic.Error
			if TextValue != "" || !errors.As(err, &ce) || ce.Kind != diagnostic.KindInput {
				t.Fatalf("accepted invalid UTF-8: %q %v", TextValue, err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := rt.Utilities().ParseEntityUID(context.Background(), TextValue)
		if err != nil || parsed != uid {
			t.Fatalf("round trip %q: %+v %v", TextValue, parsed, err)
		}
	})
}
