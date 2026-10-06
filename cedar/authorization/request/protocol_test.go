package request

import (
	"errors"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	"testing"
)

func TestAuthorizationResponseRequiredFields(t *testing.T) {
	for _, input := range []string{
		`{`, `null`, `{}`, `{"decision":"allow"}`, `{"decision":"allow","reasons":[],"errors":null}`,
		`{"decision":"allow","reasons":null,"errors":[]}`, `{"decision":"unknown","reasons":[],"errors":[]}`,
		`{"decision":"allow","reasons":[],"errors":[{"message":"missing ID"}]}`,
		"{\"decision\":\"allow\",\"reasons\":[\"\xff\"],\"errors\":[]}",
	} {
		response, err := DecodeAuthorize([]byte(input))
		if response.Decision != Deny || !errors.Is(err, diagnostic.ErrFault) {
			t.Fatalf("malformed result granted permission: %+v %v", response, err)
		}
	}
	response, err := DecodeAuthorize([]byte(`{"decision":"allow","reasons":[],"errors":[]}`))
	if err != nil || response.Decision != Allow {
		t.Fatalf("valid response: %+v %v", response, err)
	}
}
