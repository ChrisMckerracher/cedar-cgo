package store_test

import (
	jsonassert "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/jsonassert"

	reflect "reflect"
	testing "testing"
)

func TestEntityStoreJSONComparisonPreservesIntegers(t *testing.T) {
	for _, numbers := range [][2]string{
		{"9007199254740992", "9007199254740993"},
		{"9223372036854775806", "9223372036854775807"},
		{"-9223372036854775808", "-9223372036854775807"},
	} {
		left := []byte(`{"attrs":{"n":` + numbers[0] + `}}`)
		right := []byte(`{"attrs":{"n":` + numbers[1] + `}}`)
		if reflect.DeepEqual(jsonassert.Decode(t, left), jsonassert.Decode(t, right)) {
			t.Fatalf("different integers compare equal: %s and %s", left, right)
		}
		jsonassert.Equal(t, left, left)
	}
}
