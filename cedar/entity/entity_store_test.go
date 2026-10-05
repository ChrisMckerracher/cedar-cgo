package entity_test

import (
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
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
		if reflect.DeepEqual(testsupport.EntityStoreJSON(t, left), testsupport.EntityStoreJSON(t, right)) {
			t.Fatalf("different integers compare equal: %s and %s", left, right)
		}
		testsupport.EqualJSON(t, left, left)
	}
}
