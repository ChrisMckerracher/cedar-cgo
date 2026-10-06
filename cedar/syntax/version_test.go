package syntax_test

import (
	syntax "github.com/ChrisMckerracher/cedar-go-wasm/cedar/syntax"
	fixture "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/fixture"

	regexp "regexp"
	testing "testing"
)

func TestVersionsMatchCargoLock(t *testing.T) {
	lock := string(fixture.MustReadFile(t, "../rust/Cargo.lock"))
	for crate, want := range map[string]string{
		"cedar-policy":           syntax.CedarVersion,
		"cedar-policy-core":      syntax.CedarVersion,
		"cedar-policy-formatter": syntax.CedarVersion,
		"cedar-policy-symcc":     syntax.SymCCVersion,
	} {
		re := regexp.MustCompile(`(?m)^name = "` + regexp.QuoteMeta(crate) + `"\r?\nversion = "([^"]+)"`)
		m := re.FindStringSubmatch(lock)
		if m == nil {
			t.Fatalf("%s is not in rust/Cargo.lock", crate)
		}
		if m[1] != want {
			t.Errorf("rust/Cargo.lock has %s %s, the Go constant says %s", crate, m[1], want)
		}
	}
}
