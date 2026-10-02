package cedar_test

import (
	"regexp"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

func TestVersionsMatchCargoLock(t *testing.T) {
	lock := string(readFile(t, "../rust/Cargo.lock"))
	for crate, want := range map[string]string{
		"cedar-policy":           cedar.CedarVersion,
		"cedar-policy-core":      cedar.CedarVersion,
		"cedar-policy-formatter": cedar.CedarVersion,
		"cedar-policy-symcc":     cedar.SymCCVersion,
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
