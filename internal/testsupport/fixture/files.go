package fixture

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Path resolves repository fixtures independently of a test package's working directory.
func Path(name string) string {
	if filepath.IsAbs(name) {
		return name
	}
	trimmed := strings.TrimLeft(filepath.ToSlash(name), "./")
	if !strings.HasPrefix(trimmed, "testdata/") && !strings.HasPrefix(trimmed, "rust/") {
		return name
	}
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", filepath.FromSlash(trimmed))
}

func ReadFile(name string) ([]byte, error) { return os.ReadFile(Path(name)) }

func MustReadFile(t testing.TB, name string) []byte {
	t.Helper()
	data, err := ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
