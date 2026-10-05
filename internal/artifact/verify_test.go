package artifact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyArtifact(t *testing.T) {
	if err := Verify(fixture(t), testCommit); err != nil {
		t.Fatal(err)
	}
}

func TestRejectArtifactChanges(t *testing.T) {
	tests := []struct {
		name, message string
		change        func(*testing.T, string)
	}{
		{"missing module", "missing artifact file", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, "analysis", "analysis.wasm")); err != nil {
				t.Fatal(err)
			}
		}},
		{"extra file", "unexpected artifact entry", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "analysis", "other.wasm"), nil)
		}},
		{"extra directory", "unexpected artifact entry", func(t *testing.T, dir string) {
			if err := os.Mkdir(filepath.Join(dir, "other"), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"wrong commit", "source commit does not match", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "SOURCE_COMMIT"), []byte(strings.Repeat("0", 40)+"\n"))
		}},
		{"changed hash file", "generated source does not match", func(t *testing.T, dir string) {
			path := filepath.Join(dir, "analysis", "sha256.go")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			write(t, path, append(data, []byte("// changed\n")...))
		}},
		{"changed module with matching manifest", "generated source does not match", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "analysis", "analysis.wasm"), []byte("changed module"))
			rewriteManifest(t, dir)
		}},
		{"wrong checksum", "checksums or manifest paths", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "SHA256SUMS"), []byte("wrong\n"))
		}},
		{"manifest path traversal", "checksums or manifest paths", func(t *testing.T, dir string) {
			path := filepath.Join(dir, "SHA256SUMS")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			write(t, path, []byte(strings.ReplaceAll(string(data), "analysis/analysis.wasm", "../analysis.wasm")))
		}},
		{"injected Go declaration with matching manifest", "generated source does not match", func(t *testing.T, dir string) {
			path := filepath.Join(dir, "analysis", "sha256.go")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			write(t, path, append(data, []byte("func init() {}\n")...))
			rewriteManifest(t, dir)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := fixture(t)
			test.change(t, dir)
			if err := Verify(dir, testCommit); err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("got %v, want %q", err, test.message)
			}
		})
	}
}

func TestRejectInvalidCommit(t *testing.T) {
	for _, commit := range []string{"HEAD", testCommit[:39], strings.ToUpper(testCommit), strings.Repeat("z", 40)} {
		if err := Verify(fixture(t), commit); err == nil {
			t.Fatalf("accepted invalid commit %q", commit)
		}
	}
}
