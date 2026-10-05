package artifact

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeArtifactFrameworkPairs(t *testing.T) {
	flags := []string{"-liconv", "-framework", "CoreFoundation", "-lSystem", "-lc", "-lm", "-framework", "CoreFoundation", "-lc"}
	target := "aarch64-apple-darwin"
	dir := fixtureForTarget(t, target, flags)
	if err := Verify(dir, testCommit, target, testHeader); err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(filepath.Join(dir, "link_flags.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(source), "-lcgw_native "+strings.Join(flags, " ")+"\n") {
		t.Fatalf("generated source changed ordered or repeated flags: %s", source)
	}
}

func TestNativeArtifactRejectsUnsafeFrameworkRequirements(t *testing.T) {
	for _, test := range []struct {
		name, target, want string
		flags              []string
	}{
		{"linux amd64", testTarget, "native frameworks require darwin_arm64", []string{"-framework", "CoreFoundation"}},
		{"linux arm64", "aarch64-unknown-linux-gnu", "native frameworks require darwin_arm64", []string{"-framework", "CoreFoundation"}},
		{"orphan", "aarch64-apple-darwin", "native framework has no name", []string{"-lc", "-framework"}},
		{"path", "aarch64-apple-darwin", "invalid native framework name", []string{"-framework", "../CoreFoundation"}},
		{"line injection", "aarch64-apple-darwin", "invalid native framework name", []string{"-framework", "CoreFoundation\nimport unsafe"}},
		{"flag as name", "aarch64-apple-darwin", "invalid native framework name", []string{"-framework", "-lSystem"}},
		{"adjacent flag", "aarch64-apple-darwin", "invalid native framework name", []string{"-framework", "-framework", "CoreFoundation"}},
		{"extra name", "aarch64-apple-darwin", "invalid native linker requirement: Foundation", []string{"-framework", "CoreFoundation", "Foundation"}},
		{"empty name", "aarch64-apple-darwin", "invalid native framework name", []string{"-framework", ""}},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := fixtureForTarget(t, test.target, []string{"-lc"})
			body, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
			if err != nil {
				t.Fatal(err)
			}
			var manifest Manifest
			if err := json.Unmarshal(body, &manifest); err != nil {
				t.Fatal(err)
			}
			manifest.NativeStaticLibs = test.flags
			updateMetadata(t, dir, manifest)
			if err := Verify(dir, testCommit, test.target, testHeader); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got %v; want %s", err, test.want)
			}
		})
	}
}
