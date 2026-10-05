package artifact

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type cgoCacheFixture struct {
	t         *testing.T
	directory string
	platform  string
	goTool    string
	compiler  string
	archiver  string
	env       []string
}

func newCgoCacheFixture(t *testing.T) *cgoCacheFixture {
	t.Helper()
	f := &cgoCacheFixture{t: t, directory: t.TempDir(), platform: runtime.GOOS + "_" + runtime.GOARCH}
	f.goTool, f.compiler, f.archiver = cacheTool(t, "go"), cacheTool(t, "cc"), cacheTool(t, "ar")
	cache, err := exec.Command(f.goTool, "env", "GOCACHE").Output()
	if err != nil {
		t.Fatal(err)
	}
	f.env = append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=local", "CGO_ENABLED=1", "GOFLAGS=", "GOOS="+runtime.GOOS, "GOARCH="+runtime.GOARCH, "GOCACHE="+strings.TrimSpace(string(cache)))
	for _, dir := range []string{"build", "native/lib/" + f.platform} {
		if err := os.MkdirAll(filepath.Join(f.directory, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(f.directory, "go.mod"), []byte("module cache.example\n\ngo 1.26.0\n"))
	write(t, filepath.Join(f.directory, "main.go"), []byte("package main\nimport (\"fmt\"; \"cache.example/native\")\nfunc main() { fmt.Println(native.Value()) }\n"))
	write(t, filepath.Join(f.directory, "native/value.go"), []byte("package native\n// int library_value(void);\nimport \"C\"\nfunc Value() int { return int(C.library_value()) }\n"))
	return f
}

func cacheTool(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Fatalf("cache integration requires %s: %v", name, err)
	}
	return path
}

func (f *cgoCacheFixture) run(name string, args ...string) []byte {
	f.t.Helper()
	command := exec.Command(name, args...)
	command.Dir, command.Env = f.directory, f.env
	out, err := command.CombinedOutput()
	if err != nil {
		f.t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return out
}

func (f *cgoCacheFixture) archive(value int) string {
	f.t.Helper()
	write(f.t, filepath.Join(f.directory, "build/library.c"), []byte(fmt.Sprintf("int library_value(void) { return %d; }\n", value)))
	f.run(f.compiler, "-c", "build/library.c", "-o", "build/library.o")
	path := filepath.Join(f.directory, "native/lib", f.platform, "libcgw_native.a")
	f.run(f.archiver, "crs", path, "build/library.o")
	data, err := os.ReadFile(path)
	if err != nil {
		f.t.Fatal(err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func (f *cgoCacheFixture) linkerSource(digest string) {
	f.t.Helper()
	source, err := LinkSource(f.platform, []string{"-lc"}, digest)
	if err != nil {
		f.t.Fatal(err)
	}
	write(f.t, filepath.Join(f.directory, "native/link_flags.go"), source)
}

func (f *cgoCacheFixture) binaryValue() string {
	f.t.Helper()
	path := filepath.Join(f.directory, "consumer")
	f.run(f.goTool, "build", "-buildvcs=false", "-o", path, ".")
	return strings.TrimSpace(string(f.run(path)))
}
