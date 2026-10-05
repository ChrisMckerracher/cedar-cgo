//go:build !windows

package artifact

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRejectSymbolicLinks(t *testing.T) {
	t.Run("file", func(t *testing.T) {
		dir := fixture(t)
		path := filepath.Join(dir, "libcgw_native.a")
		target := filepath.Join(t.TempDir(), "libcgw_native.a")
		if err := os.Rename(path, target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if err := Verify(dir, testCommit, testTarget, testHeader); err == nil {
			t.Fatal("accepted a symbolic link instead of a module")
		}
	})
	t.Run("root", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "artifact")
		if err := os.Symlink(fixture(t), path); err != nil {
			t.Fatal(err)
		}
		if err := Verify(path, testCommit, testTarget, testHeader); err == nil {
			t.Fatal("accepted a symbolic link instead of the artifact directory")
		}
	})
}
