// Package artifact verifies generated Wasm files before they enter the Go build.
package artifact

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

var paths = []string{
	"analysis/analysis.wasm", "analysis/sha256.go",
	"authorizer/authorizer.wasm", "authorizer/sha256.go",
}

// Verify requires an exact artifact tree and the full source commit identifier.
func Verify(dir, expectedCommit string) error {
	if len(expectedCommit) != 40 {
		return fmt.Errorf("expected source commit must contain 40 lowercase hexadecimal characters")
	}
	if _, err := hex.DecodeString(expectedCommit); err != nil || expectedCommit != lowerHex(expectedCommit) {
		return fmt.Errorf("expected source commit must contain 40 lowercase hexadecimal characters")
	}
	allowed := map[string]bool{"SOURCE_COMMIT": false, "SHA256SUMS": false}
	for _, path := range paths {
		allowed[path] = false
	}
	if err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if entry.IsDir() && (rel == "." || rel == "analysis" || rel == "authorizer") {
			return nil
		}
		if _, ok := allowed[rel]; !ok || !entry.Type().IsRegular() {
			return fmt.Errorf("unexpected artifact entry: %s", rel)
		}
		allowed[rel] = true
		return nil
	}); err != nil {
		return err
	}
	for path, found := range allowed {
		if !found {
			return fmt.Errorf("missing artifact file: %s", path)
		}
	}
	source, err := os.ReadFile(filepath.Join(dir, "SOURCE_COMMIT"))
	if err != nil {
		return err
	}
	if string(source) != expectedCommit+"\n" {
		return fmt.Errorf("artifact source commit does not match %s", expectedCommit)
	}
	var manifest bytes.Buffer
	for i := 0; i < len(paths); i += 2 {
		wasm, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(paths[i])))
		if err != nil {
			return err
		}
		sum := fmt.Sprintf("%x", sha256.Sum256(wasm))
		hashFile, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(paths[i+1])))
		if err != nil {
			return err
		}
		if err := verifyGoHash(hashFile, filepath.Dir(paths[i]), sum); err != nil {
			return fmt.Errorf("%s: %w", paths[i+1], err)
		}
		fmt.Fprintf(&manifest, "%s  %s\n%x  %s\n", sum, paths[i], sha256.Sum256(hashFile), paths[i+1])
	}
	checksums, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		return err
	}
	if !bytes.Equal(checksums, manifest.Bytes()) {
		return fmt.Errorf("artifact checksums or manifest paths do not match")
	}
	return nil
}

func lowerHex(value string) string {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(decoded)
}
