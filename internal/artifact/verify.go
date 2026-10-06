// Package artifact verifies native files before they enter the Go build.
package artifact

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

var paths = []string{"SOURCE_COMMIT", "cedar.h", "libcgw_native.a", "link_flags.go", "manifest.json"}

// Verify requires an exact artifact tree and the expected source, target, and header.
func Verify(dir, expectedCommit, expectedTarget string, header []byte) error {
	if len(expectedCommit) != 40 || lowerHex(expectedCommit) != expectedCommit {
		return fmt.Errorf("expected source commit must contain 40 lowercase hexadecimal characters")
	}
	if _, ok := Platforms[expectedTarget]; !ok {
		return fmt.Errorf("unsupported native target: %s", expectedTarget)
	}
	files, err := readTree(dir)
	if err != nil {
		return err
	}
	if string(files["SOURCE_COMMIT"]) != expectedCommit+"\n" {
		return fmt.Errorf("artifact source commit does not match %s", expectedCommit)
	}
	if !bytes.Equal(files["cedar.h"], header) {
		return fmt.Errorf("artifact header does not match source header")
	}
	var manifest Manifest
	if err := json.Unmarshal(files["manifest.json"], &manifest, json.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("decode native manifest: %w", err)
	}
	if err := manifest.verify(expectedCommit, expectedTarget, files); err != nil {
		return err
	}
	if err := verifyArchive(files["libcgw_native.a"], expectedTarget); err != nil {
		return err
	}
	var checksums bytes.Buffer
	for _, path := range paths {
		fmt.Fprintf(&checksums, "%x  %s\n", sha256.Sum256(files[path]), path)
	}
	if !bytes.Equal(files["SHA256SUMS"], checksums.Bytes()) {
		return fmt.Errorf("artifact checksums or manifest paths do not match")
	}
	return nil
}

func readTree(dir string) (map[string][]byte, error) {
	files := make(map[string][]byte)
	allowed := map[string]bool{"SHA256SUMS": true}
	for _, path := range paths {
		allowed[path] = true
	}
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if rel == "." && entry.IsDir() {
			return nil
		}
		if !allowed[rel] || !entry.Type().IsRegular() {
			return fmt.Errorf("unexpected artifact entry: %s", rel)
		}
		files[rel], err = os.ReadFile(path)
		return err
	})
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(allowed))
	for path := range allowed {
		names = append(names, path)
	}
	sort.Strings(names)
	for _, path := range names {
		if _, found := files[path]; !found {
			return nil, fmt.Errorf("missing artifact file: %s", path)
		}
	}
	return files, nil
}

func lowerHex(value string) string {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(decoded)
}
