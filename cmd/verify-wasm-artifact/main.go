// Command verify-wasm-artifact checks Wasm files before a Go build embeds them.
package main

import (
	"fmt"
	"os"

	"github.com/ChrisMckerracher/cedar-go-wasm/internal/artifact"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: verify-wasm-artifact ARTIFACT_DIR SOURCE_COMMIT")
		os.Exit(1)
	}
	if err := artifact.Verify(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("Wasm artifact files and source commit match.")
}
