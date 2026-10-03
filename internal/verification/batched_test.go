package verification

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Full declaration fingerprints preserve the premises, casts, and guard order reviewed for the model.
func TestBatchedProofSource(t *testing.T) {
	checks := map[string]map[string]string{
		"../../cedar/batched.go": {
			"AuthorizeBatched":       "b3bb0932f52ec5a8ec771c645efe20012aa3dfdb4160806715c91a933fd097ba",
			"entityLoaderState":      "329f1433c14a880785396a433c40f17ffd1dcb0ff6a9fd1992cc8f520036e5c4",
			"charge":                 "c5ca032a105efe396ee4745fb0b36561faad5f68900d577c7809ca1cb17d7a83",
			"loadEntityBatch":        "6a8e0f705af595bea6bdeeb519e02caf10a68cd3ac0b8d07a5d89a93b95a2130",
			"encodeEntityLoadResult": "7c9f83fd575004c1c257b8d87e7b058343d58dad90e04c9d89b9e7008ca4a21e",
			"DefaultMaxBatchBytes":   "6cdd837b8a317898f0d862fa1357be0ff89d16521839b8c22fa8073b724f457c",
			"DefaultMaxLoaderBytes":  "e470d69e046e1be25c080a6f112920f5a61d0c97b4e085e1668b4c4b3bc07bf7",
		},
		"../../cedar/runtime.go": {
			"DefaultMaxSourceBytes": "3e3dd176f77d783ffd18525efa54c9e6bdc8f46317be81336484cd6a20c1696d",
		},
	}
	for path, wanted := range checks {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			switch declaration := declaration.(type) {
			case *ast.FuncDecl:
				checkBatchedDeclaration(t, path, declaration.Name.Name, declaration, wanted)
			case *ast.GenDecl:
				for _, spec := range declaration.Specs {
					switch spec := spec.(type) {
					case *ast.TypeSpec:
						checkBatchedDeclaration(t, path, spec.Name.Name, spec, wanted)
					case *ast.ValueSpec:
						for _, name := range spec.Names {
							checkBatchedDeclaration(t, path, name.Name, spec, wanted)
						}
					}
				}
			}
		}
		for name := range wanted {
			t.Errorf("%s: missing %s; review batched.smt2 source correspondence", path, name)
		}
	}
}

func checkBatchedDeclaration(t *testing.T, path, name string, node ast.Node, wanted map[string]string) {
	t.Helper()
	want, ok := wanted[name]
	if !ok {
		return
	}
	delete(wanted, name)
	var syntax bytes.Buffer
	positionType := reflect.TypeOf(token.Pos(0))
	// Positions and parser object links do not change the declaration's syntax.
	if err := ast.Fprint(&syntax, nil, node, func(field string, value reflect.Value) bool {
		return field != "Obj" && field != "Scope" && value.Type() != positionType && ast.NotNilFilter(field, value)
	}); err != nil {
		t.Fatal(err)
	}
	got := fmt.Sprintf("%x", sha256.Sum256(syntax.Bytes()))
	if got != want {
		t.Errorf("%s: %s changed (syntax SHA-256 %s); review batched.smt2 and its premises before updating this guard", path, name, got)
	}
}

func TestBatchedProof(t *testing.T) {
	solver := os.Getenv("CVC5")
	if solver == "" {
		t.Skip("CVC5 is not set; see docs/verification.md")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, solver, "--lang=smt2", "batched.smt2").CombinedOutput()
	if err != nil {
		t.Fatalf("cvc5: %v\n%s", err, output)
	}
	const want = "sat unsat unsat sat unsat sat unsat sat unsat"
	if got := strings.Join(strings.Fields(string(output)), " "); got != want {
		t.Fatalf("expected four satisfiable premise sets and five proved properties (%s), got:\n%s", want, output)
	}
	t.Log("proved: charge range and conservation, bounded call increment, request int conversion, positive result int32 conversion")
}
