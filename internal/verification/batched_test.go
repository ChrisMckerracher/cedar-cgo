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
		"../../cedar/authorization/batched/batched.go": {
			"AuthorizeBatched":      "73a8833b8f2592e49d98c39b24aadbb2454707530ad62d89a6b60ed538f6973b",
			"EntityLoaderState":     "2bd5d64c0e198178676dc673ebf9678391eaca2eb1cf94a88cd0533a7c9048da",
			"DefaultMaxBatchBytes":  "6cdd837b8a317898f0d862fa1357be0ff89d16521839b8c22fa8073b724f457c",
			"DefaultMaxLoaderBytes": "e470d69e046e1be25c080a6f112920f5a61d0c97b4e085e1668b4c4b3bc07bf7",
		},
		"../../cedar/authorization/batched/callback.go": {
			"charge":                 "bcdc4920f823a1b13a76abc3de6e23270e7f35c7066616ad903856e12c63a148",
			"LoadEntityBatch":        "56dd39db215beea321944e547dae1651c6d1c5386fd509de68be6c9883e9f6d3",
			"EncodeEntityLoadResult": "9fcf62b608186a9db5b9101f0c28aae3ab7cb2655c93a8bc6ee133f214fe4a9c",
		},
		"../../internal/execution/runtime.go": {
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
	t.Log("proved: charge range and conservation, bounded call increment, request length bound, positive native callback result")
}
