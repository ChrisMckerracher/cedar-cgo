package verification

import (
	"bytes"
	"context"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestABIProofSource(t *testing.T) {
	rustSource, err := os.ReadFile("../../rust/crates/abi/src/lib.rs")
	if err != nil {
		t.Fatal(err)
	}
	_, respond, found := strings.Cut(string(rustSource), "pub fn respond(body: Vec<u8>) -> u64 {\n")
	if !found {
		t.Fatal("respond changed: review the ABI proof")
	}
	body, _, found := strings.Cut(respond, "\n}")
	if !found || !strings.HasSuffix(compact(body), "(u64::from(ptr)<<32)|u64::from(len)") {
		t.Fatal("response packing changed: update abi.smt2 and its source checks")
	}
	fileSet := token.NewFileSet()
	host, err := parser.ParseFile(fileSet, "../wasmhost/instance.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	wanted := map[string]bool{
		"packed := i.stack[0]":                               false,
		"rptr, rlen := uint32(packed >> 32), uint32(packed)": false,
		"rptr == 0 || rlen == 0":                             false,
		"rlen > maxResponse":                                 false,
	}
	for _, declaration := range host.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "Call" || function.Recv == nil {
			continue
		}
		for _, statement := range function.Body.List {
			var node ast.Node
			switch statement := statement.(type) {
			case *ast.AssignStmt:
				node = statement
			case *ast.IfStmt:
				node = statement.Cond
			default:
				continue
			}
			var rendered bytes.Buffer
			if err := format.Node(&rendered, fileSet, node); err != nil {
				t.Fatal(err)
			}
			for expression := range wanted {
				if compact(rendered.String()) == compact(expression) {
					wanted[expression] = true
				}
			}
		}
	}
	for expression, found := range wanted {
		if !found {
			t.Errorf("host expression %q changed: update abi.smt2 and its source checks", expression)
		}
	}
}

func TestABIProof(t *testing.T) {
	solver := os.Getenv("CVC5")
	if solver == "" {
		t.Skip("CVC5 is not set; see docs/verification.md")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, solver, "--lang=smt2", "abi.smt2").CombinedOutput()
	if err != nil {
		t.Fatalf("cvc5: %v\n%s", err, output)
	}
	if strings.Join(strings.Fields(string(output)), " ") != "unsat unsat unsat" {
		t.Fatalf("expected three proved properties, got:\n%s", output)
	}
	t.Log("proved: pointer/length round trip, zero sentinel, response-header predicates")
}

func compact(source string) string {
	return strings.Join(strings.Fields(source), "")
}
