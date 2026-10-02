// Package analysis compares Cedar policy sets with SymCC, Cedar's symbolic
// compiler, running in a WebAssembly module under wazero.
//
// SymCC turns each question into SMT-LIB queries. An external SMT solver,
// which you provide through a [Solver], answers them. Cedar supports cvc5;
// see [CVC5]. This module does not include a solver.
//
// Every counterexample that the solver returns is re-checked with Cedar's
// concrete authorizer inside the module, and the call fails if the check
// disagrees. A result that holds rests on the solver's "unsat" answer and
// on SymCC's encoding, which Cedar proves sound and complete in Lean.
package analysis
