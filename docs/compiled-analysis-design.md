# Reusable compiled analysis sessions

Issue: #27. Design recorded before implementation.

## Scope

Add reusable compilation and explicit request-environment selection.
Keep the existing stateless equivalence and implication methods.
Expose named checks through opaque compiled policy-set handles.
Keep raw symbolic terms, custom assertions, and custom symbolic environments inside Rust.
Their native contracts include undocumented invariants. This API does not export those invariants.
A later API can define typed assertions after it defines their validation and concrete replay contracts.

## Ownership

`Analyzer.OpenCompiled` creates one Go-owned solver session and one Wasm instance.
The constructor context controls the session lifetime.
The native instance owns one schema, selected request environments, compiled policy sets, and a symbolic compiler.
The Go session owns the instance, solver transport, lifetime cancellation, and call gate.
A handle contains its originating Go session and a native integer ID.
A handle has no pointer into Wasm memory.
The native session retains the original policy sets for concrete counterexample replay.

```text
Analyzer
  CompiledSession
    Go solver transport
    exclusive call gate
    Wasm instance
      Schema + RequestEnv values
      CedarSymCompiler<HostSolver>
      handle -> original PolicySet + compiled sets per environment
```

## Operations

Open the session with a schema and optional environment selection.
A nil selection uses all native schema environments.
A supplied selection must match native schema environments. Duplicate or unknown entries fail.
Compile each policy set once for every selected environment.
Reject templates through the native compilation contract.
Check implication, equivalence, or disjointness with existing native optimized methods.
Reuse compiled sets and the solver transport across checks.
Release a handle to remove its native policy data.
Limit each session to 128 active handles. The configured Wasm memory limit also applies.
Close the session to release all handles, its instance, and solver.
Closing the analyzer also closes its compiled sessions.

## Concurrency and faults

Serialize calls through a context-aware gate.
A canceled caller that still waits for the gate does not affect an active call.
Each active call uses the analyzer timeout and a new solver-output byte counter.
If an active call times out or is canceled, close the solver and invalidate the whole session.
A solver read must unblock when its transport closes.
A guest trap, malformed response, solver failure, or unconfirmed counterexample also invalidates the session.
Ordinary input and compilation errors leave the session usable.
Reject handles from another session before guest execution.
Never reuse native handle IDs within one session.

## Results and compatibility

Reuse the existing `Report`, `Result`, and `Counterexample` types.
Use the original policy sets to confirm each counterexample with Cedar's concrete authorizer.
Keep stateless methods independent. They continue to create and close a solver for each call.
Compiled sessions require explicit creation and closure.
The caller can use stateless calls when independent solver isolation is preferred.

## Verification

Compare reusable checks with stateless checks and replay all returned counterexamples.
Check one solver start across repeated reusable calls.
Test foreign, released, and zero handles.
Test cancellation while waiting and during an active solver call.
Test session and analyzer closure, output limits, malformed responses, and ordinary compilation failures.
Measure repeated checks with a benchmark after excluding initial session creation and compilation.
Record benchmark input, tool versions, iterations, timings, and allocations.

## Implementation refinement

The Go call gate covers resource construction as well as regular calls.
Register a session before construction so analyzer closure can cancel pending solver startup.
Cancel the session lifetime and close its solver before waiting for the guest call gate.
This order unblocks an active host read before guest cleanup.
Each native check retains the original policies and uses the existing concrete replay helper.
Native solver failures also discard the native session state.
Go rejects non-monotonic returned handle IDs, including IDs of released handles.
Cache one native default `SymEnv` for each selected request environment.
All handles compile with clones of those terms and share the same symbolic request variables.
`CompiledSchema::sym_env` preserves the native default environment contract.
Tests compare the cached environment with `SymEnv::new` and compare distinct conditional policies.
Host transport faults invalidate the session before ordinary native errors are processed.
Response envelopes contain one success field or one complete error record.
Go rejects invalid UTF-8 and error fields inside compiled reports before decoding results.
Late solver cleanup errors join construction errors and remain available to analyzer closure.
