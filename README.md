# cedar-go-wasm

cedar-go-wasm gives Go programs [Cedar](https://www.cedarpolicy.com/)'s
reference semantics. It runs Cedar's Rust implementation, the
[`cedar-policy`](https://crates.io/crates/cedar-policy) crate, as
WebAssembly under [wazero](https://wazero.io/). It needs no cgo and no Rust
toolchain. Package `analysis` adds change analysis with Cedar's symbolic
compiler, SymCC.

This release embeds cedar-policy 4.13.0 and cedar-policy-symcc 0.7.0. It
passes Cedar's integration-test corpus through the Go API with zero
mismatches. No version is tagged yet; the API may change before v1.

Why it exists: the Go port, [cedar-go](https://github.com/cedar-policy/cedar-go),
has merged no pull request since 2026-06-01. Its strict validator disagrees
with Rust 4.13.0 on 68 of the corpus's 7,523 tests.

```bash
go get github.com/ChrisMckerracher/cedar-go-wasm
```

The module requires Go 1.26 or later.

## Example

```go
ctx := context.Background()
rt, err := cedar.NewRuntime(ctx) // verifies and compiles the embedded module
if err != nil {
	return err
}
defer rt.Close(ctx)

schema := cedar.SchemaFromCedar(`
entity User;
entity Photo { owner: User, private: Bool };
action view appliesTo { principal: User, resource: Photo, context: { mfa: Bool } };
`)
alice := cedar.NewEntityUID("User", "alice")
a, err := rt.NewAuthorizer(ctx, cedar.Config{
	Schema: &schema,
	Policies: cedar.PoliciesFromCedar(`
permit(principal, action == Action::"view", resource)
when { resource.owner == principal || !resource.private };
forbid(principal, action, resource) unless { context.mfa };`),
	Entities: cedar.NewEntities(
		cedar.Entity{UID: alice},
		cedar.Entity{
			UID:   cedar.NewEntityUID("Photo", "beach"),
			Attrs: cedar.Record{"owner": alice, "private": cedar.Bool(true)},
		},
	),
})
if err != nil {
	return err // Cedar rejected the schema, the policies or the entities
}
defer a.Close()

resp, err := a.Authorize(ctx, cedar.Request{
	Principal: alice,
	Action:    cedar.NewEntityUID("Action", "view"),
	Resource:  cedar.NewEntityUID("Photo", "beach"),
	Context:   cedar.NewContext(cedar.Record{"mfa": cedar.Bool(true)}),
})
// resp.Decision is cedar.Allow, and resp.Reasons is [policy0].
// On any error, resp.Decision is cedar.Deny.
```

[`example_test.go`](example_test.go) and
[`analysis/example_test.go`](analysis/example_test.go) hold runnable
versions.

## API

Package `cedar`:

| Name | Purpose |
|---|---|
| `NewRuntime(ctx, opts...)` | Verifies the module's SHA-256 and imports, then compiles it. Create one per process. |
| `WithMemoryLimit`, `WithCompilationCache`, `WithMaxSourceBytes` | Runtime options |
| `Runtime.NewAuthorizer(ctx, Config)` | Loads a schema, policies and entities, and returns an `Authorizer` |
| `Authorizer.Authorize(ctx, Request)` | Evaluates one request. Safe for concurrent use. |
| `Runtime.Validate(ctx, Schema, PolicySet)` | Runs Cedar's strict validator |
| `SchemaFromCedar`, `SchemaFromJSON`, `PoliciesFromCedar`, `PoliciesFromJSON` | Source text in Cedar's two syntaxes |
| `NewEntities`, `EntitiesFromJSON`, `NewContext`, `ContextFromJSON` | Typed Go values or Cedar JSON |
| `Bool`, `Long`, `String`, `Set`, `Record`, `EntityUID`, `Decimal`, `IPAddr`, `Datetime`, `Duration` | Cedar values |
| `Response` | `Decision`, the policies that decided (`Reasons`), and the policies whose evaluation failed (`Errors`) |
| `*Error`, `ErrorKind`, `ErrFault` | Errors; see [Failure Behavior](#failure-behavior) |
| `Limits` | Per-authorizer limits: instances, call timeout, load timeout, request size, memory recycling |
| `CedarVersion`, `SymCCVersion`, `ModuleSHA256` | The embedded versions and the module hash |

Package `analysis`:

| Name | Purpose |
|---|---|
| `New(ctx, Solver, opts...)` | Verifies and compiles the analysis module |
| `Analyzer.NewlyPermitted(ctx, schema, before, after)` | Does `after` permit any request that `before` denies? |
| `Analyzer.Equivalent(ctx, schema, x, y)` | Do `x` and `y` decide every request the same way? |
| `Report`, `Result`, `Counterexample` | One result per request environment, with a concrete request when the property fails |
| `CVC5(path)`, `Command` | Run a solver executable that you provide |

The [Go reference](https://pkg.go.dev/github.com/ChrisMckerracher/cedar-go-wasm)
documents every name.

## Guarantees

**From Cedar upstream.** The module runs `cedar-policy` 4.13.0 unchanged.
Cedar's [Lean model](https://github.com/cedar-policy/cedar-spec/tree/main/cedar-lean)
proves properties such as "a satisfied `forbid` denies" and the soundness of
the typechecker. It also proves SymCC's encoding sound and complete.
Cedar's [differential tests](https://github.com/cedar-policy/cedar-spec/tree/main/cedar-drt)
fuzz the Rust authorizer, validator and SymCC against that model. Those
results cover the Rust code. They do not cover this repository's glue.

**From this repository.** The glue is about 630 lines of Rust and 1,240
lines of Go, without comments and tests. It moves JSON between Go and the
module, and it adds no authorization logic.
This repository checks it as follows:

- CI runs Cedar's [integration corpus](https://github.com/cedar-policy/cedar-integration-tests)
  through the Go API: 7,523 tests and 60,184 requests at commit `1999ea24`.
  It requires zero mismatches in decisions, reasons, error policy IDs and
  strict-validation results. The current result is zero of each.
- Tests prove that every fault returns Deny and discards the instance. The
  faults are memory exhaustion, timeout, cancellation, stack overflow, a
  corrupted instance, a wrong module hash and a forbidden import.
- Go fuzz targets drive requests, policies and entities across the boundary.
  They require that no input faults the module.
- `NewRuntime` and `analysis.New` check each embedded module's SHA-256 and
  its imports. CI rebuilds the modules from source and requires
  byte-identical output.
- The analysis module re-checks every counterexample with Cedar's concrete
  authorizer before it returns it.

**Not guaranteed.** Nothing formally verifies the glue, wazero, or the
solver. A property that holds rests on the solver's `unsat` answer. The
analysis module reads solver replies with its own code, about 90 lines. It
follows SymCC's `LocalSolver`, but Cedar's differential tests do not cover
it.

## Security Model

The module runs inside wazero's sandbox. It reaches the host only through
its imports. The host refuses to compile a module that imports anything
outside this list:

| Import | What the host provides | Why |
|---|---|---|
| `random_get` | `crypto/rand` | Seeds for Rust's hash maps, which resist hash flooding with random seeds |
| `environ_get`, `environ_sizes_get` | An empty environment | Rust's standard library asks at startup |
| `fd_write` | Discards stdout; keeps the first 4 KiB of stderr | Panic messages, which appear in fault errors |
| `proc_exit` | Ends the instance, which counts as a fault | Rust's abort path |
| `clock_time_get` (analysis only) | wazero's fake clock, not real time | tokio's runtime asks for the time |
| `poll_oneoff` (analysis only) | wazero's no-op sleep | tokio's runtime parks there; it never waits in practice |
| `cgw_host.solver_write`, `cgw_host.solver_read` (analysis only) | The solver process's stdin and stdout | SymCC's queries |

The module gets no files, no network, no real clock, no arguments and no
stdin.

Limits, all configurable:

| Limit | Default |
|---|---|
| Linear memory per instance | 256 MiB (analysis: 1 GiB) |
| Time the module may spend on one `Authorize` call | 1 s; the caller's context bounds the wait for an instance |
| Time to create and load one instance | 30 s |
| Encoded request, with context and entities | 1 MiB |
| Schema, policies and entities per load or validation | 64 MiB |
| Module response | 16 MiB |
| Memory an instance may keep between calls | 64 MiB; a larger instance is replaced |
| Instances per authorizer | `GOMAXPROCS` |
| Analysis call, solver included | 60 s |
| Solver output per analysis call | 256 MiB |

The module's 8 MiB stack sits below its data. A stack overflow traps; it
cannot overwrite memory.

The solver for change analysis runs as a separate process with an empty
environment. The process is killed when the call's context ends.

## Failure Behavior

| Condition | Decision | Error | Instance |
|---|---|---|---|
| Cedar rejects the input: a context, entity or request that does not match the schema, or a bad entity UID | Deny | `*Error` with the matching `Kind` | Kept: Cedar's state is read-only during a call |
| An input exceeds a size limit | Deny | `*Error`, `KindLimit` | Not used |
| The call exceeds its timeout | Deny | Matches `ErrFault` and `context.DeadlineExceeded` | Discarded |
| The caller's context ends | Deny | Wraps the context's error | Discarded if the call had started |
| The module traps or aborts: memory exhaustion, stack overflow, a Rust panic | Deny | Matches `ErrFault`, with the guest's stderr | Discarded |
| The module returns a malformed response | Deny | Matches `ErrFault` | Discarded |

`Deny` is the zero value of `Decision`, so a `Response` that a caller
forgets to fill also denies. The pool replaces a discarded instance on the
next call that needs one. `Authorizer.Stats` counts instances created and
discarded.

## Change Analysis

SymCC runs inside the analysis module. It compiles each question into
SMT-LIB queries, and the Go host passes them to a solver process. Neither
the module nor this repository includes a solver.

**Use cvc5 1.3.1.** Cedar tests SymCC with that version. Get it from the
[cvc5 release](https://github.com/cvc5/cvc5/releases/tag/cvc5-1.3.1) and
pass its path to `analysis.CVC5`. cvc5's default build links GMP, which is
licensed under the LGPL-3.0; that concerns your distribution, not this
module.

**Z3 does not work.** SymCC writes cvc5's finite-set operations, such as
`set.member`, `set.subset`, `set.inter` and `set.union`. Z3 5.1.0 rejects
them with `unknown constant set.member`. Z3 handles a policy set without
entity hierarchies or set operations, but every realistic set has those. We
measured this on 2026-10-01 with the joy policies in `testdata/joy`.

**No solver can run inside the module cleanly.** Z3 fails as described
above. cvc5 cannot build without GMP (LGPL-3.0) or CLN (GPL); its
`CMakeLists.txt` requires GMP 6.3. A cvc5 module would bundle LGPL code,
which this Apache-2.0 module does not ship. cvc5's official Wasm build
targets Emscripten and JavaScript, not WASI.

Results on the joy data set, with cvc5 1.3.1:

| Question | Result | Time |
|---|---|---|
| One added binding: does it permit anything new? | Yes, in 8 of 10 request environments, with counterexamples | 1.19 s |
| One raised device level: does it permit anything new? | No, in all 10 | 0.58 s |

Native SymCC with the same cvc5 took 0.79 s and 0.19 s for the same
questions.

SymCC needs a schema and strictly valid policies, and it rejects policy
templates. Counterexamples can hold extreme values, such as a `Long` of
2^63-1 or a datetime before 1970.

cedar-policy-symcc 0.7.0 does not build for wasm32-wasip1 as published. It
always enables tokio's `process` feature for `LocalSolver`. The 31-line
patch in `rust/patches` removes `LocalSolver` and the solver pool from wasm
targets, and changes nothing else. CI checks the vendored copy against the
crates.io release plus the patch.

## Performance

Measured on 2026-10-01 on an AMD Ryzen 5 5600X (6 cores, 12 threads),
Linux 6.19, Go 1.27.1, Rust 1.99.0 and wazero 1.12.0. The data set is
`testdata/joy`: 45 policies, 10 request types, and a context with
`datetime`, `ipaddr` and record values. Run `go test -bench . .` and
`cargo run --release -p cgw-native-bench` in `rust/` to reproduce.

| Measurement | Result |
|---|---|
| One decision, native `cedar-policy`, request already built | 49 µs |
| One decision, native, request and context parsed from JSON | 127 µs |
| One decision through `Authorize`, one instance | 1.22–1.24 ms |
| `Authorize` with 12 concurrent callers and 12 instances | 184–203 µs per decision, about 5,000 per second |
| `NewRuntime`, no compilation cache | 3.7 s |
| `NewRuntime`, warm disk cache (`wazero.NewCompilationCacheWithDir`) | 130 ms |
| `analysis.New`, no cache | 4.4 s |
| Load one instance: parse schema, policies and entities | 32 ms |
| Strict validation | 67 ms |
| Memory per loaded instance | 11.4 MB of Go heap, of which 9.6 MB is linear memory |
| `authorizer.wasm` | 5.47 MB; 1.51 MB with gzip |
| `analysis.wasm` | 6.33 MB; 1.75 MB with gzip |
| Stripped binary: hello world / with package `cedar` / with `analysis` too | 1.5 MB / 10.8 MB / 17.1 MB |

A decision through the Go API costs about ten times the native end-to-end
cost. Two factors cause it, measured on the same day:

- wazero's generated code runs Cedar 4 to 5 times slower than native. The
  same Rust code, run as a WASI command under the wazero CLI, took 210 µs
  per decision and 497 µs with JSON parsing.
- Timeouts double that. With `WithCloseOnContextDone`, wazero calls a check
  at every loop header so that it can stop a running call. The same command
  with the CLI's `-timeout` took 456 µs and 1,121 µs. `Authorize` without
  the checks took 571 µs in an experiment. This package keeps them on,
  because they are wazero's only way to stop a running call.

The Go side, JSON encoding and the pool, adds about 70 µs. Load and
validation are one-time costs per instance and per policy change. Use a
compilation cache directory to cut startup time.

## Known Differences from Native cedar-policy

- **Nesting depth.** The module parses up to 750 nested parentheses in a
  policy, and traps on 775, which denies. Native 4.13.0 on Linux's default
  8 MiB main-thread stack parses up to 550, and aborts the whole process on
  575.
- **Scope.** The API covers authorization with static policies and strict
  validation. It omits partial evaluation, policy templates, entity slicing
  and the formatter.
- **Policy IDs.** Cedar names policies `policy0`, `policy1` and so on, in
  source order. `@id` annotations do not change the IDs.
- **Request validation.** With a schema, Cedar always validates requests.
  The corpus never disables that.

## Versioning

Each release embeds exactly one Cedar version. Versions follow
`v0.MINOR.PATCH` until the API settles:

- A new Cedar version produces a new MINOR version.
- A fix to the glue, with the same Cedar version, produces a new PATCH
  version.
- v1.0.0 will mark a stable Go API. After it, a new Cedar version still
  produces a new MINOR version.

| Release | cedar-policy | cedar-policy-symcc | Corpus commit |
|---|---|---|---|
| v0.1.0 (planned) | 4.13.0 | 0.7.0 | `1999ea24` |

`cedar.CedarVersion` and `cedar.SymCCVersion` report the embedded versions.
A test checks them against `rust/Cargo.lock`. The module ABI has its own
version, which the host checks at instantiation.

## Reproducing the Build

The Go packages embed the modules, so users never build them. To check that
the committed modules come from this source:

```bash
rustup toolchain install   # Rust 1.99.0 and wasm32-wasip1, from rust-toolchain.toml
scripts/build-wasm.sh      # builds with --locked and rewrites internal/modules
git diff --exit-code -- internal/modules
```

The build is reproducible for four reasons:

- The toolchain is pinned.
- Cargo builds with `--locked`.
- Path remapping removes the checkout, `CARGO_HOME` and `RUSTUP_HOME` paths.
- LTO with one codegen unit fixes the code layout.

Two builds from different checkout paths and different `CARGO_HOME`
directories gave identical bytes. CI repeats the comparison on every push.

Releases publish both modules with SHA-256 sums and a build-provenance
attestation that GitHub signs through Sigstore. To verify a downloaded
module:

```bash
gh attestation verify authorizer.wasm --repo ChrisMckerracher/cedar-go-wasm
```

## Supply Chain

| Control | Where |
|---|---|
| Rust toolchain pinned to 1.99.0 | `rust-toolchain.toml` |
| `Cargo.lock` committed; every build uses `--locked` | `rust/` |
| Cedar crates pinned with `=` | `rust/Cargo.toml` |
| `cargo deny`: advisories, licenses, bans, sources | `rust/deny.toml`, CI |
| `cargo audit --deny warnings` | CI, weekly as well |
| `govulncheck` | CI |
| GitHub Actions pinned by commit SHA; only `actions/*` | `.github/workflows` |
| Corpus and cvc5 downloads pinned by SHA-256 | `.github/workflows` |
| Dependabot pull requests for Go modules, crates and Actions; no auto-merge | `.github/dependabot.yml` |
| Signed build provenance for releases | `.github/workflows/release.yml` |

The license allowlist is Apache-2.0, Apache-2.0 WITH LLVM-exception, MIT,
Unicode-3.0 and Zlib. Crates.io is the only allowed registry.
[THIRD_PARTY_LICENSES.txt](THIRD_PARTY_LICENSES.txt) lists every crate in
the modules with its license text, and CI checks it against the lockfile.

### Dependency Audit

The policy: every direct choice, meaning a dependency, a tool, a toolchain,
a binary or an Action, must come from an established organization or have
a solid star count. Transitive dependencies of an accepted choice are
accepted. The audit on 2026-10-01 covered every direct choice:

| Choice | Source | Basis |
|---|---|---|
| `cedar-policy`, `cedar-policy-core`, `cedar-policy-symcc` | crates.io, cedar-policy organization | Organization; the reference implementation |
| `serde`, `serde_json` | crates.io, serde-rs organization | Organization |
| `tokio` (the `rt` feature only) | crates.io, tokio-rs organization | Organization |
| `miette` | crates.io, zkat/miette | 2,612 stars; Cedar depends on it too |
| `github.com/tetratelabs/wazero` v1.12.0 | wazero organization | Organization |
| `github.com/jackc/puddle/v2` v2.2.2 | jackc/puddle | 421 stars; the connection pool of pgx (14,285 stars) |
| Rust 1.99.0 | rustup, static.rust-lang.org | Official distribution |
| Go 1.27.1 | go.dev/dl, checksum verified | Official distribution |
| cargo-deny 0.20.2, cargo-about 0.9.2 | crates.io, EmbarkStudios organization | Organization |
| cargo-audit 0.22.2 | crates.io, rustsec organization | Organization |
| govulncheck v1.8.0 | golang.org/x/vuln | Go team |
| wasm-tools 1.260.0 (inspection only) | crates.io, bytecodealliance organization | Organization |
| cvc5 1.3.1 (CI and tests only) | cvc5/cvc5 official release, checksum verified | Organization |
| Z3 5.1.0 (compatibility test only) | Z3Prover/z3 official release, checksum verified | Organization |
| `actions/checkout`, `setup-go`, `cache`, `upload-artifact`, `download-artifact`, `attest-build-provenance` | GitHub | Official |

Every downloaded archive matched the checksum that its project publishes.
All 168 crates.io packages in `rust/Cargo.lock` have more than 7 million
downloads. No dependency comes from a git repository.

## License

Apache License 2.0, the same as Cedar. See [LICENSE](LICENSE) and
[NOTICE](NOTICE).
