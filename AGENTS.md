# Working rules

Comments should explain rationale, invariants, or non-obvious contracts in one
line, usually two at most. Preserve directives, executable example output, and
Rust safety contracts; use longer explanations only when complexity requires it.

## README format

Use the README for the package overview, requirements, installation, a working example, limitations, and links to detailed documentation.
Chris rejected lesson headings, learning objectives, and knowledge checks in READMEs. Reserve lesson structure for requested primers and tutorials.

## Package structure

Treat directories approaching 12 Go files, including tests, as a design smell that requires a responsibility review.
File count is a review trigger, not a strict limit or a reason for mechanical splits.
Organize code into nested packages that explain domain responsibilities.
Keep each package's tests beside its implementation.
Split responsibilities rather than moving tests alone to reduce file counts.

## Responsibility, size, and readability

Give each file one responsibility. Apply the single responsibility principle: each module should have one reason to change.
Target 150 production lines per maintained code file.
Production code above this target requires a rare, necessary exception with a specific reason.
When a file grows, review its responsibilities before splitting it.
Prefer explicit names, direct control flow, and small interfaces that make ownership and behavior easy to read.
Do not compress code or combine unrelated responsibilities to meet a size target.

Tests may exceed 150 lines when they verify one coherent responsibility.
Split test files when their size or mixed responsibilities make them difficult to understand.
For Rust, count production code separately from inline test modules, including `#[cfg(test)]` modules.
Inline tests may increase the total Rust file length beyond 150 lines. Keep them beside the implementation they verify.

## Minimal custom implementation

Apply DRY: maintain each shared behavior in one place.
Compare contracts, ownership, limits, and errors before sharing similar implementations.
Prefer standard libraries and pinned upstream Rust APIs over custom implementations.
Check that a reused solution meets the required behavior and ownership contract.
Remove dead code and duplicated behavior before adding abstractions.
Keep custom adapters and public interfaces as small as practical.
Count custom work across Go, Rust, C, build scripts, and code generators.
Moving behavior between languages or adding forwarding layers does not reduce the maintenance burden.

## Dependency trust

Require broad production adoption or stewardship by an extremely well-trusted organization for other dependencies.
Record maintenance, production use, compatibility, licensing, and the custom code removed before proposing adoption.
GitHub stars support adoption evidence; stars, company ownership, and a stable version alone do not establish trust.
Check the specific library and API. An established organization can publish experimental or recent interfaces.
Keep dependency additions exceptional. Prefer existing upstream APIs before adding frameworks or generators.

Retain Puddle and Rapid as explicit existing exceptions.
Puddle supplies native resource ownership and is also used by pgx for connection pooling.
Rapid supplies structured generators, shrinking, and state-machine tests; preserve these capabilities.
These exceptions do not authorize other dependencies from the same maintainers.
Require an equivalent ownership or verification contract before replacing either dependency.
Obtain Chris's approval before installing new packages, dependencies, or maintainer tools.

## Verification preservation

Keep formal verification, property tests, fuzz targets, regression inputs, and independent parity checks during cleanup.
Preserve their assertions and scope when implementation or package paths change.
Keep independent verification separate from production adapter implementations.
Keep verification code separate from production reduction targets; a large verification corpus is acceptable.
Preserve ownership, cancellation, encoding, and failure checks when simplifying adapters.
Document verification changes and run the applicable checks. Fewer production lines must not mean less assurance.

## Publication gate

- Subagents may edit and validate, but must leave pushes and releases to the lead agent.
- Before any push, run every applicable locally runnable check from
  `.github/workflows/ci.yml` against the final candidate, including the exact
  repository-wide `gofmt` check. Use `set -euo pipefail` for combined commands.
- Require a successful exit from every check. A skipped check, missing tool, or
  masked failure is not a pass; report it and resolve it before pushing.
- Use existing tools and dependencies. Obtain Chris's approval before installing any.
- Verify remote CI succeeds for the exact published commit before tagging a release.
