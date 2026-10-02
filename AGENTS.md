# Working rules

Comments should explain rationale, invariants, or non-obvious contracts in one
line, usually two at most. Preserve directives, executable example output, and
Rust safety contracts; use longer explanations only when complexity requires it.

## Publication gate

- Subagents may edit and validate, but must leave pushes and releases to the lead agent.
- Before any push, run every applicable locally runnable check from
  `.github/workflows/ci.yml` against the final candidate, including the exact
  repository-wide `gofmt` check. Use `set -euo pipefail` for combined commands.
- Require a successful exit from every check. A skipped check, missing tool, or
  masked failure is not a pass; report it and resolve it before pushing.
- Use existing tools and dependencies. Obtain Chris's approval before installing any.
- Verify remote CI succeeds for the exact published commit before tagging a release.
