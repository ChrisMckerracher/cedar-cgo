# Security Policy

## Report a Vulnerability

Report vulnerabilities privately, through GitHub's private vulnerability
reporting: open the repository's **Security** tab and choose **Report a
vulnerability**. Do not open a public issue or pull request.

Include the version or commit, a minimal reproduction, and the impact you
expect. We confirm receipt within 5 working days.

## Scope

In scope:

- The Go packages, including the fail-closed handling, the limits and the
  WASI capability set that the README describes.
- The Rust glue in `rust/crates`, and the patch to cedar-policy-symcc in
  `rust/patches`.
- The build, release and provenance workflows.

A vulnerability in Cedar itself belongs to the Cedar project. Report it
through Cedar's process in
[cedar-policy/cedar SECURITY.md](https://github.com/cedar-policy/cedar/blob/main/SECURITY.md).
A vulnerability in wazero belongs to
[wazero](https://github.com/wazero/wazero/security). If you are not sure
where a problem lies, report it here and we will forward it.

## Supported Versions

Only the latest release receives fixes. Each release embeds one Cedar
version; a Cedar security release produces a new release here.
