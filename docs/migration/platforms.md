# Native platforms for Cedar Go consumers

Chris selected these targets on 2026-10-05.
The migration replaces the previous Windows and macOS amd64 support matrix with this explicit scope.

| Go platform | Rust target | CI build environment | Required compiler | Release gate |
|---|---|---|---|---|
| Linux amd64 | `x86_64-unknown-linux-gnu` | Ubuntu 22.04 | System GCC | Native reproduction and independent consumer |
| Linux arm64 | `aarch64-unknown-linux-gnu` | Ubuntu 24.04 ARM | System GCC | Native reproduction and independent consumer |
| macOS arm64 | `aarch64-apple-darwin` | macOS 15 ARM | Apple Clang | Native reproduction and independent consumer |

CI tests Go 1.26 and 1.27 on each target.
Each runner builds two independent archives and compares them byte for byte.
Consumer tests use the exact verified artifact for their target.
Each consumer executes concrete authorization and solver-backed analysis.

The Linux archives use the GNU C runtime.
The amd64 release environment provides glibc 2.35. The arm64 release environment provides glibc 2.39.
The release gate requires passing consumer checks in both environments.
The local VM uses a newer runtime. Local checks cannot establish either release minimum.

Executable inspection records system dependencies and symbol version requirements.
The native manifest records source, target, ABI, header, Cedar versions, Rust toolchain, and linker requirements.
The build uses the target's baseline CPU settings. It does not use `target-cpu=native`.

Musl and fully static consumer executables are outside this support matrix.
A Rust static library does not make the final Go executable fully static.
Linker requirements come from Rust's `--print=native-static-libs` output.
macOS requires the CoreFoundation framework. Verified linker source preserves its ordered framework and library flags.

A source build requires the pinned Rust toolchain and the supported C compiler.
A prebuilt source bundle requires cgo, Go, and the supported C compiler. It does not require Rust.
Analysis also requires an external solver. The verification solver is cvc5 1.3.1.
The solver remains a separate executable with its own license and platform requirements.

Official solver archives and hashes come from the [cvc5 1.3.1 release](https://github.com/cvc5/cvc5/releases/tag/cvc5-1.3.1).
