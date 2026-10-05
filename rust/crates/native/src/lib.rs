//! Versioned C entry points keep ownership and unwinding inside Rust.

// The C interface promises panic conversion; aborting profiles cannot uphold that contract.
#[cfg(panic = "abort")]
compile_error!("cgw-native requires panic=unwind; build with --profile native");
mod buffers;
mod entries;
mod ffi;

pub use buffers::ResultRecord;
pub use ffi::*;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod callback_tests;
