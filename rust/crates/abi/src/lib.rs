//! Operations consume host-allocated JSON input and transfer JSON response ownership
//! back to the host, which copies the bytes before calling `cgw_free`.

pub mod structured;

use cedar_policy::{PolicySet, Schema};
use serde::{Deserialize, Serialize};
use std::alloc::Layout;
use std::str::FromStr;

/// The host rejects a version mismatch before exchanging memory.
pub const ABI_VERSION: u32 = 1;

/// Allocates `len` bytes for the host. Returns 0 if the allocation fails.
pub fn alloc(len: u32) -> u32 {
    let Ok(layout) = Layout::array::<u8>(len.max(1) as usize) else {
        return 0;
    };
    // SAFETY: the layout has a non-zero size.
    unsafe { std::alloc::alloc(layout) as u32 }
}

/// Releases a buffer that `alloc` or `respond` returned.
///
/// # Safety
/// `ptr` and `len` must come from one `alloc` call or one response, and the
/// buffer must not be used after this call.
pub unsafe fn free(ptr: u32, len: u32) {
    if ptr == 0 {
        return;
    }
    if let Ok(layout) = Layout::array::<u8>(len.max(1) as usize) {
        // SAFETY: the caller guarantees that `ptr` came from `alloc` with this layout.
        unsafe { std::alloc::dealloc(ptr as *mut u8, layout) }
    }
}

/// Takes ownership of an input buffer that the host filled.
///
/// # Safety
/// `ptr` and `len` must come from one `alloc(len)` call, and the host must not
/// use the buffer after this call.
pub unsafe fn take_input(ptr: u32, len: u32) -> Input {
    Input { ptr, len }
}

/// An input buffer owned by the module. Dropping it releases the memory.
pub struct Input {
    ptr: u32,
    len: u32,
}

impl Input {
    pub fn bytes(&self) -> &[u8] {
        if self.len == 0 {
            return &[];
        }
        // SAFETY: `take_input` guarantees that the buffer holds `len` bytes.
        unsafe { std::slice::from_raw_parts(self.ptr as *const u8, self.len as usize) }
    }
}

impl Drop for Input {
    fn drop(&mut self) {
        // SAFETY: `take_input` guarantees that the buffer came from `alloc(len)`.
        unsafe { free(self.ptr, self.len) }
    }
}

/// Transfers ownership to the host: pointer in the high 32 bits, length in the low 32.
pub fn respond(body: Vec<u8>) -> u64 {
    let len = body.len() as u32;
    let ptr = alloc(len);
    if ptr == 0 {
        // The host treats a zero response as a fault and discards the instance.
        return 0;
    }
    // SAFETY: `ptr` points to `len` freshly allocated bytes.
    unsafe { std::ptr::copy_nonoverlapping(body.as_ptr(), ptr as *mut u8, body.len()) };
    (u64::from(ptr) << 32) | u64::from(len)
}

pub fn respond_json<T: Serialize>(value: &T) -> u64 {
    match serde_json::to_vec(value) {
        Ok(body) => respond(body),
        Err(e) => respond_error("internal", e.to_string()),
    }
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    kind: &'a str,
    message: String,
}

#[derive(Serialize)]
struct ErrorResponse<'a> {
    error: ErrorBody<'a>,
}

pub fn respond_error(kind: &str, message: String) -> u64 {
    let body = ErrorResponse {
        error: ErrorBody { kind, message },
    };
    // Serializing two strings cannot fail.
    respond(serde_json::to_vec(&body).unwrap_or_default())
}

#[derive(Debug)]
pub struct OpError {
    /// Machine-readable error kind, such as `schema` or `request`.
    pub kind: &'static str,
    pub message: String,
}

impl OpError {
    /// Retains related diagnostics and help text that `Display` alone omits.
    pub fn new(kind: &'static str, err: &(dyn diagnostics::Diagnostic + '_)) -> Self {
        Self {
            kind,
            message: diagnostics::render(err),
        }
    }

    pub fn msg(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

pub fn run<T: Serialize>(input: Input, op: impl FnOnce(&[u8]) -> Result<T, OpError>) -> u64 {
    let result = op(input.bytes());
    drop(input);
    match result {
        Ok(value) => respond_json(&value),
        Err(e) => respond_error(e.kind, e.message),
    }
}

pub fn parse_input<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, OpError> {
    serde_json::from_slice(bytes).map_err(|e| OpError::msg("input", e.to_string()))
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    /// Cedar's human-readable syntax.
    Cedar,
    Json,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub format: Format,
    pub text: String,
}

pub fn parse_schema(src: &Source) -> Result<Schema, OpError> {
    parse_schema_with_warnings(src).map(|(schema, _)| schema)
}

pub fn parse_schema_with_warnings(
    src: &Source,
) -> Result<(Schema, Vec<structured::Message>), OpError> {
    match src.format {
        Format::Cedar => Schema::from_cedarschema_str(&src.text)
            .map(|(schema, warnings)| {
                (
                    schema,
                    warnings.map(|w| structured::schema_warning(&w)).collect(),
                )
            })
            .map_err(|e| OpError::new("schema", &e)),
        Format::Json => Schema::from_json_str(&src.text)
            .map(|schema| (schema, Vec::new()))
            .map_err(|e| OpError::new("schema", &e)),
    }
}

pub fn parse_policies(src: &Source) -> Result<PolicySet, OpError> {
    match src.format {
        Format::Cedar => PolicySet::from_str(&src.text).map_err(|e| OpError::new("policies", &e)),
        Format::Json => {
            PolicySet::from_json_str(&src.text).map_err(|e| OpError::new("policies", &e))
        }
    }
}

pub mod diagnostics {
    pub use miette::Diagnostic;

    pub fn render(err: &(dyn Diagnostic + '_)) -> String {
        let mut out = err.to_string();
        if let Some(related) = err.related() {
            for r in related {
                let line = r.to_string();
                if !line.is_empty() && !out.contains(&line) {
                    out.push_str("; ");
                    out.push_str(&line);
                }
            }
        }
        if let Some(help) = err.help() {
            out.push_str(" (help: ");
            out.push_str(&help.to_string());
            out.push(')');
        }
        out
    }
}

#[macro_export]
macro_rules! export_memory_functions {
    () => {
        #[unsafe(no_mangle)]
        pub extern "C" fn cgw_abi_version() -> u32 {
            $crate::ABI_VERSION
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn cgw_alloc(len: u32) -> u32 {
            $crate::alloc(len)
        }

        /// Releases a response buffer.
        ///
        /// # Safety
        /// The host passes a pointer and length from one response.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cgw_free(ptr: u32, len: u32) {
            // SAFETY: the host passes a pointer and length from one response.
            unsafe { $crate::free(ptr, len) }
        }
    };
}
