use crate::{ResultRecord, entries};
use cgw_abi::{Callback, CallbackFn};
use std::panic::{AssertUnwindSafe, catch_unwind};

fn contain<T>(f: impl FnOnce() -> T, fallback: impl FnOnce() -> T) -> T {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(value) => value,
        Err(payload) => {
            // Panic payloads can have throwing destructors; they must not unwind into C.
            std::mem::forget(payload);
            fallback()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn cgw_native_abi_version() -> u32 {
    contain(|| cgw_abi::ABI_VERSION, || 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn cgw_native_new(kind: u32) -> u64 {
    contain(|| entries::create(kind), || 0)
}

unsafe fn borrowed<'a>(data: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if data.is_null() || len > isize::MAX as usize {
        return None;
    }
    // SAFETY: the C caller supplies a readable allocation for this synchronous call.
    Some(unsafe { std::slice::from_raw_parts(data, len) })
}

fn call(
    handle: u64,
    operation: &[u8],
    input: &[u8],
    callback: Callback,
    max_response: usize,
) -> ResultRecord {
    let Some(entry) = entries::get(handle) else {
        return ResultRecord::empty(2);
    };
    let Ok(operation) = std::str::from_utf8(operation) else {
        return ResultRecord::empty(2);
    };
    let mut guard = entry.0.lock().unwrap_or_else(|e| e.into_inner());
    let Some(state) = guard.as_mut() else {
        return ResultRecord::empty(2);
    };
    let result = catch_unwind(AssertUnwindSafe(|| {
        let (status, value) = match entries::execute(state, operation, input, callback) {
            Ok(value) => (0, value),
            Err(error) => (
                if matches!(error.kind, "handle" | "operation") {
                    2
                } else {
                    1
                },
                serde_json::json!({"error":{"kind":error.kind,"message":error.message}}),
            ),
        };
        let body = serde_json::to_vec(&value).unwrap_or_else(|_| {
            b"{\"error\":{\"kind\":\"internal\",\"message\":\"JSON serialization failed\"}}"
                .to_vec()
        });
        ResultRecord::new(status, body, max_response)
    }));
    match result {
        Ok(result) => result,
        Err(payload) => {
            std::mem::forget(payload);
            // Remove failed state before dropping it, even if cleanup also panics.
            let failed = guard.take();
            contain(|| drop(failed), || ());
            ResultRecord::empty(3)
        }
    }
}

/// Input buffers and the callback remain valid until this synchronous function returns.
///
/// # Safety
/// Nonempty buffers must point to readable allocations of their stated lengths.
/// The callback must obey its borrowed buffer contract and must not unwind.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cgw_native_call(
    handle: u64,
    operation: *const u8,
    operation_len: usize,
    input: *const u8,
    input_len: usize,
    callback_id: usize,
    callback: Option<CallbackFn>,
    max_response: usize,
) -> ResultRecord {
    contain(
        || {
            // SAFETY: the C caller borrows both buffers for this synchronous call.
            let (Some(operation), Some(input)) =
                (unsafe { borrowed(operation, operation_len) }, unsafe {
                    borrowed(input, input_len)
                })
            else {
                return ResultRecord::empty(2);
            };
            call(
                handle,
                operation,
                input,
                Callback {
                    id: callback_id,
                    function: callback,
                },
                max_response,
            )
        },
        || ResultRecord::empty(3),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn cgw_native_close(handle: u64) -> u32 {
    contain(|| entries::close(handle), || 3)
}

#[unsafe(no_mangle)]
pub extern "C" fn cgw_native_free(result: ResultRecord) {
    contain(|| result.release(), || ());
}
