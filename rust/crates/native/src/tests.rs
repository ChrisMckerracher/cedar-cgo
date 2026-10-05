use crate::*;
use std::ptr::null;

fn call(handle: u64, operation: &str, input: &[u8], limit: usize) -> ResultRecord {
    // SAFETY: both input slices remain live through the call, and no callback is supplied.
    unsafe {
        cgw_native_call(
            handle,
            operation.as_ptr(),
            operation.len(),
            input.as_ptr(),
            input.len(),
            0,
            None,
            limit,
        )
    }
}

#[test]
fn handles_reject_zero_stale_and_wrong_kinds() {
    assert_eq!(cgw_native_new(0), 0);
    assert_eq!(call(0, "authorize", b"{}", 1000).status, 2);
    let authorizer = cgw_native_new(1);
    let result = call(authorizer, "analyze", b"{}", 1000);
    assert_eq!(result.status, 2);
    cgw_native_free(result);
    assert_eq!(cgw_native_close(authorizer), 0);
    assert_eq!(call(authorizer, "load", b"{}", 1000).status, 2);
    assert_eq!(cgw_native_close(authorizer), 2);
    let next = cgw_native_new(1);
    assert!(next > authorizer);
    assert_eq!(cgw_native_close(next), 0);
}

#[test]
fn response_buffers_use_native_lengths_and_safe_release() {
    let handle = cgw_native_new(1);
    let result = call(
        handle,
        "load",
        br#"{"policies":{"format":"cedar","text":"permit(principal,action,resource);"}}"#,
        1000,
    );
    assert_eq!(result.status, 0);
    // SAFETY: Rust owns the result allocation until the matching free call.
    assert_eq!(
        unsafe { std::slice::from_raw_parts(result.data, result.len) },
        br#"{"policies":1}"#
    );
    cgw_native_free(ResultRecord {
        len: result.len + 1,
        ..result
    });
    cgw_native_free(result);
    cgw_native_free(result);
    cgw_native_free(ResultRecord {
        status: 0,
        data: std::ptr::dangling_mut::<u8>(),
        len: 1,
    });
    assert_eq!(call(handle, "load", b"{}", 1).status, 4);
    // SAFETY: null buffers with nonzero lengths are rejected before reads.
    assert_eq!(
        unsafe { cgw_native_call(handle, null(), 1, null(), 0, 0, None, 1000) }.status,
        2
    );
    let result = call(handle, "load", &[0xff], 1000);
    assert_eq!(result.status, 1);
    cgw_native_free(result);
    cgw_native_close(handle);
}

#[test]
fn recovered_panic_invalidates_state_and_remains_closable() {
    const {
        assert!(cfg!(panic = "unwind"));
    }
    let handle = cgw_native_new(1);
    assert_eq!(call(handle, "__panic_test", b"{}", 1000).status, 3);
    assert_eq!(call(handle, "load", b"{}", 1000).status, 2);
    assert_eq!(cgw_native_close(handle), 0);
}

#[test]
fn native_state_moves_between_caller_threads() {
    let handle = cgw_native_new(1);
    let result = call(
        handle,
        "load",
        br#"{"policies":{"format":"cedar","text":"permit(principal,action,resource);"}}"#,
        1000,
    );
    assert_eq!(result.status, 0);
    cgw_native_free(result);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                let result = call(handle, "authorize", br#"{"principal":{"type":"User","id":"one"},"action":{"type":"Action","id":"view"},"resource":{"type":"Photo","id":"one"}}"#, 1000);
                assert_eq!(result.status, 0);
                // SAFETY: the matching allocation remains registered until free.
                let value: serde_json::Value = serde_json::from_slice(unsafe { std::slice::from_raw_parts(result.data, result.len) }).unwrap();
                assert_eq!(value["decision"], "allow");
                cgw_native_free(result);
            });
        }
    });
    cgw_native_close(handle);
}

#[test]
fn unified_analysis_dispatch_accepts_prefixed_and_plain_operations() {
    let handle = cgw_native_new(2);
    let input = br#"{"schema":{"format":"cedar","text":"entity User;"},"a":{"format":"cedar","text":""},"b":{"format":"cedar","text":""},"query":"equivalent"}"#;
    for operation in ["analyze", "cgw_analyze"] {
        let result = call(handle, operation, input, 1000);
        // SAFETY: the response allocation remains live until the following free call.
        assert_eq!(
            result.status,
            0,
            "{}",
            String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(result.data, result.len) })
        );
        cgw_native_free(result);
    }
    let result = call(
        handle,
        "cgw_compiled",
        br#"{"operation":"open","schema":{"format":"cedar","text":"entity User;"}}"#,
        1000,
    );
    assert_eq!(result.status, 0);
    cgw_native_free(result);
    assert_eq!(cgw_native_close(handle), 0);
}
