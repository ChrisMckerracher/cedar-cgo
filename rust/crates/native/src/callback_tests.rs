use crate::*;
use std::sync::{Condvar, Mutex, mpsc};

const RESPONSE: &[u8] = br#"{"entities":[{"uid":{"type":"Photo","id":"one"},"attrs":{"public":true},"parents":[]}],"missing":[]}"#;
struct Loader {
    entered: mpsc::Sender<()>,
    released: (Mutex<bool>, Condvar),
}

unsafe extern "C" fn callback(id: usize, operation: u32, data: *mut u8, len: usize) -> isize {
    // SAFETY: the test keeps this call-local loader live until both scoped threads return.
    let loader = unsafe { &*(id as *const Loader) };
    match operation {
        1 => {
            loader.entered.send(()).unwrap();
            let (lock, wake) = &loader.released;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = wake.wait(released).unwrap();
            }
            RESPONSE.len() as isize
        }
        2 if len == RESPONSE.len() => {
            // SAFETY: Rust supplies a writable allocation of exactly the requested length.
            unsafe { std::ptr::copy_nonoverlapping(RESPONSE.as_ptr(), data, len) };
            0
        }
        _ => -1,
    }
}

#[test]
fn close_waits_for_active_callback_and_blocks_new_calls() {
    let handle = cgw_native_new(1);
    let load = br#"{"schema":{"format":"cedar","text":"entity User; entity Photo {public: Bool}; action view appliesTo {principal: User, resource: Photo, context: {}};"},"policies":{"format":"cedar","text":"permit(principal,action,resource) when {resource.public};"}}"#;
    // SAFETY: the input slices remain borrowed through this call.
    let result = unsafe {
        cgw_native_call(
            handle,
            b"load".as_ptr(),
            4,
            load.as_ptr(),
            load.len(),
            0,
            None,
            1000,
        )
    };
    assert_eq!(result.status, 0);
    cgw_native_free(result);
    let (entered, notified) = mpsc::channel();
    let loader = Loader {
        entered,
        released: (Mutex::new(false), Condvar::new()),
    };
    let id = &loader as *const Loader as usize;
    let (closed, observed) = mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let input = br#"{"principal":{"type":"User","id":"one"},"action":{"type":"Action","id":"view"},"resource":{"type":"Photo","id":"one"},"max_iterations":16,"max_batch_bytes":1000}"#;
            let operation = b"authorize_batched";
            // SAFETY: the callback, loader, and input remain live until this call returns.
            let result = unsafe { cgw_native_call(handle, operation.as_ptr(), operation.len(), input.as_ptr(), input.len(), id, Some(callback), 1000) };
            assert_eq!(result.status, 0);
            cgw_native_free(result);
        });
        notified.recv().unwrap();
        scope.spawn(move || closed.send(cgw_native_close(handle)).unwrap());
        while crate::entries::get(handle).is_some() {
            std::thread::yield_now();
        }
        assert!(matches!(
            observed.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        *loader.released.0.lock().unwrap() = true;
        loader.released.1.notify_all();
        assert_eq!(observed.recv().unwrap(), 0);
    });
}
