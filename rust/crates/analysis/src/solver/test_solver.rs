use cgw_abi::Callback;
use std::collections::VecDeque;

#[derive(Default)]
struct Replies {
    enabled: bool,
    bytes: VecDeque<u8>,
}

#[derive(Default)]
pub(crate) struct TestSolver(Box<Replies>);

impl TestSolver {
    pub(crate) fn callback(&mut self) -> Callback {
        Callback {
            id: self.0.as_mut() as *mut Replies as usize,
            function: Some(invoke),
        }
    }
    pub(crate) fn enable(&mut self, enabled: bool) {
        self.0.enabled = enabled;
    }
}

// SAFETY: Tester owns Replies until synchronous analysis and every callback return.
unsafe extern "C" fn invoke(id: usize, operation: u32, ptr: *mut u8, len: usize) -> isize {
    // SAFETY: The callback ID refers to TestSolver's live, exclusively used Replies.
    let state = unsafe { &mut *(id as *mut Replies) };
    if !state.enabled {
        return -1;
    }
    // SAFETY: HostSolver supplies a live buffer of exactly len bytes.
    let data = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
    match operation {
        3 => {
            if data.windows(11).any(|part| part == b"(check-sat)") {
                state.bytes.extend(b"unsat\n");
            }
            0
        }
        4 => {
            let count = len.min(state.bytes.len());
            for byte in &mut data[..count] {
                *byte = state.bytes.pop_front().unwrap();
            }
            count as isize
        }
        _ => -1,
    }
}
