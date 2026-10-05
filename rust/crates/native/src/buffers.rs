use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ResultRecord {
    pub status: u32,
    pub data: *mut u8,
    pub len: usize,
}

static BUFFERS: OnceLock<Mutex<BTreeMap<usize, Box<[u8]>>>> = OnceLock::new();

impl ResultRecord {
    pub const fn empty(status: u32) -> Self {
        Self {
            status,
            data: std::ptr::null_mut(),
            len: 0,
        }
    }

    pub fn new(status: u32, body: Vec<u8>, max_response: usize) -> Self {
        if body.len() > max_response {
            return Self::empty(4);
        }
        let mut body = body.into_boxed_slice();
        if body.is_empty() {
            return Self::empty(status);
        }
        let result = Self {
            status,
            data: body.as_mut_ptr(),
            len: body.len(),
        };
        BUFFERS
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(result.data as usize, body);
        result
    }

    pub fn release(self) {
        let Some(buffers) = BUFFERS.get() else {
            return;
        };
        let mut buffers = buffers.lock().unwrap_or_else(|e| e.into_inner());
        // Reject foreign pointers and altered lengths before releasing a registered allocation.
        if buffers
            .get(&(self.data as usize))
            .is_some_and(|body| body.len() == self.len)
        {
            buffers.remove(&(self.data as usize));
        }
    }
}
