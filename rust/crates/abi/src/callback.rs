/// Callback input and output buffers remain borrowed for one synchronous invocation.
pub type CallbackFn = unsafe extern "C" fn(usize, u32, *mut u8, usize) -> isize;

#[derive(Clone, Copy, Default)]
pub struct Callback {
    pub id: usize,
    pub function: Option<CallbackFn>,
}

impl Callback {
    /// The foreign caller keeps the identifier and function valid until the native call returns.
    pub fn call(self, operation: u32, bytes: &mut [u8]) -> isize {
        let Some(function) = self.function else {
            return -1;
        };
        // SAFETY: native entry borrows a valid callback for this call; bytes owns the writable buffer.
        unsafe { function(self.id, operation, bytes.as_mut_ptr(), bytes.len()) }
    }
}
