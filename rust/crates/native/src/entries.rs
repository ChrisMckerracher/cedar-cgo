use cgw_abi::{Callback, OpError};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

pub enum State {
    Authorizer(Box<cgw_authorizer::State>),
    Analysis(Box<cgw_analysis::State>),
}

pub struct Entry(pub Mutex<Option<State>>);

#[derive(Default)]
struct Registry {
    next: u64,
    entries: BTreeMap<u64, Arc<Entry>>,
}

static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();

fn registry() -> &'static Mutex<Registry> {
    REGISTRY.get_or_init(Default::default)
}

pub fn create(kind: u32) -> u64 {
    let state = match kind {
        1 => State::Authorizer(Default::default()),
        2 => State::Analysis(Default::default()),
        _ => return 0,
    };
    let mut registry = registry().lock().unwrap_or_else(|e| e.into_inner());
    let Some(handle) = registry.next.checked_add(1) else {
        return 0;
    };
    registry.next = handle;
    registry
        .entries
        .insert(handle, Arc::new(Entry(Mutex::new(Some(state)))));
    handle
}

pub fn get(handle: u64) -> Option<Arc<Entry>> {
    registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entries
        .get(&handle)
        .cloned()
}

pub fn close(handle: u64) -> u32 {
    let entry = registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entries
        .remove(&handle);
    let Some(entry) = entry else {
        return 2;
    };
    // Removing the identifier rejects new calls; this lock waits for active calls and callbacks.
    entry.0.lock().unwrap_or_else(|e| e.into_inner()).take();
    0
}

pub fn execute(
    state: &mut State,
    operation: &str,
    input: &[u8],
    callback: Callback,
) -> Result<Value, OpError> {
    #[cfg(test)]
    if operation == "__panic_test" {
        panic!("native panic conversion probe");
    }
    let operation = operation.strip_prefix("cgw_").unwrap_or(operation);
    match state {
        State::Authorizer(state) if !matches!(operation, "analyze" | "compiled") => {
            cgw_authorizer::execute(state, operation, input, callback)
        }
        State::Analysis(state) if matches!(operation, "analyze" | "compiled") => {
            cgw_analysis::execute(state, operation, input, callback)
        }
        _ => Err(OpError::msg(
            "handle",
            "operation requires a different native handle kind",
        )),
    }
}
