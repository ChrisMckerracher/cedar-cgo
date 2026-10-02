use crate::{STATE, entity_uid};
use cedar_policy::{Context, Decision, Entities, Entity, EntityLoader, EntityUid, Request, Schema};
use cgw_abi::{OpError, parse_input, run, take_input};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::collections::{HashMap, HashSet};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    principal: serde_json::Value,
    action: serde_json::Value,
    resource: serde_json::Value,
    context: Option<Box<RawValue>>,
    entities: Option<Box<RawValue>>,
    max_iterations: u32,
    max_batch_bytes: usize,
}

#[derive(Serialize)]
struct Output {
    decision: &'static str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Batch {
    entities: Vec<Box<RawValue>>,
    missing: Vec<serde_json::Value>,
}

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "cgw_entity_loader")]
unsafe extern "C" {
    fn load(ptr: *const u8, len: u32) -> i32;
    fn read(ptr: *mut u8, len: u32) -> i32;
}

#[cfg(target_arch = "wasm32")]
fn exchange(bytes: &[u8], max_bytes: usize) -> Result<Vec<u8>, OpError> {
    // SAFETY: bytes remains live and immutable for the synchronous host import.
    let len = unsafe { load(bytes.as_ptr(), bytes.len() as u32) };
    if len <= 0 || len as usize > max_bytes {
        return Err(OpError::msg("loader", "invalid loader response size"));
    }
    let mut out = vec![0; len as usize];
    // SAFETY: out is a live allocation of exactly len bytes, exclusively owned here.
    if unsafe { read(out.as_mut_ptr(), len as u32) } != 0 {
        return Err(OpError::msg("loader", "entity loader read failed"));
    }
    Ok(out)
}

#[cfg(not(target_arch = "wasm32"))]
fn exchange(_: &[u8], _: usize) -> Result<Vec<u8>, OpError> {
    Err(OpError::msg("loader", "host imports require Wasm"))
}

struct Loader<'a> {
    schema: &'a Schema,
    cached: &'a Entities,
    max_bytes: usize,
    error: Option<OpError>,
}

impl Loader<'_> {
    fn batch(
        &self,
        uids: &HashSet<EntityUid>,
    ) -> Result<HashMap<EntityUid, Option<Entity>>, OpError> {
        let mut found = HashMap::new();
        let mut missing = Vec::new();
        for uid in uids {
            match self.cached.get(uid) {
                Some(entity) => {
                    found.insert(uid.clone(), Some(entity.clone()));
                }
                None => missing.push(uid),
            }
        }
        if missing.is_empty() {
            return Ok(found);
        }
        missing.sort_unstable();
        let bytes = serde_json::to_vec(
            &missing
                .iter()
                .map(|id| serde_json::json!({"type": id.type_name().to_string(), "id": id.id().unescaped()}))
                .collect::<Vec<_>>(),
        )
        .map_err(|e| OpError::msg("loader", e.to_string()))?;
        let batch: Batch = serde_json::from_slice(&exchange(&bytes, self.max_bytes)?)
            .map_err(|e| OpError::msg("entities", e.to_string()))?;
        for json in batch.entities {
            let entity = Entity::from_json_str(json.get(), Some(self.schema))
                .map_err(|e| OpError::new("entities", &e))?;
            if self.cached.get(&entity.uid()).is_some() {
                return Err(OpError::msg(
                    "entities",
                    "loader cannot redefine a cached entity",
                ));
            }
            if found.insert(entity.uid(), Some(entity)).is_some() {
                return Err(OpError::msg("entities", "duplicate loaded entity UID"));
            }
        }
        for json in batch.missing {
            let uid = entity_uid(json, "entities")?;
            if self.cached.get(&uid).is_some() {
                return Err(OpError::msg(
                    "entities",
                    "loader cannot mark a cached entity missing",
                ));
            }
            if found.insert(uid, None).is_some() {
                return Err(OpError::msg(
                    "entities",
                    "duplicate or conflicting missing UID",
                ));
            }
        }
        Ok(found)
    }
}

impl EntityLoader for Loader<'_> {
    fn load_entities(&mut self, uids: &HashSet<EntityUid>) -> HashMap<EntityUid, Option<Entity>> {
        if self.error.is_some() {
            return HashMap::new();
        }
        match self.batch(uids) {
            Ok(batch) => batch,
            Err(err) => {
                // Upstream's infallible trait requires latching failures until evaluation returns.
                self.error = Some(err);
                HashMap::new()
            }
        }
    }
}

fn authorize(bytes: &[u8]) -> Result<Output, OpError> {
    let input: Input = parse_input(bytes)?;
    if input.max_iterations > 1024 || !(1..=64 * 1024 * 1024).contains(&input.max_batch_bytes) {
        return Err(OpError::msg("input", "invalid batched work bounds"));
    }
    STATE.with(|s| {
        let state = s.borrow();
        let loaded = state
            .as_ref()
            .ok_or_else(|| OpError::msg("not_loaded", "no policy set is loaded"))?;
        let schema = loaded
            .schema
            .as_ref()
            .ok_or_else(|| OpError::msg("schema", "batched authorization requires a schema"))?;
        let principal = entity_uid(input.principal, "principal")?;
        let action = entity_uid(input.action, "action")?;
        let resource = entity_uid(input.resource, "resource")?;
        let context = Context::from_json_str(
            input.context.as_deref().map_or("{}", RawValue::get),
            Some((schema, &action)),
        )
        .map_err(|e| OpError::new("context", &e))?;
        let request = Request::new(principal, action, resource, context, Some(schema))
            .map_err(|e| OpError::new("request", &e))?;
        let extra;
        let cached = match input.entities.as_deref() {
            None => &loaded.entities,
            Some(json) => {
                extra = loaded
                    .entities
                    .clone()
                    .add_entities_from_json_str(json.get(), Some(schema))
                    .map_err(|e| OpError::new("entities", &e))?;
                &extra
            }
        };
        let mut loader = Loader {
            schema,
            cached,
            max_bytes: input.max_batch_bytes,
            error: None,
        };
        let result = loaded.policies.is_authorized_batched(
            &request,
            schema,
            &mut loader,
            input.max_iterations,
        );
        if let Some(err) = loader.error {
            return Err(err);
        }
        let decision = result.map_err(|e| OpError::msg("batched", e.to_string()))?;
        Ok(Output {
            decision: match decision {
                Decision::Allow => "allow",
                Decision::Deny => "deny",
            },
        })
    })
}

/// Authorizes with upstream type-aware evaluation and synchronous host entity loading.
///
/// # Safety
/// `ptr` and `len` must come from one `cgw_alloc(len)` call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cgw_authorize_batched(ptr: u32, len: u32) -> u64 {
    // SAFETY: the host passes a buffer from `cgw_alloc(len)`.
    run(unsafe { take_input(ptr, len) }, authorize)
}
