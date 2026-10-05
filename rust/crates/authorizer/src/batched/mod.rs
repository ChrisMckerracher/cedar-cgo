use crate::{State, entity_uid};
use cedar_policy::{Context, Decision, Request};
use cgw_abi::{Callback, OpError, parse_input};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
mod loader;
use loader::Loader;

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
pub(crate) struct Output {
    decision: &'static str,
}

pub(crate) fn authorize(
    state: &State,
    bytes: &[u8],
    callback: Callback,
) -> Result<Output, OpError> {
    let input: Input = parse_input(bytes)?;
    if input.max_iterations > 1024 || !(1..=64 * 1024 * 1024).contains(&input.max_batch_bytes) {
        return Err(OpError::msg("input", "invalid batched work bounds"));
    }
    let loaded = state
        .loaded
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
        callback,
        error: None,
    };
    let result =
        loaded
            .policies
            .is_authorized_batched(&request, schema, &mut loader, input.max_iterations);
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
}
