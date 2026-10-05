//! Request-specific whole-entity slices selected by Cedar's TPE loader.

use crate::{AuthorizeInput, entity_uid, parse_entities};
use cedar_policy::{Context, Decision, Entities, Entity, EntityLoader, EntityUid, Request};
use cgw_abi::{OpError, Source, parse_input, parse_policies, parse_schema};
use serde::{Deserialize, Serialize};
use serde_json::{Value, value::RawValue};
use std::collections::{HashMap, HashSet};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SliceInput {
    schema: Source,
    policies: Source,
    entities: Option<Box<RawValue>>,
    request: AuthorizeInput,
    max_iterations: u32,
}

#[derive(Serialize)]
pub(crate) struct SliceOutput {
    decision: &'static str,
    entities: Vec<Value>,
    batches: Vec<Vec<Value>>,
}

struct RecordingLoader<'a> {
    source: &'a Entities,
    loaded: HashSet<EntityUid>,
    batches: Vec<Vec<EntityUid>>,
}

impl EntityLoader for RecordingLoader<'_> {
    fn load_entities(&mut self, uids: &HashSet<EntityUid>) -> HashMap<EntityUid, Option<Entity>> {
        let mut batch: Vec<_> = uids.iter().cloned().collect();
        batch.sort();
        self.batches.push(batch);
        self.loaded.extend(uids.iter().cloned());
        // Parsing the complete source computed the ancestor closure required by EntityLoader.
        uids.iter()
            .map(|uid| (uid.clone(), self.source.get(uid).cloned()))
            .collect()
    }
}

pub(crate) fn slice(bytes: &[u8]) -> Result<SliceOutput, OpError> {
    let input: SliceInput = parse_input(bytes)?;
    let schema = parse_schema(&input.schema)?;
    let policies = parse_policies(&input.policies)?;
    let mut entities = parse_entities(input.entities.as_deref(), Some(&schema))?;
    if let Some(extra) = input.request.entities.as_deref() {
        entities = entities
            .add_entities_from_json_str(extra.get(), Some(&schema))
            .map_err(|e| OpError::new("entities", &e))?;
    }
    let principal = entity_uid(input.request.principal, "principal")?;
    let action = entity_uid(input.request.action, "action")?;
    let resource = entity_uid(input.request.resource, "resource")?;
    let context = Context::from_json_str(
        input.request.context.as_deref().map_or("{}", RawValue::get),
        Some((&schema, &action)),
    )
    .map_err(|e| OpError::new("context", &e))?;
    let request = Request::new(principal, action, resource, context, Some(&schema))
        .map_err(|e| OpError::new("request", &e))?;
    let mut loader = RecordingLoader {
        source: &entities,
        loaded: HashSet::new(),
        batches: Vec::new(),
    };
    let decision = policies
        .is_authorized_batched(&request, &schema, &mut loader, input.max_iterations)
        .map_err(|e| OpError::msg("slicing", e.to_string()))?;
    let mut loaded: Vec<_> = loader.loaded.into_iter().collect();
    loaded.sort();
    Ok(SliceOutput {
        decision: match decision {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
        },
        entities: loaded
            .iter()
            .filter_map(|uid| entities.get(uid))
            .map(|entity| {
                entity
                    .to_json_value()
                    .map_err(|e| OpError::new("entities", &e))
            })
            .collect::<Result<_, _>>()?,
        batches: loader
            .batches
            .into_iter()
            .map(|batch| {
                batch
                    .into_iter()
                    .map(|uid| {
                        uid.to_json_value()
                            .map_err(|e| OpError::new("entities", &e))
                    })
                    .collect::<Result<_, _>>()
            })
            .collect::<Result<_, _>>()?,
    })
}
