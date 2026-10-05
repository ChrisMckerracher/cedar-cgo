use cedar_policy::{Entities, Entity, EntityUid};
use cgw_abi::{OpError, Source, parse_input, parse_schema};
use serde::Deserialize;
use serde_json::{Value, json};
mod projection;
mod snapshot;
use projection::{entity_info, uid_value};
use snapshot::{Snapshot, restore, snapshot};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    operation: String,
    schema: Option<Source>,
    entities: Option<Value>,
    snapshot: Option<Snapshot>,
    other: Option<Snapshot>,
    uid: Option<Value>,
    ancestor: Option<Value>,
    remove: Option<Vec<Value>>,
}

fn parse_uid(uid: Option<Value>) -> Result<EntityUid, OpError> {
    EntityUid::from_json(uid.ok_or_else(|| OpError::msg("input", "missing entity UID"))?)
        .map_err(|e| OpError::new("entities", &e))
}

pub fn execute(bytes: &[u8]) -> Result<Value, OpError> {
    let input: Input = parse_input(bytes)?;
    if input.operation == "parse" {
        let schema = input.schema.as_ref().map(parse_schema).transpose()?;
        let entities = Entities::from_json_value(
            input
                .entities
                .ok_or_else(|| OpError::msg("input", "missing entities"))?,
            schema.as_ref(),
        )
        .map_err(|e| OpError::new("entities", &e))?;
        return snapshot(&entities, input.schema);
    }
    let (entities, source, schema) = restore(
        input
            .snapshot
            .ok_or_else(|| OpError::msg("input", "missing entity snapshot"))?,
    )?;
    match input.operation.as_str() {
        "get" => {
            let uid = parse_uid(input.uid)?;
            Ok(json!({"entity":entities.get(&uid).map(entity_info).transpose()?}))
        }
        "ancestors" => {
            let uid = parse_uid(input.uid)?;
            let ancestors = entities.ancestors(&uid).map(|ancestors| {
                let mut result: Vec<_> = ancestors.cloned().collect();
                result.sort();
                result.into_iter().map(uid_value).collect::<Vec<_>>()
            });
            Ok(json!({"ancestors":ancestors}))
        }
        "is_ancestor" => Ok(
            json!({"answer":entities.is_ancestor_of(&parse_uid(input.ancestor)?, &parse_uid(input.uid)?)}),
        ),
        "equal" => {
            let (other, _, _) = restore(
                input
                    .other
                    .ok_or_else(|| OpError::msg("input", "missing comparison snapshot"))?,
            )?;
            Ok(json!({"answer":entities.deep_eq(&other)}))
        }
        "remove" => {
            let remove = input
                .remove
                .ok_or_else(|| OpError::msg("input", "missing removal UIDs"))?
                .into_iter()
                .map(|uid| parse_uid(Some(uid)))
                .collect::<Result<Vec<_>, _>>()?;
            let changed = entities
                .remove_entities(remove)
                .map_err(|e| OpError::new("entities", &e))?;
            snapshot(&changed, source)
        }
        "upsert" => {
            let values: Vec<Value> = serde_json::from_value(
                input
                    .entities
                    .ok_or_else(|| OpError::msg("input", "missing upsert entities"))?,
            )
            .map_err(|e| OpError::msg("input", e.to_string()))?;
            let additions = values
                .into_iter()
                .map(|value| {
                    Entity::from_json_value(value, schema.as_ref())
                        .map_err(|e| OpError::new("entities", &e))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let changed = entities
                .upsert_entities(additions, schema.as_ref())
                .map_err(|e| OpError::new("entities", &e))?;
            snapshot(&changed, source)
        }
        _ => Err(OpError::msg("input", "unknown entity store operation")),
    }
}
