use cedar_policy::{Entities, Entity, EntityUid, Schema};
use cedar_policy_core::ast;
use cgw_abi::{Format, OpError, Source, parse_input, parse_schema};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u32,
    schema: Option<Source>,
    entities: Value,
}

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

fn canonical(value: &mut Value) {
    match value {
        Value::Array(values) => {
            values.iter_mut().for_each(canonical);
            values.sort_by_cached_key(Value::to_string);
        }
        Value::Object(values) => {
            values.values_mut().for_each(canonical);
            values.sort_keys();
        }
        _ => (),
    }
}

fn uid_value(uid: EntityUid) -> Value {
    json!({"type":uid.type_name().to_string(), "id":uid.id().unescaped()})
}

fn parse_uid(uid: Option<Value>) -> Result<EntityUid, OpError> {
    EntityUid::from_json(uid.ok_or_else(|| OpError::msg("input", "missing entity UID"))?)
        .map_err(|e| OpError::new("entities", &e))
}

fn restore(snapshot: Snapshot) -> Result<(Entities, Option<Source>, Option<Schema>), OpError> {
    if snapshot.version != 1 {
        return Err(OpError::msg("input", "unsupported entity snapshot version"));
    }
    let schema = snapshot.schema.as_ref().map(parse_schema).transpose()?;
    // The snapshot already contains schema actions; parsing must not restore deleted actions.
    let entities = Entities::from_json_value(snapshot.entities, None)
        .map_err(|e| OpError::new("entities", &e))?;
    Ok((entities, snapshot.schema, schema))
}

fn snapshot(entities: &Entities, schema: Option<Source>) -> Result<Value, OpError> {
    let mut normalized = entities
        .to_json_value()
        .map_err(|e| OpError::new("entities", &e))?;
    canonical(&mut normalized);
    let direct = entities
        .iter()
        .map(|entity| {
            let mut value = entity
                .to_json_value()
                .map_err(|e| OpError::new("entities", &e))?;
            let native: &ast::Entity = entity.as_ref();
            // Native JSON includes closure edges; snapshots need only direct parents for later mutation.
            value["parents"] = Value::Array(
                native
                    .parents()
                    .cloned()
                    .map(EntityUid::from)
                    .map(uid_value)
                    .collect(),
            );
            Ok(value)
        })
        .collect::<Result<Vec<_>, OpError>>()?;
    let mut direct = Value::Array(direct);
    canonical(&mut direct);
    let schema = schema.map(|source| json!({"format":match source.format { Format::Cedar => "cedar", Format::Json => "json" }, "text":source.text}));
    Ok(json!({"snapshot":{"version":1,"schema":schema,"entities":direct},"normalized":normalized}))
}

fn entity_info(entity: &Entity) -> Result<Value, OpError> {
    let native: &ast::Entity = entity.as_ref();
    let mut parents: Vec<_> = native.parents().cloned().collect();
    let mut ancestors: Vec<_> = native.ancestors().cloned().collect();
    parents.sort();
    ancestors.sort();
    let attrs: BTreeMap<_, _> = entity
        .attrs()
        .map(|(name, value)| {
            value
                .map(|v| (name, super::expressions::project(v)))
                .map_err(|e| OpError::new("entities", &e))
        })
        .collect::<Result<_, _>>()?;
    let tags: BTreeMap<_, _> = entity
        .tags()
        .map(|(name, value)| {
            value
                .map(|v| (name, super::expressions::project(v)))
                .map_err(|e| OpError::new("entities", &e))
        })
        .collect::<Result<_, _>>()?;
    let mut normalized = entity
        .to_json_value()
        .map_err(|e| OpError::new("entities", &e))?;
    canonical(&mut normalized);
    Ok(
        json!({"uid":uid_value(entity.uid()),"parents":parents.into_iter().map(EntityUid::from).map(uid_value).collect::<Vec<_>>(),"ancestors":ancestors.into_iter().map(EntityUid::from).map(uid_value).collect::<Vec<_>>(),"attrs":attrs,"tags":tags,"normalized":normalized}),
    )
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
