use super::projection::{canonical, uid_value};
use cedar_policy::{Entities, EntityUid, Schema};
use cedar_policy_core::ast;
use cgw_abi::{Format, OpError, Source, parse_schema};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Snapshot {
    version: u32,
    schema: Option<Source>,
    entities: Value,
}

pub(super) fn restore(
    snapshot: Snapshot,
) -> Result<(Entities, Option<Source>, Option<Schema>), OpError> {
    if snapshot.version != 1 {
        return Err(OpError::msg("input", "unsupported entity snapshot version"));
    }
    let schema = snapshot.schema.as_ref().map(parse_schema).transpose()?;
    // The snapshot already contains schema actions; parsing must not restore deleted actions.
    let entities = Entities::from_json_value(snapshot.entities, None)
        .map_err(|e| OpError::new("entities", &e))?;
    Ok((entities, snapshot.schema, schema))
}

pub(super) fn snapshot(entities: &Entities, schema: Option<Source>) -> Result<Value, OpError> {
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
