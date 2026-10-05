use cedar_policy::{Entity, EntityUid};
use cedar_policy_core::ast;
use cgw_abi::OpError;
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(super) fn canonical(value: &mut Value) {
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

pub(super) fn uid_value(uid: EntityUid) -> Value {
    json!({"type":uid.type_name().to_string(), "id":uid.id().unescaped()})
}

pub(super) fn entity_info(entity: &Entity) -> Result<Value, OpError> {
    let native: &ast::Entity = entity.as_ref();
    let mut parents: Vec<_> = native.parents().cloned().collect();
    let mut ancestors: Vec<_> = native.ancestors().cloned().collect();
    parents.sort();
    ancestors.sort();
    let attrs: BTreeMap<_, _> = entity
        .attrs()
        .map(|(name, value)| {
            value
                .map(|v| (name, crate::expressions::project(v)))
                .map_err(|e| OpError::new("entities", &e))
        })
        .collect::<Result<_, _>>()?;
    let tags: BTreeMap<_, _> = entity
        .tags()
        .map(|(name, value)| {
            value
                .map(|v| (name, crate::expressions::project(v)))
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
