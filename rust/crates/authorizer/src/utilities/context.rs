use cedar_policy::Context;
use cgw_abi::{OpError, Source, parse_input, parse_schema};
use serde::Deserialize;
use serde_json::{Value, json, value::RawValue};
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct Operation {
    operation: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextValuesInput {
    #[serde(rename = "operation")]
    _operation: String,
    context: Box<RawValue>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextGetInput {
    #[serde(rename = "operation")]
    _operation: String,
    context: Box<RawValue>,
    key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextMergeInput {
    #[serde(rename = "operation")]
    _operation: String,
    context: Box<RawValue>,
    other: Box<RawValue>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextValidateInput {
    #[serde(rename = "operation")]
    _operation: String,
    context: Box<RawValue>,
    schema: Source,
    action: Value,
}

fn context(raw: &RawValue) -> Result<Context, OpError> {
    Context::from_json_str(raw.get(), None).map_err(|e| OpError::new("context", &e))
}

pub(crate) fn execute(bytes: &[u8]) -> Result<Value, OpError> {
    // Tagged enum buffering cannot retain RawValue; decode context structs from the original bytes.
    let operation: Operation = parse_input(bytes)?;
    match operation.operation.as_str() {
        "context_values" => {
            let input: ContextValuesInput = parse_input(bytes)?;
            let context = context(&input.context)?;
            let values = context
                .clone()
                .into_iter()
                .map(|(key, _)| {
                    let value = context.get(&key).ok_or_else(|| {
                        OpError::msg("context", "context attribute is not concrete")
                    })?;
                    Ok((key, crate::expressions::project(value)))
                })
                .collect::<Result<BTreeMap<_, _>, OpError>>()?;
            Ok(json!({"values": values}))
        }
        "context_get" => {
            let input: ContextGetInput = parse_input(bytes)?;
            let value = context(&input.context)?
                .get(&input.key)
                .map(crate::expressions::project);
            Ok(json!({"found": value.is_some(), "value": value}))
        }
        "context_merge" => {
            let input: ContextMergeInput = parse_input(bytes)?;
            let merged = context(&input.context)?
                .merge(context(&input.other)?)
                .map_err(|e| OpError::new("context", &e))?;
            let json = merged
                .to_json_value()
                .map_err(|e| OpError::new("context", &e))?;
            Ok(json!({"context": json}))
        }
        "context_validate" => {
            let input: ContextValidateInput = parse_input(bytes)?;
            context(&input.context)?
                .validate(
                    &parse_schema(&input.schema)?,
                    &crate::entity_uid(input.action, "entity_uid")?,
                )
                .map_err(|e| OpError::new("context", &e))?;
            Ok(json!({"valid": true}))
        }
        _ => super::execute_other(bytes),
    }
}
