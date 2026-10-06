use cedar_policy::{Authorizer, Entities, PolicySet, Schema};
use cgw_abi::{OpError, Source, parse_input, parse_policies, parse_schema};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::borrow::Cow;

pub(crate) struct Loaded {
    pub(crate) schema: Option<Schema>,
    pub(crate) policies: PolicySet,
    pub(crate) entities: Entities,
    pub(crate) authorizer: Authorizer,
}

#[derive(Default)]
pub struct State {
    pub(crate) loaded: Option<Loaded>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoadInput {
    pub(crate) schema: Option<Source>,
    policies: Source,
    entities: Option<Box<RawValue>>,
}

#[derive(Serialize)]
pub(crate) struct LoadOutput {
    policies: usize,
}

/// A schema also validates entity data and supplies action entities.
pub(crate) fn parse_entities(
    json: Option<&RawValue>,
    schema: Option<&Schema>,
) -> Result<Entities, OpError> {
    let text = json.map_or("[]", RawValue::get);
    Entities::from_json_str(text, schema).map_err(|e| OpError::new("entities", &e))
}

pub(crate) fn merged_entities<'a>(
    loaded: &'a Loaded,
    input: Option<&RawValue>,
) -> Result<Cow<'a, Entities>, OpError> {
    match input {
        None => Ok(Cow::Borrowed(&loaded.entities)),
        Some(json) => loaded
            .entities
            .clone()
            .add_entities_from_json_str(json.get(), loaded.schema.as_ref())
            .map(Cow::Owned)
            .map_err(|e| OpError::new("entities", &e)),
    }
}

pub(crate) fn load(state: &mut State, bytes: &[u8]) -> Result<LoadOutput, OpError> {
    let input: LoadInput = parse_input(bytes)?;
    let schema = input.schema.as_ref().map(parse_schema).transpose()?;
    let policies = parse_policies(&input.policies)?;
    let entities = parse_entities(input.entities.as_deref(), schema.as_ref())?;
    let out = LoadOutput {
        policies: policies.policies().count(),
    };
    state.loaded = Some(Loaded {
        schema,
        policies,
        entities,
        authorizer: Authorizer::new(),
    });
    Ok(out)
}
