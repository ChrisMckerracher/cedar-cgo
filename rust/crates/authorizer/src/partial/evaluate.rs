use super::residual::{
    CEDAR_VERSION, PartialOutput, RESIDUAL_VERSION, ResidualProjection, import_projection,
    summarize,
};
use super::{PartialInput, parse_partial_entities};
use crate::State;
use cgw_abi::{OpError, parse_input};
use serde::Deserialize;

pub(crate) fn partial_authorize(state: &State, bytes: &[u8]) -> Result<PartialOutput, OpError> {
    let input: PartialInput = parse_input(bytes)?;
    let loaded = state
        .loaded
        .as_ref()
        .ok_or_else(|| OpError::msg("not_loaded", "no policy set is loaded"))?;
    let schema = loaded
        .schema
        .as_ref()
        .ok_or_else(|| OpError::msg("schema", "partial evaluation requires a schema"))?;
    let entities = parse_partial_entities(input.entities.as_deref(), &loaded.entities, schema)?;
    let request = input.request(schema)?;
    let response = loaded
        .policies
        .tpe(&request, &entities, schema)
        .map_err(|e| OpError::new("policies", &e))?;
    summarize(&response)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportPartialInput {
    version: u32,
    cedar_version: String,
    partial: PartialInput,
    projection: ResidualProjection,
}

pub(crate) fn import_partial(state: &State, bytes: &[u8]) -> Result<PartialOutput, OpError> {
    let input: ImportPartialInput = parse_input(bytes)?;
    if input.version != RESIDUAL_VERSION || input.cedar_version != CEDAR_VERSION {
        return Err(OpError::msg(
            "input",
            "unsupported partial export or Cedar version",
        ));
    }
    let loaded = state
        .loaded
        .as_ref()
        .ok_or_else(|| OpError::msg("not_loaded", "no policy set is loaded"))?;
    let schema = loaded
        .schema
        .as_ref()
        .ok_or_else(|| OpError::msg("schema", "partial evaluation requires a schema"))?;
    let entities =
        parse_partial_entities(input.partial.entities.as_deref(), &loaded.entities, schema)?;
    let request = input.partial.request(schema)?;
    let response = loaded
        .policies
        .tpe(&request, &entities, schema)
        .map_err(|e| OpError::new("policies", &e))?;
    let output = summarize(&response)?;
    let imported = import_projection(&input.projection, &response)?;
    if imported.policies().count() != output.residuals.len() {
        return Err(OpError::msg(
            "input",
            "residual export does not match native partial evaluation",
        ));
    }
    Ok(output)
}
