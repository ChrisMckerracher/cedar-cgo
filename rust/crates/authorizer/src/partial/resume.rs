use super::residual::{ResidualProjection, import_projection};
use super::{PartialInput, parse_partial_entities};
use crate::{
    AuthorizeInput, AuthorizeOutput, State, authorize::request_context, entity_uid,
    state::merged_entities,
};
use cedar_policy::Request;
use cgw_abi::{OpError, parse_input};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReauthorizeInput {
    partial: PartialInput,
    request: AuthorizeInput,
    projection: Option<ResidualProjection>,
}

pub(crate) fn reauthorize(state: &State, bytes: &[u8]) -> Result<AuthorizeOutput, OpError> {
    let input: ReauthorizeInput = parse_input(bytes)?;
    let loaded = state
        .loaded
        .as_ref()
        .ok_or_else(|| OpError::msg("not_loaded", "no policy set is loaded"))?;
    let schema = loaded
        .schema
        .as_ref()
        .ok_or_else(|| OpError::msg("schema", "partial evaluation requires a schema"))?;
    let partial_entities =
        parse_partial_entities(input.partial.entities.as_deref(), &loaded.entities, schema)?;
    let partial_request = input.partial.request(schema)?;
    let response = loaded
        .policies
        .tpe(&partial_request, &partial_entities, schema)
        .map_err(|e| OpError::new("policies", &e))?;
    let concrete = input.request;
    let action = entity_uid(concrete.action, "action")?;
    let context = request_context(concrete.context.as_deref(), Some((schema, &action)))?;
    let request = Request::new(
        entity_uid(concrete.principal, "principal")?,
        action,
        entity_uid(concrete.resource, "resource")?,
        context,
        Some(schema),
    )
    .map_err(|e| OpError::new("request", &e))?;
    let entities = merged_entities(loaded, concrete.entities.as_deref())?;
    // Native reauthorization enforces consistency with all previously known data.
    let checked = response
        .reauthorize(&request, &entities)
        .map_err(|e| OpError::msg("request", e.to_string()))?;
    let result = if let Some(imported) = input.projection {
        let policies = import_projection(&imported, &response)?;
        // Reuse the imported native PST only after Cedar checks the original known data.
        cedar_policy::Authorizer::new().is_authorized(&request, &policies, &entities)
    } else {
        checked
    };
    Ok(AuthorizeOutput::from(result))
}
