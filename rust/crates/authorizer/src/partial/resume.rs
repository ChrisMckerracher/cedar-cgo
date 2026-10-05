use super::residual::{ResidualProjection, import_projection};
use super::{PartialInput, parse_partial_entities};
use crate::{AuthorizeInput, AuthorizeOutput, PolicyMessage, State, entity_uid};
use cedar_policy::{Context, Decision, Request};
use cgw_abi::{OpError, parse_input};
use serde::Deserialize;
use serde_json::value::RawValue;

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
    let context = Context::from_json_str(
        concrete.context.as_deref().map_or("{}", RawValue::get),
        Some((schema, &action)),
    )
    .map_err(|e| OpError::new("context", &e))?;
    let request = Request::new(
        entity_uid(concrete.principal, "principal")?,
        action,
        entity_uid(concrete.resource, "resource")?,
        context,
        Some(schema),
    )
    .map_err(|e| OpError::new("request", &e))?;
    let entities = match concrete.entities.as_deref() {
        Some(json) => loaded
            .entities
            .clone()
            .add_entities_from_json_str(json.get(), Some(schema))
            .map_err(|e| OpError::new("entities", &e))?,
        None => loaded.entities.clone(),
    };
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
    let mut reasons: Vec<_> = result
        .diagnostics()
        .reason()
        .map(|id| AsRef::<str>::as_ref(id).to_owned())
        .collect();
    reasons.sort_unstable();
    let mut errors: Vec<_> = result
        .diagnostics()
        .errors()
        .map(|e| match e {
            cedar_policy::AuthorizationError::PolicyEvaluationError(pe) => PolicyMessage {
                policy_id: AsRef::<str>::as_ref(pe.policy_id()).to_owned(),
                message: cgw_abi::diagnostics::render(pe.inner()),
            },
        })
        .collect();
    errors.sort_unstable_by(|a, b| a.policy_id.cmp(&b.policy_id));
    Ok(AuthorizeOutput {
        decision: match result.decision() {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
        },
        reasons,
        errors,
    })
}
