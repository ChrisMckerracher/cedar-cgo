use crate::{State, state::merged_entities};
use cedar_policy::{Context, Decision, EntityUid, Request, Response, Schema};
use cgw_abi::{OpError, parse_input};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthorizeInput {
    pub(crate) principal: serde_json::Value,
    pub(crate) action: serde_json::Value,
    pub(crate) resource: serde_json::Value,
    pub(crate) context: Option<Box<RawValue>>,
    pub(crate) entities: Option<Box<RawValue>>,
}

#[derive(Serialize)]
pub(crate) struct PolicyMessage {
    pub(crate) policy_id: String,
    pub(crate) message: String,
}

#[derive(Serialize)]
pub(crate) struct AuthorizeOutput {
    pub(crate) decision: &'static str,
    pub(crate) reasons: Vec<String>,
    pub(crate) errors: Vec<PolicyMessage>,
}

pub(crate) fn entity_uid(v: serde_json::Value, kind: &'static str) -> Result<EntityUid, OpError> {
    EntityUid::from_json(v).map_err(|e| OpError::new(kind, &e))
}

pub(crate) fn request_context(
    input: Option<&RawValue>,
    schema: Option<(&Schema, &EntityUid)>,
) -> Result<Context, OpError> {
    Context::from_json_str(input.map_or("{}", RawValue::get), schema)
        .map_err(|e| OpError::new("context", &e))
}

pub(crate) fn authorize(state: &State, bytes: &[u8]) -> Result<AuthorizeOutput, OpError> {
    let input: AuthorizeInput = parse_input(bytes)?;
    let loaded = state
        .loaded
        .as_ref()
        .ok_or_else(|| OpError::msg("not_loaded", "no policy set is loaded"))?;
    let schema = loaded.schema.as_ref();
    let principal = entity_uid(input.principal, "principal")?;
    let action = entity_uid(input.action, "action")?;
    let resource = entity_uid(input.resource, "resource")?;
    let context = request_context(input.context.as_deref(), schema.map(|s| (s, &action)))?;
    let request = Request::new(principal, action, resource, context, schema)
        .map_err(|e| OpError::new("request", &e))?;
    let entities = merged_entities(loaded, input.entities.as_deref())?;
    let response = loaded
        .authorizer
        .is_authorized(&request, &loaded.policies, &entities);
    Ok(AuthorizeOutput::from(response))
}

impl From<Response> for AuthorizeOutput {
    fn from(response: Response) -> Self {
        let diagnostics = response.diagnostics();
        let mut reasons: Vec<String> = diagnostics
            .reason()
            .map(|id| AsRef::<str>::as_ref(id).to_owned())
            .collect();
        reasons.sort_unstable();
        let mut errors: Vec<PolicyMessage> = diagnostics
            .errors()
            .map(|e| match e {
                cedar_policy::AuthorizationError::PolicyEvaluationError(pe) => PolicyMessage {
                    policy_id: AsRef::<str>::as_ref(pe.policy_id()).to_owned(),
                    message: cgw_abi::diagnostics::render(pe.inner()),
                },
            })
            .collect();
        errors.sort_unstable_by(|a, b| a.policy_id.cmp(&b.policy_id));
        Self {
            decision: match response.decision() {
                Decision::Allow => "allow",
                Decision::Deny => "deny",
            },
            reasons,
            errors,
        }
    }
}
