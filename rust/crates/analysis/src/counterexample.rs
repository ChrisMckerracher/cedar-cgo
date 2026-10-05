use cedar_policy::{Entities, EntityUid, Request};
use cedar_policy_core::ast::Context as CoreContext;
use cedar_policy_core::entities::json::CedarValueJson;
use cgw_abi::OpError;
use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct Uid {
    #[serde(rename = "type")]
    pub(crate) type_name: String,
    pub(crate) id: String,
}

impl From<&EntityUid> for Uid {
    fn from(uid: &EntityUid) -> Self {
        Self {
            type_name: uid.type_name().to_string(),
            id: uid.id().unescaped().to_string(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct CexRequest {
    pub(crate) principal: Uid,
    pub(crate) action: Uid,
    pub(crate) resource: Uid,
    pub(crate) context: serde_json::Map<String, serde_json::Value>,
}

#[derive(Serialize)]
pub(crate) struct Counterexample {
    pub(crate) request: CexRequest,
    pub(crate) entities: serde_json::Value,
    pub(crate) text: String,
    pub(crate) a_decision: &'static str,
    pub(crate) b_decision: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) a_evaluation: Option<PolicyEvaluation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) b_evaluation: Option<PolicyEvaluation>,
}

#[derive(Serialize)]
pub(crate) struct EvaluationError {
    pub(crate) policy_id: String,
    pub(crate) message: String,
}

#[derive(Serialize)]
pub(crate) struct PolicyEvaluation {
    pub(crate) matched: bool,
    pub(crate) errors: Vec<EvaluationError>,
}

#[derive(Serialize)]
pub(crate) struct EnvResult {
    pub(crate) principal_type: String,
    pub(crate) action: Uid,
    pub(crate) resource_type: String,
    pub(crate) holds: bool,
    pub(crate) counterexample: Option<Counterexample>,
}

#[derive(Serialize)]
pub(crate) struct AnalyzeOutput {
    pub(crate) results: Vec<EnvResult>,
}

fn request_part(uid: Option<&EntityUid>, what: &str) -> Result<Uid, OpError> {
    uid.map(Uid::from)
        .ok_or_else(|| OpError::msg("internal", format!("counterexample has no {what}")))
}

pub(crate) fn serialize_request(req: &Request) -> Result<CexRequest, OpError> {
    let mut context = serde_json::Map::new();
    match req.context().map(AsRef::<CoreContext>::as_ref) {
        Some(CoreContext::Value(attrs)) => {
            for (k, v) in attrs.iter() {
                let json = CedarValueJson::from_value(v.clone())
                    .map_err(|e| OpError::new("internal", &e))?;
                let json = serde_json::to_value(json)
                    .map_err(|e| OpError::msg("internal", e.to_string()))?;
                context.insert(k.to_string(), json);
            }
        }
        _ => {
            return Err(OpError::msg(
                "internal",
                "counterexample context is not concrete",
            ));
        }
    }
    Ok(CexRequest {
        principal: request_part(req.principal(), "principal")?,
        action: request_part(req.action(), "action")?,
        resource: request_part(req.resource(), "resource")?,
        context,
    })
}

pub(crate) fn serialize_entities(entities: &Entities) -> Result<serde_json::Value, OpError> {
    entities
        .to_json_value()
        .map_err(|e| OpError::new("internal", &e))
}
