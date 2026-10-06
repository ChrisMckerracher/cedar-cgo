use cedar_policy::{Entities, EntityUid, Request};
use cedar_policy_core::ast::Context as CoreContext;
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
    let concrete = req
        .context()
        .filter(|context| {
            matches!(
                AsRef::<CoreContext>::as_ref(*context),
                CoreContext::Value(_)
            )
        })
        .ok_or_else(|| OpError::msg("internal", "counterexample context is not concrete"))?;
    let context = match concrete
        .to_json_value()
        .map_err(|e| OpError::new("internal", &e))?
    {
        serde_json::Value::Object(context) => context,
        _ => {
            return Err(OpError::msg(
                "internal",
                "counterexample context is not an object",
            ));
        }
    };
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

#[cfg(test)]
mod tests {
    use super::*;
    use cedar_policy::Context;

    #[test]
    fn public_context_projection_preserves_exact_nested_values() {
        let json = serde_json::json!({
            "max": i64::MAX, "min": i64::MIN,
            "nested": {"set": [1, 2], "entity": {"__entity": {"type": "User", "id": "alice"}}},
            "decimal": {"__extn": {"fn": "decimal", "arg": "1.25"}},
            "ip": {"__extn": {"fn": "ip", "arg": "192.0.2.1"}},
            "time": {"__extn": {"fn": "datetime", "arg": "2026-10-05T00:00:00Z"}},
        });
        let context = Context::from_json_value(json, None).unwrap();
        let request = Request::new(
            "User::\"alice\"".parse().unwrap(),
            "Action::\"read\"".parse().unwrap(),
            "Document::\"one\"".parse().unwrap(),
            context.clone(),
            None,
        )
        .unwrap();
        let serialized = serialize_request(&request).unwrap();
        assert_eq!(serialized.principal.id, "alice");
        assert_eq!(serialized.context["max"].as_i64(), Some(i64::MAX));
        assert_eq!(serialized.context["min"].as_i64(), Some(i64::MIN));
        assert_eq!(
            serde_json::Value::Object(serialized.context),
            context.to_json_value().unwrap()
        );
    }

    #[test]
    fn absent_context_does_not_project_as_an_empty_record() {
        use cedar_policy_core::ast::{EntityUIDEntry, Request as CoreRequest};
        let unknown = EntityUIDEntry::Unknown {
            ty: None,
            loc: None,
        };
        let request = CoreRequest::new_unchecked(unknown.clone(), unknown.clone(), unknown, None);
        let error = serialize_request(&request.into()).err().unwrap();
        assert_eq!(error.kind, "internal");
        assert_eq!(error.message, "counterexample context is not concrete");
    }
}
