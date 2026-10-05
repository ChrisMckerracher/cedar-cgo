use super::policy_error;
use cedar_policy::{Policy, pst};
use cedar_policy_core::est;
use cgw_abi::OpError;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Syntax {
    pub(super) id: String,
    pub(super) effect: String,
    #[serde(default)]
    pub(super) annotations: BTreeMap<String, String>,
    pub(super) principal: Scope,
    pub(super) action: Action,
    pub(super) resource: Scope,
    #[serde(default)]
    pub(super) conditions: Vec<est::Clause>,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Scope {
    Any {},
    Eq { entity: Value },
    In { entity: Value },
    Is { entity_type: String },
    IsIn { entity_type: String, entity: Value },
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Action {
    Any {},
    Eq { entity: Value },
    In { entities: Vec<Value> },
}

impl Scope {
    fn est(self) -> Value {
        match self {
            Self::Any {} => json!({"op": "All"}),
            Self::Eq { entity } => json!({"op": "==", "entity": entity}),
            Self::In { entity } => json!({"op": "in", "entity": entity}),
            Self::Is { entity_type } => json!({"op": "is", "entity_type": entity_type}),
            Self::IsIn {
                entity_type,
                entity,
            } => json!({"op": "is", "entity_type": entity_type, "in": {"entity": entity}}),
        }
    }
}

impl Action {
    fn est(self) -> Value {
        match self {
            Self::Any {} => json!({"op": "All"}),
            Self::Eq { entity } => json!({"op": "==", "entity": entity}),
            Self::In { entities } => json!({"op": "in", "entities": entities}),
        }
    }
}

impl Syntax {
    pub(super) fn into_policy(self) -> Result<Policy, OpError> {
        let value = json!({
            "effect": self.effect,
            "annotations": self.annotations,
            "principal": self.principal.est(),
            "action": self.action.est(),
            "resource": self.resource.est(),
            "conditions": self.conditions,
        });
        let est: est::Policy =
            serde_json::from_value(value).map_err(|e| OpError::msg("policies", e.to_string()))?;
        let body = pst::Template::try_from(est)
            .map_err(|e| policy_error(&e))?
            .with_id(self.id.as_str().into());
        let policy = pst::StaticPolicy::try_from(body).map_err(|e| policy_error(&e))?;
        Policy::from_pst(policy.into()).map_err(|e| policy_error(&e))
    }
}

fn uid(uid: cedar_policy::EntityUid) -> Value {
    json!({"type": uid.type_name().to_string(), "id": uid.id().unescaped()})
}

pub(super) fn principal(p: &Policy) -> Scope {
    use cedar_policy::PrincipalConstraint as C;
    match p.principal_constraint() {
        C::Any => Scope::Any {},
        C::Eq(e) => Scope::Eq { entity: uid(e) },
        C::In(e) => Scope::In { entity: uid(e) },
        C::Is(t) => Scope::Is {
            entity_type: t.to_string(),
        },
        C::IsIn(t, e) => Scope::IsIn {
            entity_type: t.to_string(),
            entity: uid(e),
        },
    }
}

pub(super) fn resource(p: &Policy) -> Scope {
    use cedar_policy::ResourceConstraint as C;
    match p.resource_constraint() {
        C::Any => Scope::Any {},
        C::Eq(e) => Scope::Eq { entity: uid(e) },
        C::In(e) => Scope::In { entity: uid(e) },
        C::Is(t) => Scope::Is {
            entity_type: t.to_string(),
        },
        C::IsIn(t, e) => Scope::IsIn {
            entity_type: t.to_string(),
            entity: uid(e),
        },
    }
}

pub(super) fn action(p: &Policy) -> Action {
    use cedar_policy::ActionConstraint as C;
    match p.action_constraint() {
        C::Any => Action::Any {},
        C::Eq(e) => Action::Eq { entity: uid(e) },
        C::In(es) => Action::In {
            entities: es.into_iter().map(uid).collect(),
        },
    }
}
