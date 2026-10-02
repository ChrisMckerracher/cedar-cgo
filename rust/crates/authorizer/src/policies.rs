use cedar_policy::{Policy, PolicyId, PolicySet, pst};
use cedar_policy_core::est;
use cgw_abi::{OpError, Source, parse_input, parse_policies};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn policy_error(e: &(dyn cgw_abi::diagnostics::Diagnostic + '_)) -> OpError {
    OpError::new("policies", e)
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Input {
    Parse {
        id: String,
        source: Source,
    },
    Construct {
        syntax: Box<Syntax>,
    },
    Inspect {
        set: Source,
    },
    Add {
        set: Source,
        id: String,
        policy: Value,
    },
    Remove {
        set: Source,
        id: String,
    },
    Merge {
        set: Source,
        other: Source,
        rename_duplicates: bool,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Syntax {
    id: String,
    effect: String,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
    principal: Scope,
    action: Action,
    resource: Scope,
    #[serde(default)]
    conditions: Vec<est::Clause>,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Scope {
    Any {},
    Eq { entity: Value },
    In { entity: Value },
    Is { entity_type: String },
    IsIn { entity_type: String, entity: Value },
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Action {
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
    fn into_policy(self) -> Result<Policy, OpError> {
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

fn principal(p: &Policy) -> Scope {
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

fn resource(p: &Policy) -> Scope {
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

fn action(p: &Policy) -> Action {
    use cedar_policy::ActionConstraint as C;
    match p.action_constraint() {
        C::Any => Action::Any {},
        C::Eq(e) => Action::Eq { entity: uid(e) },
        C::In(es) => Action::In {
            entities: es.into_iter().map(uid).collect(),
        },
    }
}

#[derive(Serialize)]
struct PolicyOutput {
    id: String,
    effect: String,
    annotations: BTreeMap<String, String>,
    principal: Scope,
    action: Action,
    resource: Scope,
    has_non_scope_constraint: bool,
    template_id: Option<String>,
    cedar: Option<String>,
    json: Value,
    syntax: Option<Syntax>,
}

fn policy_output(p: &Policy) -> Result<PolicyOutput, OpError> {
    let syntax = if p.is_static() {
        let tree = p.to_pst().map_err(|e| policy_error(&e))?;
        let conditions = tree
            .body()
            .clauses()
            .iter()
            .cloned()
            .map(est::Clause::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| policy_error(&e))?;
        Some(Syntax {
            id: AsRef::<str>::as_ref(p.id()).to_owned(),
            effect: p.effect().to_string(),
            annotations: p.annotations().map(|(k, v)| (k.into(), v.into())).collect(),
            principal: principal(p),
            action: action(p),
            resource: resource(p),
            conditions,
        })
    } else {
        None
    };
    Ok(PolicyOutput {
        id: AsRef::<str>::as_ref(p.id()).to_owned(),
        effect: p.effect().to_string(),
        annotations: p.annotations().map(|(k, v)| (k.into(), v.into())).collect(),
        principal: principal(p),
        action: action(p),
        resource: resource(p),
        has_non_scope_constraint: p.has_non_scope_constraint(),
        template_id: p
            .template_id()
            .map(|id| AsRef::<str>::as_ref(id).to_owned()),
        // Cedar text cannot preserve links, even when upstream renders a materialized body.
        cedar: if p.is_static() { p.to_cedar() } else { None },
        json: p.to_json().map_err(|e| policy_error(&e))?,
        syntax,
    })
}

#[derive(Serialize)]
struct SetOutput {
    json: Value,
    cedar: Option<String>,
    policies: Vec<PolicyOutput>,
}

fn set_output(set: PolicySet) -> Result<SetOutput, OpError> {
    let mut policies = set
        .policies()
        .map(policy_output)
        .collect::<Result<Vec<_>, _>>()?;
    policies.sort_by(|a, b| a.id.cmp(&b.id));
    // JSON-backed linked policies may render materialized bodies upstream; retain the link contract.
    let cedar = if policies.iter().any(|p| p.template_id.is_some()) {
        None
    } else {
        set.to_cedar()
    };
    Ok(SetOutput {
        json: set.to_json().map_err(|e| policy_error(&e))?,
        cedar,
        policies,
    })
}

#[derive(Serialize)]
pub(super) struct Output {
    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<PolicyOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    set: Option<SetOutput>,
    renames: BTreeMap<String, String>,
}

pub(super) fn execute(bytes: &[u8]) -> Result<Output, OpError> {
    let input: Input = parse_input(bytes)?;
    let mut out = Output {
        policy: None,
        set: None,
        renames: BTreeMap::new(),
    };
    match input {
        Input::Parse { id, source } => {
            let id = Some(PolicyId::new(id));
            let policy = match source.format {
                cgw_abi::Format::Cedar => {
                    Policy::parse(id, source.text).map_err(|e| policy_error(&e))?
                }
                cgw_abi::Format::Json => Policy::from_json(
                    id,
                    serde_json::from_str(&source.text)
                        .map_err(|e| OpError::msg("policies", e.to_string()))?,
                )
                .map_err(|e| policy_error(&e))?,
            };
            out.policy = Some(policy_output(&policy)?);
        }
        Input::Construct { syntax } => out.policy = Some(policy_output(&syntax.into_policy()?)?),
        Input::Inspect { set } => out.set = Some(set_output(parse_policies(&set)?)?),
        Input::Add { set, id, policy } => {
            let mut set = parse_policies(&set)?;
            set.add(
                Policy::from_json(Some(PolicyId::new(id)), policy).map_err(|e| policy_error(&e))?,
            )
            .map_err(|e| policy_error(&e))?;
            out.set = Some(set_output(set)?);
        }
        Input::Remove { set, id } => {
            let mut set = parse_policies(&set)?;
            set.remove_static(PolicyId::new(id))
                .map_err(|e| policy_error(&e))?;
            out.set = Some(set_output(set)?);
        }
        Input::Merge {
            set,
            other,
            rename_duplicates,
        } => {
            let mut set = parse_policies(&set)?;
            let renames = set
                .merge(&parse_policies(&other)?, rename_duplicates)
                .map_err(|e| policy_error(&e))?;
            out.renames = renames
                .into_iter()
                .map(|(k, v)| {
                    (
                        AsRef::<str>::as_ref(&k).to_owned(),
                        AsRef::<str>::as_ref(&v).to_owned(),
                    )
                })
                .collect();
            out.set = Some(set_output(set)?);
        }
    }
    Ok(out)
}
