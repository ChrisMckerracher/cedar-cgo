use cedar_policy::{EntityUid, PolicySet, Template};
use cedar_policy_core::{ast, est};
use cgw_abi::{OpError, Source, parse_input, parse_policies};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Replacement {
    from: Value,
    to: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    operation: String,
    policies: Source,
    replacements: Vec<Replacement>,
}

fn uid_value(uid: &EntityUid) -> Value {
    json!({"type":uid.type_name().to_string(), "id":uid.id().unescaped()})
}
fn sorted(mut literals: Vec<EntityUid>) -> Vec<Value> {
    literals.sort();
    literals.iter().map(uid_value).collect()
}

fn inventory(set: &PolicySet) -> Value {
    let policies: BTreeMap<_, _> = set
        .policies()
        .map(|p| (p.id().to_string(), sorted(p.entity_literals())))
        .collect();
    let templates: BTreeMap<_, _> = set
        .templates()
        .map(|t| {
            let ast: &ast::Template = t.as_ref();
            let literals = ast
                .condition()
                .subexpressions()
                .filter_map(|expr| match expr.expr_kind() {
                    ast::ExprKind::Lit(ast::Literal::EntityUID(uid)) => {
                        Some(EntityUid::from(uid.as_ref().clone()))
                    }
                    _ => None,
                })
                .collect();
            (t.id().to_string(), sorted(literals))
        })
        .collect();
    json!({"policies":policies,"templates":templates})
}

fn substitute(
    set: &PolicySet,
    mapping: &BTreeMap<EntityUid, EntityUid>,
) -> Result<PolicySet, OpError> {
    let mut result = PolicySet::new();
    for template in set.templates() {
        let est: est::Policy = serde_json::from_value(
            template
                .to_json()
                .map_err(|e| OpError::new("policies", &e))?,
        )
        .map_err(|e| OpError::msg("policies", e.to_string()))?;
        let native_mapping = mapping
            .iter()
            .map(|(from, to)| {
                (
                    ast::EntityUID::from(from.clone()),
                    ast::EntityUID::from(to.clone()),
                )
            })
            .collect();
        let est = est
            .sub_entity_literals(&native_mapping)
            .map_err(|e| OpError::new("policies", &e))?;
        let value =
            serde_json::to_value(est).map_err(|e| OpError::msg("policies", e.to_string()))?;
        let updated = Template::from_json(Some(template.id().clone()), value)
            .map_err(|e| OpError::new("policies", &e))?;
        result
            .add_template(updated)
            .map_err(|e| OpError::new("policies", &e))?;
    }
    for policy in set.policies() {
        if let Some(template_id) = policy.template_id() {
            let bindings = policy
                .template_links()
                .ok_or_else(|| OpError::msg("policies", "linked policy has no bindings"))?;
            let bindings = bindings
                .into_iter()
                .map(|(slot, uid)| {
                    let target = mapping.get(&uid).cloned().unwrap_or(uid);
                    (slot, target)
                })
                .collect();
            result
                .link(template_id.clone(), policy.id().clone(), bindings)
                .map_err(|e| OpError::new("policies", &e))?;
        } else {
            let updated = policy
                .sub_entity_literals(mapping.clone())
                .map_err(|e| OpError::new("policies", &e))?;
            result
                .add(updated)
                .map_err(|e| OpError::new("policies", &e))?;
        }
    }
    Ok(result)
}

pub fn execute(bytes: &[u8]) -> Result<Value, OpError> {
    let input: Input = parse_input(bytes)?;
    let policies = parse_policies(&input.policies)?;
    match input.operation.as_str() {
        "inspect" => Ok(json!({"inventory":inventory(&policies)})),
        "substitute" => {
            let mut mapping = BTreeMap::new();
            for entry in input.replacements {
                let from =
                    EntityUid::from_json(entry.from).map_err(|e| OpError::new("input", &e))?;
                let to = EntityUid::from_json(entry.to).map_err(|e| OpError::new("input", &e))?;
                if mapping.insert(from, to).is_some() {
                    return Err(OpError::msg(
                        "input",
                        "duplicate entity substitution source",
                    ));
                }
            }
            let result = substitute(&policies, &mapping)?;
            Ok(json!({"policies":result.to_json().map_err(|e| OpError::new("policies",&e))?}))
        }
        _ => Err(OpError::msg("input", "unknown entity literal operation")),
    }
}
