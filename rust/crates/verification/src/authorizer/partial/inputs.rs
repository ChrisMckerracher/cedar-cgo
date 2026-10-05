use super::*;

pub(super) fn uid(v: &Value) -> Result<EntityUid> {
    Ok(EntityUid::from_json(v.clone())?)
}

pub(super) fn partial_uid(v: &Value) -> Result<PartialEntityUid> {
    Ok(PartialEntityUid::new(
        v["type"].as_str().ok_or("missing type")?.parse()?,
        v["id"].as_str().map(EntityId::new),
    ))
}

pub(super) fn response_json(response: &cedar_policy::Response) -> Value {
    let mut reasons: Vec<_> = response
        .diagnostics()
        .reason()
        .map(|id| AsRef::<str>::as_ref(id).to_owned())
        .collect();
    reasons.sort();
    let mut errors: Vec<_> = response
        .diagnostics()
        .errors()
        .map(|e| match e {
            cedar_policy::AuthorizationError::PolicyEvaluationError(e) => {
                AsRef::<str>::as_ref(e.policy_id()).to_owned()
            }
        })
        .collect();
    errors.sort();
    json!({"decision": decision(response.decision()), "reasons": reasons, "error_policies": errors})
}

pub(super) fn decision(d: Decision) -> &'static str {
    match d {
        Decision::Allow => "allow",
        Decision::Deny => "deny",
    }
}

pub(super) fn completion(
    v: &Value,
    schema: &Schema,
    loaded: &Entities,
) -> Result<(Request, Entities)> {
    let action = uid(&v["action"])?;
    let context = Context::from_json_value(v["context"].clone(), Some((schema, &action)))?;
    let request = Request::new(
        uid(&v["principal"])?,
        action,
        uid(&v["resource"])?,
        context,
        Some(schema),
    )?;
    let entities = loaded
        .clone()
        .add_entities_from_json_value(v["entities"].clone(), Some(schema))?;
    Ok((request, entities))
}
