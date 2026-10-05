use super::*;

pub(super) const TEMPLATE: &str = "@description(\"shared access\") permit(principal == ?principal, action == Action::\"view\", resource == ?resource);";
pub(super) const SCHEMA: &str = "entity User; entity Photo; action view appliesTo { principal: User, resource: Photo, context: {} };";

pub(super) fn id(s: &str) -> PolicyId {
    PolicyId::new(s)
}
pub(super) fn uid(s: &str) -> EntityUid {
    s.parse().unwrap()
}
pub(super) fn bindings() -> HashMap<SlotId, EntityUid> {
    HashMap::from([
        (SlotId::principal(), uid("User::\"alice\"")),
        (SlotId::resource(), uid("Photo::\"beach\"")),
    ])
}
pub(super) fn binding_json(bindings: &HashMap<SlotId, EntityUid>) -> Value {
    Value::Object(
        bindings
            .iter()
            .map(|(s, u)| {
                (
                    s.to_string(),
                    json!({"type": u.type_name().to_string(), "id": u.id().unescaped()}),
                )
            })
            .collect(),
    )
}
pub(super) fn base(linked: bool) -> PolicySet {
    let mut set: PolicySet = "forbid(principal, action, resource) when { false };"
        .parse()
        .unwrap();
    set.add_template(Template::parse(Some(id("share")), TEMPLATE).unwrap())
        .unwrap();
    if linked {
        set.link(id("share"), id("alice-access"), bindings())
            .unwrap();
    }
    set
}

pub(super) fn case(
    name: &str,
    mut set: PolicySet,
    operation: Value,
    edit: impl FnOnce(&mut PolicySet) -> Result<(), Box<cedar_policy::PolicySetError>>,
) -> Value {
    let before = set.clone().to_json().unwrap();
    let result = edit(&mut set);
    let expected = match result {
        Err(e) => json!({"error": native_error(&e)}),
        Ok(()) => {
            let schema = Schema::from_cedarschema_str(SCHEMA).unwrap().0;
            let validation = Validator::new(schema.clone()).validate(&set, ValidationMode::Strict);
            let valid = validation.validation_passed();
            let mut errors: Vec<_> = validation
                .validation_errors()
                .map(|e| {
                    serde_json::to_value(cgw_abi::structured::validation_error(e).without_spans())
                        .unwrap()
                })
                .collect();
            let mut warnings: Vec<_> = validation
                .validation_warnings()
                .map(|e| {
                    serde_json::to_value(cgw_abi::structured::validation_warning(e).without_spans())
                        .unwrap()
                })
                .collect();
            errors.sort_by_key(Value::to_string);
            warnings.sort_by_key(Value::to_string);
            let req = cedar_policy::Request::new(
                uid("User::\"alice\""),
                uid("Action::\"view\""),
                uid("Photo::\"beach\""),
                Context::empty(),
                Some(&schema),
            )
            .unwrap();
            let response = Authorizer::new().is_authorized(&req, &set, &Entities::empty());
            let mut reasons: Vec<_> = response
                .diagnostics()
                .reason()
                .map(|id| AsRef::<str>::as_ref(id).to_owned())
                .collect();
            reasons.sort_unstable();
            json!({"policies": set.to_json().unwrap(), "decision": match response.decision() { Decision::Allow => "allow", Decision::Deny => "deny" }, "reasons": reasons, "valid": valid, "errors":errors, "warnings":warnings})
        }
    };
    json!({"name": name, "policies": before, "operation": operation, "expected": expected})
}

pub(super) fn canonicalize(set: &mut Value) {
    set.sort_all_objects();
    if let Some(links) = set.get_mut("templateLinks").and_then(Value::as_array_mut) {
        links.sort_by_key(Value::to_string);
    }
}

pub(super) fn native_error(error: &cedar_policy::PolicySetError) -> String {
    let mut message = cgw_abi::diagnostics::render(error);
    let mut source = error.source();
    while let Some(cause) = source {
        let detail = cause.to_string();
        if !detail.is_empty() && !message.contains(&detail) {
            message.push_str("; ");
            message.push_str(&detail);
        }
        source = cause.source();
    }
    message
}
