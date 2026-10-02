//! Independent native cedar-policy oracle; deliberately does not call the guest operations.

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, PolicyId, PolicySet, Schema, SlotId,
    Template, ValidationMode, Validator,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::error::Error;

const TEMPLATE: &str = "@description(\"shared access\") permit(principal == ?principal, action == Action::\"view\", resource == ?resource);";
const SCHEMA: &str = "entity User; entity Photo; action view appliesTo { principal: User, resource: Photo, context: {} };";

fn id(s: &str) -> PolicyId {
    PolicyId::new(s)
}
fn uid(s: &str) -> EntityUid {
    s.parse().unwrap()
}
fn bindings() -> HashMap<SlotId, EntityUid> {
    HashMap::from([
        (SlotId::principal(), uid("User::\"alice\"")),
        (SlotId::resource(), uid("Photo::\"beach\"")),
    ])
}
fn binding_json(bindings: &HashMap<SlotId, EntityUid>) -> Value {
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
fn base(linked: bool) -> PolicySet {
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

fn case(
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
            let mut errors: Vec<_> = validation.validation_errors().map(|e| json!({"policy_id":AsRef::<str>::as_ref(e.policy_id()), "message":cgw_abi::diagnostics::render(e)})).collect();
            let mut warnings: Vec<_> = validation.validation_warnings().map(|e| json!({"policy_id":AsRef::<str>::as_ref(e.policy_id()), "message":cgw_abi::diagnostics::render(e)})).collect();
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

fn main() -> Result<(), Box<dyn Error>> {
    let mut cases = Vec::new();
    for (name, template, policy, values) in [
        ("valid link", "share", "alice-access", bindings()),
        (
            "missing one binding",
            "share",
            "new",
            HashMap::from([(SlotId::principal(), uid("User::\"alice\""))]),
        ),
        ("missing all bindings", "share", "new", HashMap::new()),
        ("duplicate template id", "share", "share", bindings()),
        ("duplicate static id", "share", "policy0", bindings()),
        ("missing template", "absent", "new", bindings()),
        ("link static policy", "policy0", "new", bindings()),
    ] {
        cases.push(case(name, base(false), json!({"op":"link", "template_id":template, "policy_id":policy,"bindings":binding_json(&values)}), |s| s.link(id(template), id(policy), values).map_err(Box::new)));
    }
    cases.push(case("duplicate linked id", base(true), json!({"op":"link","template_id":"share","policy_id":"alice-access","bindings":binding_json(&bindings())}), |s| s.link(id("share"), id("alice-access"), bindings()).map_err(Box::new)));
    let mut single = PolicySet::new();
    single.add_template(Template::parse(
        Some(id("share")),
        "permit(principal == ?principal, action, resource);",
    )?)?;
    cases.push(case("extra resource binding", single, json!({"op":"link","template_id":"share","policy_id":"new","bindings":binding_json(&bindings())}), |s| s.link(id("share"), id("new"), bindings()).map_err(Box::new)));
    let mut wrong_type = bindings();
    wrong_type.insert(SlotId::principal(), uid("Photo::\"alice\""));
    cases.push(case("inapplicable link warns but passes validation", base(false), json!({"op":"link","template_id":"share","policy_id":"new","bindings":binding_json(&wrong_type)}), |s| s.link(id("share"), id("new"), wrong_type).map_err(Box::new)));
    let mut unknown_type = bindings();
    unknown_type.insert(SlotId::principal(), uid("Uzer::\"alice\""));
    cases.push(case("link succeeds but strict validation fails", base(false), json!({"op":"link","template_id":"share","policy_id":"new","bindings":binding_json(&unknown_type)}), |s| s.link(id("share"), id("new"), unknown_type).map_err(Box::new)));
    for (name, policy) in [
        ("unlink", "alice-access"),
        ("unlink missing", "absent"),
        ("unlink static", "policy0"),
        ("unlink template", "share"),
    ] {
        cases.push(case(
            name,
            base(true),
            json!({"op":"unlink","policy_id":policy}),
            |s| s.unlink(id(policy)).map(|_| ()).map_err(Box::new),
        ));
    }
    for (name, linked, template) in [
        ("remove", false, "share"),
        ("remove active template", true, "share"),
        ("remove missing", false, "absent"),
        ("remove static", false, "policy0"),
        ("remove linked policy", true, "alice-access"),
    ] {
        cases.push(case(
            name,
            base(linked),
            json!({"op":"remove","template_id":template}),
            |s| {
                s.remove_template(id(template))
                    .map(|_| ())
                    .map_err(Box::new)
            },
        ));
    }
    for (name, template) in [
        ("add template", "new"),
        ("add duplicate template", "share"),
        ("add duplicate static", "policy0"),
        ("add duplicate link", "alice-access"),
    ] {
        cases.push(case(
            name,
            base(true),
            json!({"op":"add","id":template,"template":TEMPLATE}),
            |s| {
                s.add_template(Template::parse(Some(id(template)), TEMPLATE).unwrap())
                    .map_err(Box::new)
            },
        ));
    }
    let mut escaped = PolicySet::new();
    let template_id = "share\\\"\n\0雪";
    let policy_id = "link\\\"\n\0雪";
    escaped.add_template(Template::parse(Some(id(template_id)), TEMPLATE)?)?;
    cases.push(case("escaped template and linked IDs", escaped.clone(), json!({"op":"link", "template_id":template_id, "policy_id":policy_id,"bindings":binding_json(&bindings())}), |s| s.link(id(template_id), id(policy_id), bindings()).map_err(Box::new)));
    let mut values = bindings();
    values.insert(SlotId::principal(), uid("Uzer::\"alice\""));
    cases.push(case("escaped ID in validation diagnostics", escaped, json!({"op":"link", "template_id":template_id, "policy_id":policy_id,"bindings":binding_json(&values)}), |s| s.link(id(template_id), id(policy_id), values).map_err(Box::new)));
    // Canonicalize unordered EST link arrays so regeneration is byte-for-byte reproducible.
    for case in &mut cases {
        canonicalize(&mut case["policies"]);
        if let Some(policies) = case["expected"].get_mut("policies") {
            canonicalize(policies);
        }
    }
    let mut fixtures = json!({"cedar_version":"4.13.0", "schema":SCHEMA, "cases":cases});
    fixtures.sort_all_objects();
    println!("{}", serde_json::to_string_pretty(&fixtures)?);
    Ok(())
}

fn canonicalize(set: &mut Value) {
    set.sort_all_objects();
    if let Some(links) = set.get_mut("templateLinks").and_then(Value::as_array_mut) {
        links.sort_by_key(Value::to_string);
    }
}

fn native_error(error: &cedar_policy::PolicySetError) -> String {
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
