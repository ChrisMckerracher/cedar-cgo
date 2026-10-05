//! Independent native cedar-policy oracle; deliberately does not call the guest operations.

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, PolicyId, PolicySet, Schema, SlotId,
    Template, ValidationMode, Validator,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::error::Error;

mod observations;
use observations::*;

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
