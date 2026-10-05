//! Native 4.13.0 oracle: intentionally calls upstream APIs, never the guest wrapper.
use cedar_policy::{
    Authorizer, Context, Entities, Policy, PolicyId, PolicySet, Request, Schema, SlotId, Template,
    ValidationMode, Validator, pst,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

mod edit;
mod observations;
mod parse;
use observations::*;

fn main() {
    let parses = parse::cases();
    let (base, edits) = edit::cases();
    let mut linked = base.clone();
    linked
        .add_template(
            Template::parse(
                Some(PolicyId::new("template")),
                "permit(principal == ?principal,action,resource);",
            )
            .unwrap(),
        )
        .unwrap();
    linked
        .link(
            PolicyId::new("template"),
            PolicyId::new("instance"),
            HashMap::from([(SlotId::principal(), "User::\"alice\"".parse().unwrap())]),
        )
        .unwrap();
    let linked_remove_error = diagnostic(
        &linked
            .clone()
            .remove_static(PolicyId::new("instance"))
            .unwrap_err(),
    );
    let template_remove_error = diagnostic(
        &linked
            .clone()
            .remove_static(PolicyId::new("template"))
            .unwrap_err(),
    );

    let tree = pst::Template::new(
        "constructed",
        pst::Effect::Permit,
        pst::PrincipalConstraint::Is(pst::EntityType::from_name(
            pst::Name::unqualified("User").unwrap(),
        )),
        pst::ActionConstraint::Any,
        pst::ResourceConstraint::Any,
    )
    .with_annotations(BTreeMap::from([("origin".into(), "pst".into())]))
    .try_with_clauses([
        pst::Clause::When(Arc::new(pst::Expr::Literal(pst::Literal::Bool(true)))),
        pst::Clause::Unless(Arc::new(pst::Expr::Literal(pst::Literal::Bool(false)))),
    ])
    .unwrap();
    let constructed = Policy::from_pst(pst::StaticPolicy::try_from(tree).unwrap().into()).unwrap();
    let syntax = json!({"id":"constructed","effect":"permit","annotations":{"origin":"pst"},"principal":{"kind":"is","entity_type":"User"},"action":{"kind":"any"},"resource":{"kind":"any"},"conditions":[{"kind":"when","body":{"Value":true}},{"kind":"unless","body":{"Value":false}}]});
    let rendering_source = "@b permit(principal,action,resource);\n@a forbid(principal,action,resource);\npermit(principal == ?principal,action,resource);";
    let rendered: PolicySet = rendering_source.parse().unwrap();
    let mut fixture = json!({"version":"4.13.0","schema":SCHEMA,"parses":parses,"edits":edits,"linked":{"json":linked.clone().to_json().unwrap(),"remove_error":linked_remove_error,"template_remove_error":template_remove_error,"result":snapshot(&linked)},"constructed":{"syntax":syntax,"json":constructed.to_json().unwrap(),"result":snapshot(&PolicySet::from_policies([constructed]).unwrap())},"rendering":{"source":rendering_source,"cedar":rendered.to_cedar().unwrap()}});
    fixture.sort_all_objects();
    println!("{}", serde_json::to_string_pretty(&fixture).unwrap());
}
