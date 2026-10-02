//! Native 4.13.0 oracle: intentionally calls upstream APIs, never the guest wrapper.
use cedar_policy::{
    Authorizer, Context, Entities, Policy, PolicyId, PolicySet, Request, Schema, SlotId, Template,
    ValidationMode, Validator, pst,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

const SCHEMA: &str = "entity User; entity Photo { public: Bool }; action view appliesTo { principal: User, resource: Photo, context: { mfa: Bool } };";
const PERMIT: &str = "@owner(\"security\") permit(principal is User, action == Action::\"view\", resource is Photo) when { resource.public };";
const FORBID: &str = "forbid(principal, action, resource) unless { context.mfa };";

fn raw_id(id: &PolicyId) -> &str {
    AsRef::<str>::as_ref(id)
}

fn policy(id: &str, source: &str) -> Policy {
    Policy::parse(Some(PolicyId::new(id)), source).unwrap()
}

fn diagnostic(e: &(dyn cgw_abi::diagnostics::Diagnostic + '_)) -> String {
    cgw_abi::diagnostics::render(e)
}

fn snapshot(set: &PolicySet) -> Value {
    let schema = Schema::from_cedarschema_str(SCHEMA).unwrap().0;
    let validation = Validator::new(schema).validate(set, ValidationMode::Strict);
    let mut errors = validation
        .validation_errors()
        .map(|e| json!({"policy_id":raw_id(e.policy_id()),"message":diagnostic(e)}))
        .collect::<Vec<_>>();
    errors.sort_by_key(ToString::to_string);
    let mut warnings = validation
        .validation_warnings()
        .map(|e| json!({"policy_id":raw_id(e.policy_id()),"message":diagnostic(e)}))
        .collect::<Vec<_>>();
    warnings.sort_by_key(ToString::to_string);
    let entities = Entities::from_json_str(
        r#"[{"uid":{"type":"Photo","id":"p"},"attrs":{"public":true},"parents":[]}]"#,
        None,
    )
    .unwrap();
    let outcomes = [true,false].into_iter().map(|mfa| {
        let request = Request::new("User::\"alice\"".parse().unwrap(),"Action::\"view\"".parse().unwrap(),"Photo::\"p\"".parse().unwrap(),Context::from_json_str(&format!("{{\"mfa\":{mfa}}}"),None).unwrap(),None).unwrap();
        let response = Authorizer::new().is_authorized(&request,set,&entities);
        let mut reasons = response.diagnostics().reason().map(|id| raw_id(id).to_owned()).collect::<Vec<_>>(); reasons.sort();
        let mut errors = response.diagnostics().errors().map(|e| match e {
            cedar_policy::AuthorizationError::PolicyEvaluationError(pe) => json!({"policy_id": raw_id(pe.policy_id()), "message": diagnostic(pe.inner())}),
        }).collect::<Vec<_>>();
        errors.sort_by_key(ToString::to_string);
        json!({"mfa":mfa,"errors":errors,"decision":match response.decision() { cedar_policy::Decision::Allow => "allow", cedar_policy::Decision::Deny => "deny" },"reasons":reasons})
    }).collect::<Vec<_>>();
    json!({"json":set.clone().to_json().unwrap(),"passed":validation.validation_passed(),"errors":errors,"warnings":warnings,"outcomes":outcomes})
}

fn main() {
    let mut parses = Vec::new();
    for (id, src) in [
        ("explicit/id", PERMIT),
        (
            "expressions",
            r#"permit(principal in Group::"staff", action in [Action::"view"], resource is Photo in Album::"all") when { if context has nested.key then context.nested.key like "a*\*" else [1,2,3].contains(2) && {x: 1}["x"] >= -1 } unless { decimal("1.0").lessThan(decimal("0.0")) || ip("192.0.2.1").isLoopback() || datetime("2026-10-01T00:00:00Z").offset(duration("1h")) < datetime("2026-10-01T00:00:00Z") };"#,
        ),
        ("", FORBID),
        ("bad", "permit(principal, action, resource) when { 1 + };"),
        ("slot", "permit(principal == ?principal, action, resource);"),
        (
            "twice",
            "permit(principal,action,resource); forbid(principal,action,resource);",
        ),
        (
            "overflow",
            "permit(principal,action,resource) when { 9223372036854775808 == 0 };",
        ),
        (
            "annotation",
            "@owner(\"one\") @owner(\"two\") permit(principal,action,resource);",
        ),
        (
            "escapes\n雪",
            r#"@empty @text("quote\" and \n") permit(principal == User::"a\"\n雪", action in [], resource is Photo);"#,
        ),
    ] {
        let result = Policy::parse(Some(PolicyId::new(id)), src);
        parses.push(match result {
            Ok(p) => {
                let pst_policy = Policy::from_pst(p.to_pst().unwrap()).unwrap();
                let cedar = pst_policy.to_cedar().unwrap();
                let rendered = Policy::parse(Some(p.id().clone()), &cedar).unwrap();
                assert_eq!(pst_policy, rendered, "Cedar round trip changed policy {id}");
                json!({"id":id,"source":src,"json":p.to_json().unwrap(),"pst_json":pst_policy.to_json().unwrap(),"pst_cedar":cedar,"rendered_json":rendered.to_json().unwrap(),"error":null})
            },
            Err(e) => json!({"id":id,"source":src,"json":null,"error":diagnostic(&e)}),
        });
    }
    let base = PolicySet::from_policies([policy("allow-view", PERMIT)]).unwrap();
    let block = policy("require-mfa", FORBID);
    let unusual_id = "quote\"\nslash\\雪";
    let mut edits = Vec::new();
    for (name, add, remove, other, rename) in [
        ("add", Some(block.clone()), None, None, false),
        (
            "unusual-id",
            Some(policy(unusual_id, FORBID)),
            None,
            None,
            false,
        ),
        (
            "unusual-validation-id",
            Some(policy(
                unusual_id,
                "permit(principal,action,resource) when { resource.missing };",
            )),
            None,
            None,
            false,
        ),
        (
            "duplicate-add",
            Some(policy("allow-view", FORBID)),
            None,
            None,
            false,
        ),
        ("missing-remove", None, Some("absent"), None, false),
        ("remove", None, Some("allow-view"), None, false),
        (
            "merge",
            None,
            None,
            Some(PolicySet::from_policies([block.clone()]).unwrap()),
            false,
        ),
        ("merge-equal", None, None, Some(base.clone()), false),
        (
            "merge-conflict",
            None,
            None,
            Some(PolicySet::from_policies([policy("allow-view", FORBID)]).unwrap()),
            false,
        ),
        (
            "merge-rename",
            None,
            None,
            Some(PolicySet::from_policies([policy("allow-view", FORBID)]).unwrap()),
            true,
        ),
        (
            "invalid-validation",
            Some(policy(
                "bad-attribute",
                "permit(principal,action,resource) when { resource.missing };",
            )),
            None,
            None,
            false,
        ),
    ] {
        let mut set = base.clone();
        let mut renames = BTreeMap::new();
        let result = if let Some(p) = &add {
            set.add(p.clone())
        } else if let Some(id) = remove {
            set.remove_static(PolicyId::new(id)).map(|_| ())
        } else if let Some(other) = &other {
            set.merge(other, rename).map(|m| {
                renames = m
                    .into_iter()
                    .map(|(a, b)| (raw_id(&a).to_owned(), raw_id(&b).to_owned()))
                    .collect();
            })
        } else {
            Ok(())
        };
        edits.push(json!({"name":name,"base":base.clone().to_json().unwrap(),"add":add.as_ref().map(|p|json!({"id":raw_id(p.id()),"json":p.to_json().unwrap()})),"remove":remove,"other":other.map(|s|s.to_json().unwrap()),"rename":rename,"renames":renames,"error":result.err().map(|e|diagnostic(&e)),"result":snapshot(&set)}));
    }
    let unusual_base = PolicySet::from_policies([policy(unusual_id, PERMIT)]).unwrap();
    let unusual_other = PolicySet::from_policies([policy(unusual_id, FORBID)]).unwrap();
    let mut unusual_merged = unusual_base.clone();
    let unusual_renames = unusual_merged
        .merge(&unusual_other, true)
        .unwrap()
        .into_iter()
        .map(|(a, b)| (raw_id(&a).to_owned(), raw_id(&b).to_owned()))
        .collect::<BTreeMap<_, _>>();
    edits.push(json!({"name":"unusual-merge-id","base":unusual_base.to_json().unwrap(),"add":null,"remove":null,"other":unusual_other.to_json().unwrap(),"rename":true,"renames":unusual_renames,"error":null,"result":snapshot(&unusual_merged)}));
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
