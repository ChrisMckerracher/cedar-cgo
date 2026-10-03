//! Direct native Cedar oracle for entity-literal inspection and simultaneous substitution.
use cedar_policy::{EntityUid, PolicyId, PolicySet, SlotId, Template};
use cedar_policy_core::{ast, est};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{self, Read};

fn refs(set: &PolicySet) -> Value {
    let uid = |u: EntityUid| json!({"type":u.type_name().to_string(), "id":u.id().unescaped()});
    let policies: BTreeMap<_, _> = set
        .policies()
        .map(|p| {
            let mut values = p.entity_literals();
            values.sort();
            (
                AsRef::<str>::as_ref(p.id()).to_owned(),
                values.into_iter().map(uid).collect::<Vec<_>>(),
            )
        })
        .collect();
    let templates: BTreeMap<_, _> = set
        .templates()
        .map(|t| {
            let native: &ast::Template = t.as_ref();
            let mut values: Vec<EntityUid> = native
                .condition()
                .subexpressions()
                .filter_map(|e| match e.expr_kind() {
                    ast::ExprKind::Lit(ast::Literal::EntityUID(u)) => {
                        Some(u.as_ref().clone().into())
                    }
                    _ => None,
                })
                .collect();
            values.sort();
            (
                AsRef::<str>::as_ref(t.id()).to_owned(),
                values.into_iter().map(uid).collect::<Vec<_>>(),
            )
        })
        .collect();
    json!({"policies":policies,"templates":templates})
}

fn main() {
    let mut text = String::new();
    io::stdin().read_to_string(&mut text).unwrap();
    let input: Value = serde_json::from_str(&text).unwrap();
    let expected:Vec<_>=input.as_array().unwrap().iter().map(|case| {
        let mut source:PolicySet=if let Some(value)=case.get("policies_json") { PolicySet::from_json_value(value.clone()).unwrap() } else { case["policies"].as_str().unwrap().parse().unwrap() };
        if !case["link"].is_null() {
            let link=&case["link"];
            let bindings=std::collections::HashMap::from([(SlotId::principal(),EntityUid::from_json(link["principal"].clone()).unwrap())]);
            source.link(PolicyId::new(link["template_id"].as_str().unwrap()),PolicyId::new(link["id"].as_str().unwrap()),bindings).unwrap();
        }
        let mappings:BTreeMap<EntityUid,EntityUid>=case["replacements"].as_array().unwrap().iter().map(|r| (EntityUid::from_json(r["from"].clone()).unwrap(),EntityUid::from_json(r["to"].clone()).unwrap())).collect();
        let before=refs(&source);
        let mut changed=PolicySet::new();
        for template in source.templates() {
            let template_json:est::Policy=serde_json::from_value(template.to_json().unwrap()).unwrap();
            let native=mappings.iter().map(|(k,v)| (ast::EntityUID::from(k.clone()),ast::EntityUID::from(v.clone()))).collect();
            let new=template_json.sub_entity_literals(&native).unwrap();
            changed.add_template(Template::from_json(Some(template.id().clone()),serde_json::to_value(new).unwrap()).unwrap()).unwrap();
        }
        for policy in source.policies() {
            if let Some(template)=policy.template_id() {
                let bindings=policy.template_links().unwrap().into_iter().map(|(slot,uid)| (slot,mappings.get(&uid).cloned().unwrap_or(uid))).collect();
                changed.link(template.clone(),policy.id().clone(),bindings).unwrap();
            } else { changed.add(policy.sub_entity_literals(mappings.clone()).unwrap()).unwrap(); }
        }
        json!({"name":case["name"],"before":before,"after":refs(&changed),"policies":changed.to_json().unwrap()})
    }).collect();
    println!("{}", serde_json::to_string_pretty(&expected).unwrap());
}
