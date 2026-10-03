//! Direct native Cedar PST to EST mapping and semantic roundtrip oracle.
use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, PolicyId, PolicySet, Request, SlotId, pst,
};
use cedar_policy_core::est;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::io::{self, Read};

fn uid(value: &Value) -> EntityUid {
    EntityUid::from_json(value.clone()).unwrap()
}

fn response(value: &cedar_policy::Response) -> Value {
    let mut reasons: Vec<_> = value
        .diagnostics()
        .reason()
        .map(|id| AsRef::<str>::as_ref(id).to_owned())
        .collect();
    reasons.sort();
    let mut errors: Vec<_> = value
        .diagnostics()
        .errors()
        .map(|error| match error {
            cedar_policy::AuthorizationError::PolicyEvaluationError(error) => {
                AsRef::<str>::as_ref(error.policy_id()).to_owned()
            }
        })
        .collect();
    errors.sort();
    json!({"decision":match value.decision() {Decision::Allow=>"allow",Decision::Deny=>"deny"},"reasons":reasons,"error_policies":errors})
}

fn main() {
    let mut text = String::new();
    io::stdin().read_to_string(&mut text).unwrap();
    let cases: Value = serde_json::from_str(&text).unwrap();
    let results: Vec<_> = cases.as_array().unwrap().iter().map(|case| {
        let mut set: PolicySet = case["policies"].as_str().unwrap().parse().unwrap();
        if let Some(links) = case["links"].as_array() {
            for link in links {
                let values: HashMap<_,_> = link["values"].as_object().unwrap().iter().map(|(slot,value)| {
                    let slot = match slot.as_str() {"?principal"=>SlotId::principal(),"?resource"=>SlotId::resource(),_=>unreachable!()};
                    (slot, uid(value))
                }).collect();
                set.link(PolicyId::new(link["template_id"].as_str().unwrap()), PolicyId::new(link["id"].as_str().unwrap()), values).unwrap();
            }
        }
        let native = set.to_pst().unwrap();
        let roundtrip = PolicySet::from_pst(native.clone()).unwrap();
        let policies: BTreeMap<_,_> = set.policies().map(|policy| {
            let pst = policy.to_pst().unwrap();
            let original: est::Policy = serde_json::from_value(policy.to_json().unwrap()).unwrap();
            let imported: pst::Template = original.try_into().unwrap();
            if policy.is_static() {
                assert_eq!(imported.with_id(pst.body().id.clone()), pst.body().clone());
            }
            (AsRef::<str>::as_ref(policy.id()).to_owned(),policy.to_json().unwrap())
        }).collect();
        let templates: BTreeMap<_,_> = set.templates().map(|template| {
            let pst = template.to_pst().unwrap();
            let original: est::Policy = serde_json::from_value(template.to_json().unwrap()).unwrap();
            let imported: pst::Template = original.try_into().unwrap();
            assert_eq!(imported.with_id(pst.id.clone()),pst);
            (AsRef::<str>::as_ref(template.id()).to_owned(),template.to_json().unwrap())
        }).collect();
        let entities = Entities::from_json_value(case["entities"].clone(),None).unwrap();
        let responses: Vec<_> = case["requests"].as_array().unwrap().iter().map(|input| {
            let request = Request::new(uid(&input["principal"]),uid(&input["action"]),uid(&input["resource"]),Context::from_json_value(input["context"].clone(),None).unwrap(),None).unwrap();
            let original = response(&Authorizer::new().is_authorized(&request,&set,&entities));
            assert_eq!(original,response(&Authorizer::new().is_authorized(&request,&roundtrip,&entities)));
            original
        }).collect();
        let mut links: Vec<_> = native.template_links.iter().map(|link| {
            let values: BTreeMap<_,_> = link.values.iter().map(|(slot,uid)| (match slot {pst::SlotId::Principal=>"?principal",pst::SlotId::Resource=>"?resource",_=>unreachable!()},json!({"type":uid.ty.to_string(),"id":uid.eid.to_string()}))).collect();
            json!({"template_id":link.template_id.0.to_string(),"id":link.new_id.0.to_string(),"values":values})
        }).collect();
        links.sort_by_key(|link| link["id"].as_str().unwrap().to_owned());
        json!({"name":case["name"],"policies":policies,"templates":templates,"links":links,"responses":responses})
    }).collect();
    let unknown: est::Expr = pst::Expr::Unknown { name: "x".into() }.into();
    let error: est::Expr = pst::Expr::ResidualError.into();
    let slot: est::Expr = pst::Expr::Slot(pst::SlotId::Principal).into();
    let imported: pst::Expr = error.clone().try_into().unwrap();
    assert!(matches!(imported, pst::Expr::ResidualError));
    assert!(pst::Expr::try_from(unknown.clone()).is_err());
    println!("{}",serde_json::to_string_pretty(&json!({"version":1,"cedar_version":"4.13.0","cases":results,"special_expressions":{"unknown":unknown,"residual_error":error,"slot":slot}})).unwrap());
}
