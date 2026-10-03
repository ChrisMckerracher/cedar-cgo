//! Generate expression results through the native Cedar API.
use cedar_policy::{
    Context, Entities, EntityUid, EvalResult, Expression, Request, RestrictedExpression,
};
use cedar_policy_core::ast::{EntityUIDEntry, Request as CoreRequest};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{self, Read};

fn value(result: EvalResult) -> Value {
    match result {
        EvalResult::Bool(v) => json!({"bool": v}),
        EvalResult::Long(v) => json!({"long": v}),
        EvalResult::String(v) => json!({"string": v}),
        EvalResult::EntityUid(v) => {
            json!({"entity_uid": {"type": v.type_name().to_string(), "id": v.id().unescaped().to_string()}})
        }
        EvalResult::ExtensionValue(v) => json!({"extension": v}),
        EvalResult::Set(v) => json!({"set": v.iter().cloned().map(value).collect::<Vec<_>>()}),
        EvalResult::Record(v) => {
            json!({"record": v.iter().map(|(k,v)| (k.clone(), value(v.clone()))).collect::<BTreeMap<_,_>>()})
        }
    }
}

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let input: Value = serde_json::from_str(&input).unwrap();
    let results: Vec<_> = input.as_array().unwrap().iter().map(|case| {
        let source = case["expression"].as_str().unwrap();
        let expr: Expression = match source.parse() {
            Ok(expr) => expr,
            Err(err) => return json!({"expression": source, "error_kind": "expression", "message": cgw_abi::diagnostics::render(&err)}),
        };
        if case["restricted"].as_bool().unwrap_or(false)
            && let Err(err) = source.parse::<RestrictedExpression>() {
                return json!({"expression": source, "error_kind": "expression", "message": cgw_abi::diagnostics::render(&err)});
        }
        let env = &case["environment"];
        let uid = |key: &str| if env[key].is_null() { None } else { Some(EntityUid::from_json(env[key].clone()).unwrap()) };
        let context = Context::from_json_value(env["context"].clone(), None).unwrap();
        let entities = Entities::from_json_value(env["entities"].clone(), None).unwrap();
        let entry = |uid: Option<cedar_policy::EntityUid>| uid.map_or_else(EntityUIDEntry::unknown, |uid| EntityUIDEntry::known(uid.into(), None));
        let core_context: &cedar_policy_core::ast::Context = context.as_ref();
        // No schema applies here; omitted variables remain unknown.
        let request = Request::from(CoreRequest::new_unchecked(entry(uid("principal")), entry(uid("action")), entry(uid("resource")), Some(core_context.clone())));
        match cedar_policy::eval_expression(&request, &entities, &expr) {
            Ok(result) => json!({"expression": source, "result": value(result)}),
            Err(err) => json!({"expression": source, "error_kind": "expression", "message": cgw_abi::diagnostics::render(&err)}),
        }
    }).collect();
    println!("{}", serde_json::to_string_pretty(&results).unwrap());
}
