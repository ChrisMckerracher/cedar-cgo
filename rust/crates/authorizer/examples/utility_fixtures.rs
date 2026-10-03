//! Generate utility fixtures directly through native Cedar operations.
use cedar_policy::{Context, EntityUid, EvalResult, PolicySet, Schema, Template};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{self, Read};

fn project(result: EvalResult) -> Value {
    match result {
        EvalResult::Bool(v) => json!({"bool": v}),
        EvalResult::Long(v) => json!({"long": v}),
        EvalResult::String(v) => json!({"string": v}),
        EvalResult::EntityUid(v) => {
            json!({"entity_uid": {"type": v.type_name().to_string(), "id": v.id().unescaped()}})
        }
        EvalResult::ExtensionValue(v) => json!({"extension": v}),
        EvalResult::Set(v) => json!({"set": v.iter().cloned().map(project).collect::<Vec<_>>()}),
        EvalResult::Record(v) => {
            json!({"record": v.iter().map(|(k, v)| (k.clone(), project(v.clone()))).collect::<BTreeMap<_,_>>()})
        }
    }
}

fn error(kind: &str, err: &impl cgw_abi::diagnostics::Diagnostic) -> Value {
    json!({"error": {"kind": kind, "message": cgw_abi::diagnostics::render(err)}})
}

fn execute(case: &Value) -> Value {
    let uid = |key: &str| EntityUid::from_json(case[key].clone()).unwrap();
    let schema = || {
        case["schema"]["text"]
            .as_str()
            .unwrap()
            .parse::<Schema>()
            .unwrap()
    };
    let operation = case["operation"].as_str().unwrap();
    match operation {
        "parse_uid" => match case["text"].as_str().unwrap().parse::<EntityUid>() {
            Ok(v) => json!({"uid": {"type": v.type_name().to_string(), "id": v.id().unescaped()}}),
            Err(e) => error("entity_uid", &e),
        },
        "render_uid" => match EntityUid::from_json(case["uid"].clone()) {
            Ok(v) => json!({"text": v.to_string()}),
            Err(e) => error("entity_uid", &e),
        },
        "scope_validate" => match cedar_policy::validate_scope_variables(
            &uid("principal"),
            &uid("action"),
            &uid("resource"),
            &schema(),
        ) {
            Ok(()) => json!({"valid": true}),
            Err(e) => error("request", &e),
        },
        "confusables" => {
            let json_policies = case["policies"]["format"].as_str().unwrap() == "json";
            let text = case["policies"]["text"].as_str().unwrap();
            let policies: PolicySet = if json_policies {
                PolicySet::from_json_str(text).unwrap()
            } else {
                text.parse().unwrap()
            };
            let static_templates: Vec<_> = policies
                .policies()
                .filter(|p| p.template_id().is_none())
                .map(|p| {
                    let ast: &cedar_policy_core::ast::Policy = p.as_ref();
                    Template::from(ast.template().clone())
                })
                .collect();
            let mut warnings: Vec<_> = cedar_policy::confusable_string_checker(
                policies.templates().chain(static_templates.iter()),
            )
            .map(|w| {
                let warning = cgw_abi::structured::validation_warning(&w);
                serde_json::to_value(if json_policies {
                    warning.without_spans()
                } else {
                    warning
                })
                .unwrap()
            })
            .collect();
            warnings.sort_by_key(Value::to_string);
            json!({"warnings": warnings})
        }
        "language_version" => json!({"version": cedar_policy::get_lang_version().to_string()}),
        _ => {
            let context = match Context::from_json_value(case["context"].clone(), None) {
                Ok(v) => v,
                Err(e) => return error("context", &e),
            };
            match operation {
                "context_values" => {
                    let values: BTreeMap<_, _> = context
                        .clone()
                        .into_iter()
                        .map(|(key, _)| {
                            let value = project(context.get(&key).unwrap());
                            (key, value)
                        })
                        .collect();
                    json!({"values": values})
                }
                "context_get" => {
                    let value = context.get(case["key"].as_str().unwrap()).map(project);
                    json!({"found": value.is_some(), "value": value})
                }
                "context_merge" => {
                    let other = match Context::from_json_value(case["other"].clone(), None) {
                        Ok(v) => v,
                        Err(e) => return error("context", &e),
                    };
                    match context.merge(other) {
                        Ok(v) => json!({"context": v.to_json_value().unwrap()}),
                        Err(e) => error("context", &e),
                    }
                }
                "context_validate" => match context.validate(&schema(), &uid("action")) {
                    Ok(()) => json!({"valid": true}),
                    Err(e) => error("context", &e),
                },
                _ => panic!("unknown fixture operation"),
            }
        }
    }
}

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let cases: Vec<Value> = serde_json::from_str(&input).unwrap();
    let results: Vec<_> = cases
        .iter()
        .map(|case| json!({"name": case["name"], "output": execute(case)}))
        .collect();
    println!("{}", serde_json::to_string_pretty(&results).unwrap());
}
