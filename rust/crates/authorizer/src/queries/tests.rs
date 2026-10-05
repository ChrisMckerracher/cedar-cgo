use super::input::{Input, input};

const CONTEXT: &str = r#"{"max":9223372036854775807,"min":-9223372036854775808,"exact":9007199254740993,"label":"\u96ea"}"#;
const ENTITIES: &str =
    r#"[{"uid":{"type":"User","id":"new"},"attrs":{"max":9223372036854775807},"parents":[]}]"#;

#[test]
fn abi_requests_preserve_raw_context_and_entities() {
    for operation in ["resource", "principal", "action"] {
        let request = match operation {
            "resource" => format!(
                r#"{{"operation":"resource","principal":{{"type":"User","id":"alice"}},"action":{{"type":"Action","id":"view"}},"resource_type":"Photo","context":{CONTEXT},"entities":{ENTITIES}}}"#
            ),
            "principal" => format!(
                r#"{{"operation":"principal","principal_type":"User","action":{{"type":"Action","id":"view"}},"resource":{{"type":"Photo","id":"one"}},"context":{CONTEXT},"entities":{ENTITIES}}}"#
            ),
            "action" => format!(
                r#"{{"operation":"action","principal":{{"type":"User"}},"resource":{{"type":"Photo"}},"context":{CONTEXT},"entities":{ENTITIES}}}"#
            ),
            _ => unreachable!(),
        };
        let (context, entities) = match input(request.as_bytes()).unwrap() {
            Input::Resource(request) => (Some(request.context), request.entities),
            Input::Principal(request) => (Some(request.context), request.entities),
            Input::Action(request) => (request.context, request.entities),
        };
        assert_eq!(context.unwrap().get(), CONTEXT);
        assert_eq!(entities.unwrap().get(), ENTITIES);
    }
}

#[test]
fn abi_action_request_retains_unknown_context() {
    for context in ["", r#", "context":null"#] {
        let request = format!(
            r#"{{"operation":"action","principal":{{"type":"User"}},"resource":{{"type":"Photo"}}{context}}}"#
        );
        let Input::Action(request) = input(request.as_bytes()).unwrap() else {
            panic!("unexpected operation");
        };
        assert!(request.context.is_none());
        assert!(request.entities.is_none());
    }
}

#[test]
fn abi_requests_reject_missing_and_unrelated_fields() {
    for request in [
        r#"{"operation":"resource","principal":{},"action":{},"resource_type":"Photo"}"#,
        r#"{"operation":"principal","action":{},"resource":{},"context":{}}"#,
        r#"{"operation":"action","principal":{"type":"User"}}"#,
        r#"{"operation":"action","principal":{"type":"User"},"resource":{"type":"Photo"},"resource_type":"Photo"}"#,
        r#"{"operation":"unknown"}"#,
        r#"{"operation":"action","operation":"principal","principal":{"type":"User"},"resource":{"type":"Photo"}}"#,
    ] {
        assert!(input(request.as_bytes()).is_err(), "{request}");
    }
}
