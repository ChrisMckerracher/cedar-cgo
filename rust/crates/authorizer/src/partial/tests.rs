use super::residual::{ResidualProjection, import_projection, projection};
use cedar_policy::{Authorizer, Policy, PolicyId, PolicySet, Response};
use cedar_policy::{
    Context, Decision, Entities, PartialEntities, PartialEntityUid, PartialRequest, Request, Schema,
};
use serde_json::json;

fn input(id: &str) -> (Schema, PolicySet, Entities) {
    let schema = Schema::from_cedarschema_str(
            "entity User; entity Photo; action view appliesTo {principal: User, resource: Photo, context: {mfa: Bool}};",
        )
        .unwrap()
        .0;
    let mut policies = PolicySet::new();
    policies
            .add(
                Policy::parse(
                    Some(PolicyId::new(id)),
                    "@note(\"雪\") permit(principal, action, resource) when { context.mfa || 9223372036854775807 + 1 > 0 };",
                )
                .unwrap(),
            )
            .unwrap();
    let entities = Entities::from_json_str("[]", Some(&schema)).unwrap();
    (schema, policies, entities)
}

fn partial_request(schema: &Schema) -> PartialRequest {
    PartialRequest::new(
        PartialEntityUid::new("User".parse().unwrap(), None),
        "Action::\"view\"".parse().unwrap(),
        PartialEntityUid::new("Photo".parse().unwrap(), None),
        None,
        schema,
    )
    .unwrap()
}

fn observation(response: &Response) -> (Decision, Vec<String>, Vec<(String, String)>) {
    let mut reasons: Vec<_> = response
        .diagnostics()
        .reason()
        .map(|id| AsRef::<str>::as_ref(id).to_owned())
        .collect();
    reasons.sort();
    let mut errors: Vec<_> = response
        .diagnostics()
        .errors()
        .map(|error| match error {
            cedar_policy::AuthorizationError::PolicyEvaluationError(error) => (
                AsRef::<str>::as_ref(error.policy_id()).to_owned(),
                error.to_string(),
            ),
        })
        .collect();
    errors.sort();
    (response.decision(), reasons, errors)
}

#[test]
fn structured_import_preserves_nested_errors_and_raw_ids() {
    for id in ["", "policy\"\n\\\0", "ordinary"] {
        let (schema, policies, entities) = input(id);
        let partial_entities = PartialEntities::from_concrete(entities.clone(), &schema).unwrap();
        let request = partial_request(&schema);
        let response = policies.tpe(&request, &partial_entities, &schema).unwrap();
        let wire = serde_json::to_vec(&projection(&response).unwrap()).unwrap();
        let imported: ResidualProjection = serde_json::from_slice(&wire).unwrap();
        assert!(imported.policies[id].to_string().contains("\"error\":[]"));
        let reconstructed = import_projection(&imported, &response).unwrap();
        assert_eq!(
            reconstructed.to_pst().unwrap(),
            response.policy_set().to_pst().unwrap()
        );
        for mfa in [true, false] {
            let context = Context::from_json_value(json!({"mfa":mfa}), None).unwrap();
            let concrete = Request::new(
                "User::\"alice\"".parse().unwrap(),
                "Action::\"view\"".parse().unwrap(),
                "Photo::\"one\"".parse().unwrap(),
                context,
                Some(&schema),
            )
            .unwrap();
            let expected = observation(&response.reauthorize(&concrete, &entities).unwrap());
            let actual =
                observation(&Authorizer::new().is_authorized(&concrete, &reconstructed, &entities));
            assert_eq!(actual, expected);
            let direct =
                observation(&Authorizer::new().is_authorized(&concrete, &policies, &entities));
            assert_eq!((actual.0, &actual.1), (direct.0, &direct.1));
            assert_eq!(
                actual.2.iter().map(|e| &e.0).collect::<Vec<_>>(),
                direct.2.iter().map(|e| &e.0).collect::<Vec<_>>()
            );
            if mfa {
                assert_eq!(actual.0, Decision::Allow);
                assert!(actual.2.is_empty());
                assert_eq!(actual.1, vec![id.to_owned()]);
            } else {
                assert_eq!(actual.0, Decision::Deny);
                assert_eq!(actual.2.len(), 1);
                assert_eq!(actual.2[0].0, id);
                assert!(!actual.2[0].1.is_empty());
            }
        }
    }
}

#[test]
fn structured_import_rejects_changed_projections() {
    let (schema, policies, entities) = input("policy");
    let partial_entities = PartialEntities::from_concrete(entities, &schema).unwrap();
    let request = partial_request(&schema);
    let response = policies.tpe(&request, &partial_entities, &schema).unwrap();
    let wire = serde_json::to_vec(&projection(&response).unwrap()).unwrap();
    for change in 0..5 {
        let mut imported: ResidualProjection = serde_json::from_slice(&wire).unwrap();
        match change {
            0 => imported.version += 1,
            1 => imported.cedar_version = "0.0.0".into(),
            2 => imported.policies.get_mut("policy").unwrap()["effect"] = json!("forbid"),
            3 => imported.policies.get_mut("policy").unwrap()["conditions"] = json!([]),
            _ => {
                imported.policies.remove("policy");
            }
        }
        assert_eq!(
            import_projection(&imported, &response).unwrap_err().kind,
            "input"
        );
    }
}
