use super::*;

pub(super) const SCHEMA: &str = "entity User; entity Photo { public: Bool }; action view appliesTo { principal: User, resource: Photo, context: { mfa: Bool } };";
pub(super) const PERMIT: &str = "@owner(\"security\") permit(principal is User, action == Action::\"view\", resource is Photo) when { resource.public };";
pub(super) const FORBID: &str = "forbid(principal, action, resource) unless { context.mfa };";

pub(super) fn raw_id(id: &PolicyId) -> &str {
    AsRef::<str>::as_ref(id)
}

pub(super) fn policy(id: &str, source: &str) -> Policy {
    Policy::parse(Some(PolicyId::new(id)), source).unwrap()
}

pub(super) fn diagnostic(e: &(dyn cgw_abi::diagnostics::Diagnostic + '_)) -> String {
    cgw_abi::diagnostics::render(e)
}

pub(super) fn snapshot(set: &PolicySet) -> Value {
    let schema = Schema::from_cedarschema_str(SCHEMA).unwrap().0;
    let validation = Validator::new(schema).validate(set, ValidationMode::Strict);
    let mut errors = validation
        .validation_errors()
        .map(|e| {
            serde_json::to_value(cgw_abi::structured::validation_error(e).without_spans()).unwrap()
        })
        .collect::<Vec<_>>();
    errors.sort_by_key(ToString::to_string);
    let mut warnings = validation
        .validation_warnings()
        .map(|e| {
            serde_json::to_value(cgw_abi::structured::validation_warning(e).without_spans())
                .unwrap()
        })
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
