use super::*;

pub(super) struct Projection {
    pub(super) reasons: Vec<String>,
    pub(super) residuals: Vec<Value>,
    pub(super) projected: BTreeMap<String, Value>,
    pub(super) nested_errors: Vec<String>,
    pub(super) rebuilt: PolicySet,
}

pub(super) fn project(response: &cedar_policy::TpeResponse<'_>) -> Result<Projection> {
    let mut reasons: Vec<_> = response
        .reason()
        .into_iter()
        .flatten()
        .map(|id| AsRef::<str>::as_ref(id).to_owned())
        .collect();
    reasons.sort();
    let mut residuals: Vec<_> = response.policies().map(|policy| {
        let id = policy.id();
        let state = if response.true_permits().chain(response.true_forbids()).any(|p| p == id) { "true" }
            else if response.false_permits().chain(response.false_forbids()).any(|p| p == id) { "false" }
            else if response.error_permits().chain(response.error_forbids()).any(|p| p == id) { "error" }
            else { "residual" };
        json!({"policy_id":AsRef::<str>::as_ref(id).to_owned(), "effect":policy.effect().to_string(), "state":state, "cedar":policy.to_string()})
    }).collect();
    residuals.sort_by(|a, b| a["policy_id"].as_str().cmp(&b["policy_id"].as_str()));
    let residual_set = response.policy_set();
    let mut projected = BTreeMap::new();
    for policy in response.policies() {
        let canonical = Policy::from_pst(policy.to_pst()?)?;
        let json = canonical.to_json()?;
        let stored = residual_set
            .policy(policy.id())
            .ok_or("missing residual policy")?;
        assert_eq!(json, Policy::from_pst(stored.to_pst()?)?.to_json()?);
        projected.insert(AsRef::<str>::as_ref(policy.id()).to_owned(), json);
    }
    let mut nested_errors = Vec::new();
    for policy in response.residual_policies() {
        let pst = policy.to_pst()?;
        if pst.body().clauses().iter().any(|clause| match clause {
            cedar_policy::pst::Clause::When(expr) | cedar_policy::pst::Clause::Unless(expr) => {
                expr.has_error()
            }
        }) {
            nested_errors.push(AsRef::<str>::as_ref(policy.id()).to_owned());
        }
        assert!(projected.contains_key(AsRef::<str>::as_ref(policy.id())));
    }
    nested_errors.sort();
    let rebuilt = PolicySet::from_pst(residual_set.to_pst()?)?;
    Ok(Projection {
        reasons,
        residuals,
        projected,
        nested_errors,
        rebuilt,
    })
}
