use cedar_policy::{Decision, Effect, TpeResponse};
use cgw_abi::OpError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};

pub(super) const RESIDUAL_VERSION: u32 = 1;
pub(super) const CEDAR_VERSION: &str = "4.13.0";

#[derive(Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResidualProjection {
    pub(super) version: u32,
    pub(super) cedar_version: String,
    pub(super) policies: BTreeMap<String, Value>,
}

pub(super) fn projection(response: &TpeResponse<'_>) -> Result<ResidualProjection, OpError> {
    let native = response
        .policy_set()
        .to_pst()
        .map_err(|e| OpError::new("policies", &e))?;
    let policies = native
        .policies
        .into_iter()
        .map(|(id, policy)| {
            let est: cedar_policy_core::est::Policy = policy
                .body()
                .clone()
                .try_into()
                .map_err(|e| OpError::new("policies", &e))?;
            let json =
                serde_json::to_value(est).map_err(|e| OpError::msg("internal", e.to_string()))?;
            Ok((id.0.to_string(), json))
        })
        .collect::<Result<_, OpError>>()?;
    Ok(ResidualProjection {
        version: RESIDUAL_VERSION,
        cedar_version: CEDAR_VERSION.to_owned(),
        policies,
    })
}

pub(super) fn import_projection(
    imported: &ResidualProjection,
    response: &TpeResponse<'_>,
) -> Result<cedar_policy::PolicySet, OpError> {
    if imported.version != RESIDUAL_VERSION || imported.cedar_version != CEDAR_VERSION {
        return Err(OpError::msg(
            "input",
            "unsupported residual representation or Cedar version",
        ));
    }
    if projection(response)? != *imported {
        return Err(OpError::msg(
            "input",
            "residual export does not match native partial evaluation",
        ));
    }
    // Ordinary EST parsing excludes residual errors; exact projection equality permits native PST reconstruction.
    let native = response
        .policy_set()
        .to_pst()
        .map_err(|e| OpError::new("input", &e))?;
    cedar_policy::PolicySet::from_pst(native).map_err(|e| OpError::new("input", &e))
}

#[derive(Serialize)]
pub(crate) struct ResidualOutput {
    policy_id: String,
    effect: &'static str,
    state: &'static str,
    cedar: String,
}

#[derive(Serialize)]
pub(crate) struct PartialOutput {
    decision: &'static str,
    reasons: Vec<String>,
    pub(super) residuals: Vec<ResidualOutput>,
    projection: ResidualProjection,
}

pub(crate) fn summarize(response: &TpeResponse<'_>) -> Result<PartialOutput, OpError> {
    let trues: HashSet<_> = response
        .true_permits()
        .chain(response.true_forbids())
        .collect();
    let falses: HashSet<_> = response
        .false_permits()
        .chain(response.false_forbids())
        .collect();
    let errors: HashSet<_> = response
        .error_permits()
        .chain(response.error_forbids())
        .collect();
    let mut residuals: Vec<_> = response
        .policies()
        .map(|p| ResidualOutput {
            policy_id: AsRef::<str>::as_ref(p.id()).to_owned(),
            effect: match p.effect() {
                Effect::Permit => "permit",
                Effect::Forbid => "forbid",
            },
            state: if trues.contains(p.id()) {
                "true"
            } else if falses.contains(p.id()) {
                "false"
            } else if errors.contains(p.id()) {
                "error"
            } else {
                "residual"
            },
            cedar: p.to_string(),
        })
        .collect();
    residuals.sort_unstable_by(|a, b| a.policy_id.cmp(&b.policy_id));
    let mut reasons: Vec<_> = response
        .reason()
        .into_iter()
        .flatten()
        .map(|id| AsRef::<str>::as_ref(id).to_owned())
        .collect();
    reasons.sort_unstable();
    Ok(PartialOutput {
        decision: match response.decision() {
            Some(Decision::Allow) => "allow",
            Some(Decision::Deny) => "deny",
            None => "undecided",
        },
        reasons,
        residuals,
        projection: projection(response)?,
    })
}
