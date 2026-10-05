use super::Environment;
use cedar_policy::{EntityUid, RequestEnv, Schema};
use cgw_abi::OpError;
use std::collections::BTreeSet;

pub(super) fn selected_environments(
    schema: &Schema,
    selection: Option<Vec<Environment>>,
) -> Result<Vec<RequestEnv>, OpError> {
    let mut available: Vec<_> = schema.request_envs().collect();
    available.sort_by_key(|env| {
        (
            env.principal().to_string(),
            env.action().clone(),
            env.resource().to_string(),
        )
    });
    let Some(selection) = selection else {
        return Ok(available);
    };
    let mut seen = BTreeSet::new();
    selection
        .into_iter()
        .map(|selected| {
            let action =
                EntityUid::from_json(selected.action).map_err(|e| OpError::new("input", &e))?;
            let key = (
                selected.principal_type.clone(),
                action.clone(),
                selected.resource_type.clone(),
            );
            if !seen.insert(key) {
                return Err(OpError::msg("input", "duplicate request environment"));
            }
            available
                .iter()
                .find(|env| {
                    env.principal().to_string() == selected.principal_type
                        && env.action() == &action
                        && env.resource().to_string() == selected.resource_type
                })
                .cloned()
                .ok_or_else(|| OpError::msg("input", "unknown request environment"))
        })
        .collect()
}
