use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum Output {
    Policies { policies: Value },
    Templates { templates: Vec<TemplateInfo> },
    Links { links: Vec<LinkInfo> },
}

#[derive(Serialize)]
pub(crate) struct TemplateInfo {
    pub(super) id: String,
    pub(super) cedar: String,
    pub(super) json: Value,
    pub(super) slots: Vec<String>,
    pub(super) annotations: BTreeMap<String, String>,
}

#[derive(Serialize)]
pub(crate) struct Uid {
    pub(super) r#type: String,
    pub(super) id: String,
}

#[derive(Serialize)]
pub(crate) struct LinkInfo {
    pub(super) policy_id: String,
    pub(super) template_id: String,
    pub(super) bindings: BTreeMap<String, Uid>,
}
