use super::{
    policy_error,
    records::{LinkInfo, Output, TemplateInfo, Uid},
};
use cedar_policy::PolicySet;
use cgw_abi::OpError;

pub(super) fn templates(set: &PolicySet) -> Result<Output, OpError> {
    let mut templates = set
        .templates()
        .map(|t| {
            let mut slots: Vec<_> = t.slots().map(ToString::to_string).collect();
            slots.sort_unstable();
            Ok(TemplateInfo {
                id: AsRef::<str>::as_ref(t.id()).to_owned(),
                cedar: t.to_cedar(),
                json: t.to_json().map_err(|e| policy_error(&e))?,
                slots,
                annotations: t
                    .annotations()
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .collect(),
            })
        })
        .collect::<Result<Vec<_>, OpError>>()?;
    templates.sort_unstable_by(|a, b| a.id.cmp(&b.id));
    Ok(Output::Templates { templates })
}

pub(super) fn links(set: &PolicySet) -> Output {
    let mut links: Vec<_> = set
        .policies()
        .filter_map(|p| {
            Some(LinkInfo {
                policy_id: AsRef::<str>::as_ref(p.id()).to_owned(),
                template_id: AsRef::<str>::as_ref(p.template_id()?).to_owned(),
                bindings: p
                    .template_links()?
                    .into_iter()
                    .map(|(slot, uid)| {
                        (
                            slot.to_string(),
                            Uid {
                                r#type: uid.type_name().to_string(),
                                id: uid.id().unescaped().to_owned(),
                            },
                        )
                    })
                    .collect(),
            })
        })
        .collect();
    links.sort_unstable_by(|a, b| a.policy_id.cmp(&b.policy_id));
    Output::Links { links }
}
