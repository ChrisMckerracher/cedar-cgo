use super::*;

pub(super) fn cases() -> (PolicySet, Vec<Value>) {
    let base = PolicySet::from_policies([policy("allow-view", PERMIT)]).unwrap();
    let block = policy("require-mfa", FORBID);
    let unusual_id = "quote\"\nslash\\雪";
    let mut edits = Vec::new();
    for (name, add, remove, other, rename) in [
        ("add", Some(block.clone()), None, None, false),
        (
            "unusual-id",
            Some(policy(unusual_id, FORBID)),
            None,
            None,
            false,
        ),
        (
            "unusual-validation-id",
            Some(policy(
                unusual_id,
                "permit(principal,action,resource) when { resource.missing };",
            )),
            None,
            None,
            false,
        ),
        (
            "duplicate-add",
            Some(policy("allow-view", FORBID)),
            None,
            None,
            false,
        ),
        ("missing-remove", None, Some("absent"), None, false),
        ("remove", None, Some("allow-view"), None, false),
        (
            "merge",
            None,
            None,
            Some(PolicySet::from_policies([block.clone()]).unwrap()),
            false,
        ),
        ("merge-equal", None, None, Some(base.clone()), false),
        (
            "merge-conflict",
            None,
            None,
            Some(PolicySet::from_policies([policy("allow-view", FORBID)]).unwrap()),
            false,
        ),
        (
            "merge-rename",
            None,
            None,
            Some(PolicySet::from_policies([policy("allow-view", FORBID)]).unwrap()),
            true,
        ),
        (
            "invalid-validation",
            Some(policy(
                "bad-attribute",
                "permit(principal,action,resource) when { resource.missing };",
            )),
            None,
            None,
            false,
        ),
    ] {
        let mut set = base.clone();
        let mut renames = BTreeMap::new();
        let result = if let Some(p) = &add {
            set.add(p.clone())
        } else if let Some(id) = remove {
            set.remove_static(PolicyId::new(id)).map(|_| ())
        } else if let Some(other) = &other {
            set.merge(other, rename).map(|m| {
                renames = m
                    .into_iter()
                    .map(|(a, b)| (raw_id(&a).to_owned(), raw_id(&b).to_owned()))
                    .collect();
            })
        } else {
            Ok(())
        };
        edits.push(json!({"name":name,"base":base.clone().to_json().unwrap(),"add":add.as_ref().map(|p|json!({"id":raw_id(p.id()),"json":p.to_json().unwrap()})),"remove":remove,"other":other.map(|s|s.to_json().unwrap()),"rename":rename,"renames":renames,"error":result.err().map(|e|diagnostic(&e)),"result":snapshot(&set)}));
    }
    let unusual_base = PolicySet::from_policies([policy(unusual_id, PERMIT)]).unwrap();
    let unusual_other = PolicySet::from_policies([policy(unusual_id, FORBID)]).unwrap();
    let mut unusual_merged = unusual_base.clone();
    let unusual_renames = unusual_merged
        .merge(&unusual_other, true)
        .unwrap()
        .into_iter()
        .map(|(a, b)| (raw_id(&a).to_owned(), raw_id(&b).to_owned()))
        .collect::<BTreeMap<_, _>>();
    edits.push(json!({"name":"unusual-merge-id","base":unusual_base.to_json().unwrap(),"add":null,"remove":null,"other":unusual_other.to_json().unwrap(),"rename":true,"renames":unusual_renames,"error":null,"result":snapshot(&unusual_merged)}));
    (base, edits)
}
