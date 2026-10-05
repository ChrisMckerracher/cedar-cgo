use super::*;

pub(super) fn uid(value: &Value) -> EntityUid {
    EntityUid::from_json(value.clone()).unwrap()
}
pub(super) fn partial(value: &Value) -> PartialEntityUid {
    PartialEntityUid::new(
        value["type"].as_str().unwrap().parse().unwrap(),
        value["id"].as_str().map(EntityId::new),
    )
}
pub(super) fn sorted(values: impl Iterator<Item = EntityUid>) -> Vec<Value> {
    let mut values: Vec<_> = values.collect();
    values.sort();
    values
        .into_iter()
        .map(|u| json!({"type":u.type_name().to_string(),"id":u.id().unescaped()}))
        .collect()
}
pub(super) fn partial_entities(
    loaded: Entities,
    additions: Option<&Value>,
    schema: &Schema,
) -> Result<PartialEntities, &'static str> {
    // Native conversion fixes all loaded fields before partial query additions are parsed.
    let loaded = PartialEntities::from_concrete(loaded, schema).map_err(|_| "entities")?;
    let Some(additions) = additions else {
        return Ok(loaded);
    };
    let core: &cedar_policy_core::tpe::entities::PartialEntities = loaded.as_ref();
    let mut values: Vec<_> = core
        .entities()
        .filter(|entity| !entity.uid().is_action())
        .cloned()
        .collect();
    for addition in additions.as_array().unwrap() {
        values.push(
            cedar_policy_core::tpe::entities::parse_ejson(
                serde_json::from_value(addition.clone()).unwrap(),
                schema.as_ref(),
            )
            .map_err(|_| "entities")?,
        );
    }
    let values = values
        .into_iter()
        .map(|entity| {
            let attrs = entity.attrs().map(|values| {
                values
                    .iter()
                    .map(|(name, value)| {
                        (
                            name.clone(),
                            cedar_policy_core::ast::RestrictedExpr::from(value.clone()).into(),
                        )
                    })
                    .collect()
            });
            let tags = entity.tags().map(|values| {
                values
                    .iter()
                    .map(|(name, value)| {
                        (
                            name.clone(),
                            cedar_policy_core::ast::RestrictedExpr::from(value.clone()).into(),
                        )
                    })
                    .collect()
            });
            let ancestors = entity
                .ancestors()
                .map(|values| values.iter().cloned().map(EntityUid::from).collect());
            PartialEntity::new(entity.uid().clone().into(), attrs, ancestors, tags, schema)
                .map_err(|_| "entities")
        })
        .collect::<Result<Vec<_>, _>>()?;
    PartialEntities::from_partial_entities(values, schema).map_err(|_| "entities")
}
