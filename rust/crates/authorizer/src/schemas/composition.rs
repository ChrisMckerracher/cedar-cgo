use cedar_policy::{Schema, SchemaFragment};
use cgw_abi::OpError;
use serde_json::{Map, Value, json};

pub(super) fn compose(fragments: Vec<SchemaFragment>) -> Result<Value, OpError> {
    // Native composition checks declarations before serialization can merge their maps.
    Schema::from_schema_fragments(fragments.clone()).map_err(|e| OpError::new("schema", &e))?;
    let mut combined = Map::new();
    for fragment in fragments {
        let value = fragment
            .to_json_value()
            .map_err(|e| OpError::new("schema", &e))?;
        for (namespace, declarations) in value
            .as_object()
            .ok_or_else(|| OpError::msg("internal", "native fragment is not an object"))?
        {
            let combined_namespace = combined
                .entry(namespace)
                .or_insert_with(|| json!({"commonTypes":{},"entityTypes":{},"actions":{}}));
            for (category, entries) in declarations
                .as_object()
                .ok_or_else(|| OpError::msg("internal", "native namespace is not an object"))?
            {
                let target = combined_namespace
                    .as_object_mut()
                    .ok_or_else(|| OpError::msg("internal", "combined namespace is not an object"))?
                    .entry(category)
                    .or_insert_with(|| json!({}));
                if let (Some(target), Some(entries)) = (target.as_object_mut(), entries.as_object())
                {
                    for (name, entry) in entries {
                        // Namespace annotation conflicts use fragment order; declarations cannot conflict.
                        target.insert(name.clone(), entry.clone());
                    }
                } else {
                    return Err(OpError::msg(
                        "internal",
                        "native declaration is not an object",
                    ));
                }
            }
        }
    }
    let combined = Value::Object(combined);
    Schema::from_json_value(combined.clone()).map_err(|e| OpError::new("schema", &e))?;
    Ok(combined)
}
