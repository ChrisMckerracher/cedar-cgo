use cedar_policy::{EntityUid, Schema, SchemaFragment};
use cedar_policy_core::validator::{RawName, ValidatorSchema, json_schema};
use cgw_abi::{Format, OpError, Source, parse_input, parse_schema};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Input {
    Convert { fragment: Source, format: Format },
    Compose { fragments: Vec<Source> },
    Inspect { schema: Source },
    Actions { schema: Source },
}

fn fragment(source: &Source) -> Result<SchemaFragment, OpError> {
    match source.format {
        Format::Cedar => SchemaFragment::from_cedarschema_str(&source.text)
            .map(|(fragment, _)| fragment)
            .map_err(|e| OpError::new("schema", &e)),
        Format::Json => {
            SchemaFragment::from_json_str(&source.text).map_err(|e| OpError::new("schema", &e))
        }
    }
}

fn uid(value: &EntityUid) -> Value {
    json!({"type":value.type_name().to_string(),"id":value.id().unescaped()})
}

fn sorted_uids(values: impl Iterator<Item = EntityUid>) -> Vec<Value> {
    let mut values: Vec<_> = values.collect();
    values.sort();
    values.into_iter().map(|value| uid(&value)).collect()
}

fn resolved(value: Value) -> Result<Value, OpError> {
    let fragment: json_schema::Fragment<RawName> =
        json_schema::Fragment::from_json_value(value).map_err(|e| OpError::new("schema", &e))?;
    let resolved = fragment
        .to_internal_name_fragment_with_resolved_types()
        .map_err(|e| OpError::new("schema", &e))?;
    serde_json::to_value(resolved).map_err(|e| OpError::msg("internal", e.to_string()))
}

fn compose(fragments: Vec<SchemaFragment>) -> Result<Value, OpError> {
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

fn inspection(schema: &Schema, source: SchemaFragment) -> Result<Value, OpError> {
    let core: &ValidatorSchema = schema.as_ref();
    let expanded = core
        .to_json_schema()
        .map_err(|e| OpError::msg("schema", e))?;
    let declarations = source
        .to_json_value()
        .map_err(|e| OpError::new("schema", &e))?;
    let ancestors: BTreeMap<_, _> = schema
        .entity_types()
        .map(|entity_type| {
            let mut ancestors: Vec<_> = schema
                .ancestors(entity_type)
                .into_iter()
                .flatten()
                .map(ToString::to_string)
                .collect();
            ancestors.sort();
            (entity_type.to_string(), ancestors)
        })
        .collect();
    let mut environments: Vec<_> = schema
        .request_envs()
        .map(|env| {
            (
                env.principal().to_string(),
                env.action().clone(),
                env.resource().to_string(),
            )
        })
        .collect();
    environments.sort();
    let environments: Vec<_> = environments
        .into_iter()
        .map(|(principal, action, resource)| {
            json!({"principal_type":principal,"action":uid(&action),"resource_type":resource})
        })
        .collect();
    Ok(json!({
        "resolved_schema":resolved(declarations)?,
        "expanded_schema":expanded,
        "ancestors":ancestors,
        "actions":sorted_uids(schema.actions().cloned()),
        "action_groups":sorted_uids(schema.action_groups().cloned()),
        "environments":environments,
    }))
}

pub fn execute(bytes: &[u8]) -> Result<Value, OpError> {
    match parse_input(bytes)? {
        Input::Convert {
            fragment: source,
            format,
        } => {
            let fragment = fragment(&source)?;
            let (format, text) = match format {
                Format::Cedar => (
                    "cedar",
                    fragment
                        .to_cedarschema()
                        .map_err(|e| OpError::new("schema", &e))?,
                ),
                Format::Json => (
                    "json",
                    fragment
                        .to_json_string()
                        .map_err(|e| OpError::new("schema", &e))?,
                ),
            };
            Ok(json!({"fragment":{"format":format,"text":text}}))
        }
        Input::Compose { fragments } => {
            let fragments = fragments.iter().map(fragment).collect::<Result<_, _>>()?;
            Ok(json!({"schema":compose(fragments)?}))
        }
        Input::Inspect { schema: source } => {
            let schema = parse_schema(&source)?;
            Ok(json!({"inspection":inspection(&schema, fragment(&source)?)?}))
        }
        Input::Actions { schema: source } => {
            let entities = parse_schema(&source)?
                .action_entities()
                .map_err(|e| OpError::new("entities", &e))?
                .to_json_value()
                .map_err(|e| OpError::new("entities", &e))?;
            Ok(json!({"entities":entities}))
        }
    }
}
