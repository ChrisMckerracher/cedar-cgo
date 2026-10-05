use crate::entity_uid;
use cedar_policy::{Context, Entities, PartialEntities, PartialEntityUid, PartialRequest, Schema};
use cgw_abi::OpError;
use serde::Deserialize;
use serde_json::{Value, value::RawValue};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PartialUidInput {
    pub(crate) r#type: String,
    pub(crate) id: Option<String>,
}

impl PartialUidInput {
    pub(crate) fn parse(self, kind: &'static str) -> Result<PartialEntityUid, OpError> {
        Ok(PartialEntityUid::new(
            self.r#type.parse().map_err(|e| OpError::new(kind, &e))?,
            self.id.map(|id| cedar_policy::EntityId::new(&id)),
        ))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PartialInput {
    principal: PartialUidInput,
    action: Value,
    resource: PartialUidInput,
    context: Option<Box<RawValue>>,
    pub(super) entities: Option<Box<RawValue>>,
}

impl PartialInput {
    pub(crate) fn request(self, schema: &Schema) -> Result<PartialRequest, OpError> {
        let action = entity_uid(self.action, "action")?;
        let context = self
            .context
            .as_deref()
            .map(|json| {
                Context::from_json_str(json.get(), Some((schema, &action)))
                    .map_err(|e| OpError::new("context", &e))
            })
            .transpose()?;
        PartialRequest::new(
            self.principal.parse("principal")?,
            action,
            self.resource.parse("resource")?,
            context,
            schema,
        )
        .map_err(|e| OpError::new("request", &e))
    }
}

pub(crate) fn parse_partial_entities(
    input: Option<&RawValue>,
    loaded: &Entities,
    schema: &Schema,
) -> Result<PartialEntities, OpError> {
    let mut entities = Vec::new();
    for entity in loaded.iter() {
        // TPE JSON excludes actions; its constructor inserts them from the schema.
        if entity.uid().type_name().basename() == "Action" {
            continue;
        }
        let mut json = entity
            .to_json_value()
            .map_err(|e| OpError::new("entities", &e))?;
        // Concrete JSON omits empty tags, while TPE interprets omission as unknown.
        if json.get("tags").is_none() {
            json["tags"] = serde_json::json!({});
        }
        entities.push(json);
    }
    if let Some(input) = input {
        let extra: Vec<Value> = serde_json::from_str(input.get())
            .map_err(|e| OpError::msg("entities", e.to_string()))?;
        entities.extend(extra);
    }
    PartialEntities::from_json_value(Value::Array(entities), schema)
        .map_err(|e| OpError::new("entities", &e))
}
