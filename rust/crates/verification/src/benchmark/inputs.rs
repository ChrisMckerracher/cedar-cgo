use super::Result;
use cedar_policy::{Authorizer, Context, Entities, EntityUid, PolicySet, Request, Schema};
use cedar_policy::{ValidationMode, Validator};
use std::hint::black_box;
use std::str::FromStr;

const CONTEXT: &str = r#"{"deviceLevel":1,"platform":{"os":"ios","model":"iPhone17,1","securityLevel":3},"sessionId":"s1","now":{"__extn":{"fn":"datetime","arg":"2026-10-01T12:00:00Z"}},"machineAttested":true,"sourceIp":{"__extn":{"fn":"ip","arg":"10.1.2.3"}}}"#;

pub(super) struct Inputs {
    schema: String,
    policies: String,
    entities: String,
}

pub(super) struct Loaded {
    pub schema: Schema,
    pub policies: PolicySet,
    pub entities: Entities,
    pub authorizer: Authorizer,
}

impl Inputs {
    pub fn read(directory: &str) -> Result<Self> {
        let read = |name| std::fs::read_to_string(format!("{directory}/{name}"));
        Ok(Self {
            schema: read("joy.cedarschema")?,
            policies: read("old.cedar")?,
            entities: read("entities.json")?,
        })
    }

    fn schema(&self) -> Result<Schema> {
        let (schema, warnings) = Schema::from_cedarschema_str(&self.schema)?;
        assert_eq!(warnings.count(), 0);
        Ok(schema)
    }

    pub fn load(&self) -> Result<Loaded> {
        let schema = self.schema()?;
        let policies = PolicySet::from_str(&self.policies)?;
        let entities = Entities::from_json_str(&self.entities, Some(&schema))?;
        assert_eq!(policies.policies().count(), 45);
        assert_eq!(entities.iter().count(), 10);
        Ok(Loaded {
            schema,
            policies,
            entities,
            authorizer: Authorizer::new(),
        })
    }

    pub fn request(&self, schema: &Schema) -> Result<Request> {
        let uid = |kind, id| -> Result<EntityUid> {
            Ok(EntityUid::from_json(
                serde_json::json!({"type": kind, "id": id}),
            )?)
        };
        let action = uid("Joy::Action", "session.write")?;
        let context = Context::from_json_str(CONTEXT, Some((schema, &action)))?;
        Ok(Request::new(
            uid("Joy::Device", "phone1")?,
            action,
            uid("Joy::Session", "s1")?,
            context,
            Some(schema),
        )?)
    }

    pub fn validate(&self) -> Result<()> {
        let validator = Validator::new(self.schema()?);
        let policies = PolicySet::from_str(&self.policies)?;
        let result = validator.validate(&policies, ValidationMode::Strict);
        assert!(result.validation_passed());
        assert_eq!(result.validation_errors().count(), 0);
        assert_eq!(result.validation_warnings().count(), 0);
        black_box(serde_json::to_vec(&serde_json::json!({
            "passed": true, "errors": [], "warnings": [], "schema_warnings": []
        }))?);
        Ok(())
    }
}
