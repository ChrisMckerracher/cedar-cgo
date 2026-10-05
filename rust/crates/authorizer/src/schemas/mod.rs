use cedar_policy::SchemaFragment;
use cgw_abi::{Format, OpError, Source, parse_input, parse_schema};
use serde::Deserialize;
use serde_json::{Value, json};
mod composition;
mod inspection;
use composition::compose;
use inspection::inspection;

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
