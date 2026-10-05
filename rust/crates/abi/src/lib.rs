//! Shared native transport records, Cedar parsing, and diagnostic conversion.
mod callback;
pub mod structured;
pub use callback::{Callback, CallbackFn};

use cedar_policy::{PolicySet, Schema};
use serde::Deserialize;
use std::str::FromStr;

pub const ABI_VERSION: u32 = 2;

#[derive(Debug)]
pub struct OpError {
    /// Machine-readable error kind, such as `schema` or `request`.
    pub kind: &'static str,
    pub message: String,
}

impl OpError {
    /// Retains related diagnostics and help text that `Display` alone omits.
    pub fn new(kind: &'static str, err: &(dyn diagnostics::Diagnostic + '_)) -> Self {
        Self {
            kind,
            message: diagnostics::render(err),
        }
    }

    pub fn msg(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

pub fn parse_input<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, OpError> {
    serde_json::from_slice(bytes).map_err(|e| OpError::msg("input", e.to_string()))
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    /// Cedar's human-readable syntax.
    Cedar,
    Json,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub format: Format,
    pub text: String,
}

pub fn parse_schema(src: &Source) -> Result<Schema, OpError> {
    parse_schema_with_warnings(src).map(|(schema, _)| schema)
}

pub fn parse_schema_with_warnings(
    src: &Source,
) -> Result<(Schema, Vec<structured::Message>), OpError> {
    match src.format {
        Format::Cedar => Schema::from_cedarschema_str(&src.text)
            .map(|(schema, warnings)| {
                (
                    schema,
                    warnings.map(|w| structured::schema_warning(&w)).collect(),
                )
            })
            .map_err(|e| OpError::new("schema", &e)),
        Format::Json => Schema::from_json_str(&src.text)
            .map(|schema| (schema, Vec::new()))
            .map_err(|e| OpError::new("schema", &e)),
    }
}

pub fn parse_policies(src: &Source) -> Result<PolicySet, OpError> {
    match src.format {
        Format::Cedar => PolicySet::from_str(&src.text).map_err(|e| OpError::new("policies", &e)),
        Format::Json => {
            PolicySet::from_json_str(&src.text).map_err(|e| OpError::new("policies", &e))
        }
    }
}

pub mod diagnostics {
    pub use miette::Diagnostic;

    pub fn render(err: &(dyn Diagnostic + '_)) -> String {
        let mut out = err.to_string();
        if let Some(related) = err.related() {
            for r in related {
                let line = r.to_string();
                if !line.is_empty() && !out.contains(&line) {
                    out.push_str("; ");
                    out.push_str(&line);
                }
            }
        }
        if let Some(help) = err.help() {
            out.push_str(" (help: ");
            out.push_str(&help.to_string());
            out.push(')');
        }
        out
    }
}
