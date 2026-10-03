//! Stable diagnostic metadata comes from native variants and labels, never rendered hints.
use crate::diagnostics::{Diagnostic, render};
use cedar_policy::{SchemaWarning, ValidationError, ValidationWarning};
use serde::Serialize;

#[derive(Serialize)]
pub struct Span {
    offset: usize,
    length: usize,
}

#[derive(Serialize)]
pub struct Message {
    category: &'static str,
    severity: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    spans: Vec<Span>,
}

pub fn message(value: &dyn Diagnostic, category: &'static str, severity: &'static str) -> Message {
    let mut spans: Vec<_> = value
        .labels()
        .into_iter()
        .flatten()
        .map(|label| Span {
            offset: label.offset(),
            length: label.len(),
        })
        .collect();
    spans.sort_by_key(|span| (span.offset, span.length));
    Message {
        category,
        severity,
        message: render(value),
        spans,
    }
}

#[derive(Serialize)]
pub struct PolicyMessage {
    policy_id: String,
    #[serde(flatten)]
    diagnostic: Message,
}

impl PolicyMessage {
    // JSON policy names can carry spans in temporary parser sources.
    pub fn without_spans(mut self) -> Self {
        self.diagnostic.spans.clear();
        self
    }
}

pub fn validation_error(value: &ValidationError) -> PolicyMessage {
    let category = match value {
        ValidationError::UnrecognizedEntityType(_) => "unrecognized_entity_type",
        ValidationError::UnrecognizedActionId(_) => "unrecognized_action_id",
        ValidationError::InvalidActionApplication(_) => "invalid_action_application",
        ValidationError::UnexpectedType(_) => "unexpected_type",
        ValidationError::IncompatibleTypes(_) => "incompatible_types",
        ValidationError::UnsafeAttributeAccess(_) => "unsafe_attribute_access",
        ValidationError::UnsafeOptionalAttributeAccess(_) => "unsafe_optional_attribute_access",
        ValidationError::UnsafeTagAccess(_) => "unsafe_tag_access",
        ValidationError::NoTagsAllowed(_) => "no_tags_allowed",
        ValidationError::UndefinedFunction(_) => "undefined_function",
        ValidationError::WrongNumberArguments(_) => "wrong_number_arguments",
        ValidationError::FunctionArgumentValidation(_) => "function_argument_validation",
        ValidationError::EmptySetForbidden(_) => "empty_set_forbidden",
        ValidationError::NonLitExtConstructor(_) => "non_literal_extension_constructor",
        ValidationError::HierarchyNotRespected(_) => "hierarchy_not_respected",
        ValidationError::InternalInvariantViolation(_) => "internal_invariant_violation",
        ValidationError::EntityDerefLevelViolation(_) => "entity_dereference_level_violation",
        ValidationError::InvalidEnumEntity(_) => "invalid_enum_entity",
        _ => "unknown_validation_error",
    };
    PolicyMessage {
        policy_id: AsRef::<str>::as_ref(value.policy_id()).to_owned(),
        diagnostic: message(value, category, "error"),
    }
}

pub fn validation_warning(value: &ValidationWarning) -> PolicyMessage {
    let category = match value {
        ValidationWarning::MixedScriptString(_) => "mixed_script_string",
        ValidationWarning::BidiCharsInString(_) => "bidi_chars_in_string",
        ValidationWarning::BidiCharsInIdentifier(_) => "bidi_chars_in_identifier",
        ValidationWarning::MixedScriptIdentifier(_) => "mixed_script_identifier",
        ValidationWarning::ConfusableIdentifier(_) => "confusable_identifier",
        ValidationWarning::ImpossiblePolicy(_) => "impossible_policy",
        ValidationWarning::InvalidActionApplication(_) => "invalid_action_application",
        _ => "unknown_validation_warning",
    };
    PolicyMessage {
        policy_id: AsRef::<str>::as_ref(value.policy_id()).to_owned(),
        diagnostic: message(value, category, "warning"),
    }
}

pub fn schema_warning(value: &SchemaWarning) -> Message {
    let category = match value {
        SchemaWarning::ShadowsBuiltin(_) => "shadows_builtin",
        SchemaWarning::ShadowsEntity(_) => "shadows_entity",
        _ => "unknown_schema_warning",
    };
    message(value, category, "warning")
}
