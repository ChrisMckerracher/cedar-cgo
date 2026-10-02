use cedar_policy::PolicySet;
use cedar_policy_formatter::{Config, policies_str_to_pretty};
use cgw_abi::{OpError, diagnostics::Diagnostic, parse_input, run, take_input};
use serde::{Deserialize, Serialize};
use std::fmt::Write;
use std::str::FromStr;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FormatInput {
    text: String,
    line_width: u32,
    indent_width: i32,
    max_output_bytes: u32,
}

#[derive(Serialize)]
struct FormatOutput {
    formatted: String,
}

fn format(bytes: &[u8]) -> Result<FormatOutput, OpError> {
    let input: FormatInput = parse_input(bytes)?;
    if input.max_output_bytes == 0 || input.max_output_bytes > 16 << 20 {
        return Err(OpError::msg("input", "invalid format output limit"));
    }
    let config = Config {
        line_width: input.line_width as usize,
        indent_width: input.indent_width as isize,
    };
    let formatted = policies_str_to_pretty(&input.text, &config).map_err(|err| {
        // Recover structured parser diagnostics hidden by the formatter's context wrapper.
        match PolicySet::from_str(&input.text) {
            Err(errors) => {
                let mut message = String::new();
                for error in errors.iter() {
                    if !message.is_empty() {
                        message.push_str("; ");
                    }
                    message.push_str(&cgw_abi::diagnostics::render(error));
                    if let Some(labels) = error.labels() {
                        for label in labels {
                            let _ = write!(
                                message,
                                " [bytes {}..{}",
                                label.offset(),
                                label.offset() + label.len()
                            );
                            if let Some(text) = label.label() {
                                let _ = write!(message, ": {text}");
                            }
                            message.push(']');
                        }
                    }
                }
                OpError::msg("policies", message)
            }
            Ok(_) => OpError::msg("internal", format!("formatter: {err:#}")),
        }
    })?;
    if formatted.len() > input.max_output_bytes as usize {
        return Err(OpError::msg(
            "limit",
            format!(
                "formatted output is {} bytes, above the limit of {}",
                formatted.len(),
                input.max_output_bytes
            ),
        ));
    }
    Ok(FormatOutput { formatted })
}

/// Formats policy and template text without loading authorization state.
///
/// # Safety
/// `ptr` and `len` must come from one `cgw_alloc(len)` call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cgw_format(ptr: u32, len: u32) -> u64 {
    // SAFETY: the host passes a buffer from `cgw_alloc(len)`.
    run(unsafe { take_input(ptr, len) }, format)
}
