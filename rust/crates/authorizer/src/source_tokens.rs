use cedar_policy_formatter::{lexer::get_token_stream, token::Token};
use cgw_abi::{OpError, parse_input};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    text: String,
}

#[derive(Serialize)]
struct Span {
    start: usize,
    end: usize,
}

#[derive(Serialize)]
struct SourceToken<'a> {
    kind: String,
    text: &'a str,
    span: Span,
    leading_comments: Vec<&'a str>,
    trailing_comment: &'a str,
}

#[derive(Serialize)]
struct Output<'a> {
    tokens: Vec<SourceToken<'a>>,
    trailing_comments: Vec<&'a str>,
}

pub fn execute(bytes: &[u8]) -> Result<serde_json::Value, OpError> {
    let input: Input = parse_input(bytes)?;
    let (tokens, trailing_comments) = get_token_stream(&input.text)
        .ok_or_else(|| OpError::msg("policies", "formatter lexer rejected policy source"))?;
    let tokens = tokens
        .into_iter()
        .map(|token| {
            let kind = match &token.token {
                Token::Identifier(_) => "identifier".to_owned(),
                Token::Number(_) => "number".to_owned(),
                Token::Str(_) => "string".to_owned(),
                Token::Whitespace | Token::Comment => {
                    return Err(OpError::msg(
                        "internal",
                        "formatter returned a skipped token",
                    ));
                }
                other => other.to_string(),
            };
            let text = input.text.get(token.span.clone()).ok_or_else(|| {
                OpError::msg("internal", "formatter returned an invalid token span")
            })?;
            Ok(SourceToken {
                kind,
                text,
                span: Span {
                    start: token.span.start,
                    end: token.span.end,
                },
                leading_comments: token.comment.leading_comment().to_vec(),
                trailing_comment: token.comment.trailing_comment(),
            })
        })
        .collect::<Result<Vec<_>, OpError>>()?;
    serde_json::to_value(Output {
        tokens,
        trailing_comments: trailing_comments.collect(),
    })
    .map_err(|e| OpError::msg("internal", e.to_string()))
}
