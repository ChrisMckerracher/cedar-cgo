//! Generate source token fixtures through the native formatter lexer.
use cedar_policy_formatter::{lexer::get_token_stream, token::Token};
use serde_json::{Value, json};
use std::io::{self, Read};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let cases: Vec<Value> = serde_json::from_str(&input).unwrap();
    let results: Vec<_> = cases.iter().map(|case| {
        let source = case["text"].as_str().unwrap();
        let output = match get_token_stream(source) {
            None => json!({"error": {"kind": "policies", "message": "formatter lexer rejected policy source"}}),
            Some((tokens, comments)) => {
                let tokens: Vec<_> = tokens.iter().map(|token| {
                    let kind = match &token.token {
                        Token::Identifier(_) => "identifier".to_owned(),
                        Token::Number(_) => "number".to_owned(),
                        Token::Str(_) => "string".to_owned(),
                        other => other.to_string(),
                    };
                    json!({
                        "kind": kind, "text": &source[token.span.clone()],
                        "span": {"start": token.span.start, "end": token.span.end},
                        "leading_comments": token.comment.leading_comment(),
                        "trailing_comment": token.comment.trailing_comment(),
                    })
                }).collect();
                json!({"tokens": tokens, "trailing_comments": comments.collect::<Vec<_>>()})
            }
        };
        json!({"name": case["name"], "output": output})
    }).collect();
    println!("{}", serde_json::to_string_pretty(&results).unwrap());
}
