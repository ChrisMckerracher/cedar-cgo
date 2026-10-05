use cedar_policy_formatter::{lexer::get_token_stream, token::Token};
use cgw_abi::OpError;

pub(super) fn check(text: &str, indent_width: i32, max_output_bytes: u32) -> Result<(), OpError> {
    if i64::from(indent_width) > i64::from(max_output_bytes) {
        return Err(OpError::msg(
            "limit",
            "format indentation exceeds the output byte limit",
        ));
    }
    // The upstream formatter recurses before its output exists; bound nesting before native entry.
    if let Some((tokens, _)) = get_token_stream(text) {
        let mut depth = 0_usize;
        for token in tokens {
            match token.token {
                Token::LParen | Token::LBrace | Token::LBracket => depth += 1,
                Token::RParen | Token::RBrace | Token::RBracket => depth = depth.saturating_sub(1),
                _ => (),
            }
            if depth > 256 {
                return Err(OpError::msg(
                    "limit",
                    "format nesting exceeds 256 delimiters",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_indentation_and_nesting_are_bounded_before_formatting() {
        assert_eq!(
            check("permit(principal,action,resource);", i32::MAX, 16 << 20)
                .unwrap_err()
                .kind,
            "limit"
        );
        let nested = format!(
            "permit(principal,action,resource)when{{{}true{}}};",
            "(".repeat(800),
            ")".repeat(800)
        );
        assert_eq!(check(&nested, 2, 16 << 20).unwrap_err().kind, "limit");
    }

    #[test]
    fn strings_comments_and_negative_indentation_retain_upstream_behavior() {
        let harmless = format!(
            "//{}\npermit(principal,action,resource)when{{context.label == \"{}\"}};",
            "(".repeat(800),
            "(".repeat(800)
        );
        assert!(check(&harmless, -2, 100).is_ok());
    }
}
