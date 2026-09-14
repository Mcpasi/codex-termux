use super::*;

#[test]
fn requires_full_context_and_matching_model() {
    assert!(validate_request(br#"{"model":"local","input":[],"stream":true}"#, "local").is_ok());
    assert!(validate_request(br#"{"model":"different","input":[]}"#, "local").is_err());
    assert!(
        validate_request(
            br#"{"model":"local","input":[],"previous_response_id":"old"}"#,
            "local"
        )
        .is_err()
    );
    assert!(validate_request(br#"{"model":"local"}"#, "local").is_err());
    assert!(validate_request(b"{", "local").is_err());
}
