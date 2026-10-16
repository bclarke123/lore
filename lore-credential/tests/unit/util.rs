// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_credential::get_domain_or_empty;
use lore_credential::token_fingerprint;

#[test]
fn a_token_fingerprint_tells_credentials_apart_without_revealing_them() {
    let first = token_fingerprint("an-authentication-token");
    let second = token_fingerprint("a-different-authentication-token");

    assert_ne!(
        first, second,
        "two credentials must not share a fingerprint"
    );
    assert_eq!(
        first,
        token_fingerprint("an-authentication-token"),
        "the same credential must fingerprint the same way"
    );
    assert!(
        !first.contains("an-authentication-token"),
        "the fingerprint must not carry the credential"
    );
    assert_eq!(first.len(), 16);
    assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn no_token_has_no_fingerprint() {
    assert!(token_fingerprint("").is_empty());
}

#[test]
fn an_ip_literal_host_is_the_domain_under_every_scheme() {
    assert_eq!(get_domain_or_empty("http://127.0.0.1:54300"), "127.0.0.1");
    assert_eq!(get_domain_or_empty("lore://127.0.0.1:54303/"), "127.0.0.1");
    assert_eq!(get_domain_or_empty("http://[::1]:1"), "[::1]");
    assert_eq!(
        get_domain_or_empty("https://auth.example.com/path"),
        "auth.example.com"
    );
}
