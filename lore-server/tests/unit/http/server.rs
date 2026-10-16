// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use axum::routing::get;
use axum_test::TestServer;
use lore_server::http::security_headers::ContentTypePolicy;
use lore_server::http::security_headers::DEFAULT_ALLOWED_CONTENT_TYPES;
use lore_server::http::server::*;

/// 32 bytes of hex, the minimum `build_presign_config` accepts.
const TEST_HMAC_KEY: &str = "32d0bd7711276da5a4d73e1211ba3884ad1819aa0b4727b8ee5d695e9c3199de";

fn settings_with_policy(policy: ContentTypePolicy) -> PresignSettings {
    PresignSettings {
        hmac_key: Some(TEST_HMAC_KEY.to_string()),
        content_type_policy: policy,
        ..PresignSettings::default()
    }
}

fn types(list: &[&str]) -> Vec<String> {
    list.iter().map(|t| (*t).to_string()).collect()
}

/// The test that catches a settings field added but never threaded into
/// `PresignConfig`.
#[test]
fn build_presign_config_threads_extra_content_types() {
    let config = build_presign_config(&settings_with_policy(ContentTypePolicy {
        extra: types(&["application/zip"]),
        denied: Vec::new(),
    }))
    .expect("config should build")
    .expect("presign should be enabled");

    assert!(config.content_type_allowlist.is_allowed("application/zip"));
    assert!(config.content_type_allowlist.is_allowed("image/png"));
}

#[tokio::test]
async fn presigned_transport_limits_timeout_slow_handlers() {
    let settings = LoreHttpServerSettings {
        request_timeout_seconds: 0,
        ..LoreHttpServerSettings::test_default()
    };
    let router = apply_presigned_transport_limits(
        Router::new().route(
            "/",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(60)).await;
                StatusCode::OK
            }),
        ),
        100,
        &settings,
    );

    let response = TestServer::new(router).unwrap().get("/").await;

    assert_eq!(response.status_code(), StatusCode::REQUEST_TIMEOUT);
}

#[test]
fn build_presign_config_threads_denied_content_types() {
    let config = build_presign_config(&settings_with_policy(ContentTypePolicy {
        extra: Vec::new(),
        denied: types(&["application/pdf"]),
    }))
    .expect("config should build")
    .expect("presign should be enabled");

    assert!(!config.content_type_allowlist.is_allowed("application/pdf"));
}

/// A browser-executable extra type stops the server from starting.
#[test]
fn build_presign_config_rejects_never_allowed_extra_type() {
    let result = build_presign_config(&settings_with_policy(ContentTypePolicy {
        extra: types(&["text/html"]),
        denied: Vec::new(),
    }));

    // Matched rather than `expect_err`, which would need `Debug` on
    // `PresignConfig` for tests alone.
    let Err(error) = result else {
        panic!("startup must fail on a browser-executable extra type");
    };

    assert!(
        error.to_string().contains("text/html"),
        "error must name the type, got: {error}"
    );
}

/// The policy must not accidentally enable the feature.
#[test]
fn build_presign_config_without_hmac_key_is_none() {
    let config = build_presign_config(&PresignSettings {
        hmac_key: None,
        content_type_policy: ContentTypePolicy {
            extra: types(&["application/zip"]),
            denied: Vec::new(),
        },
        ..PresignSettings::default()
    })
    .expect("config should build");

    assert!(config.is_none());
}

/// The derived `Default` must leave the policy empty, so programmatic
/// construction resolves to the built-in set like an absent config key. Sets
/// only `hmac_key`, so the policy comes from `Default` rather than the caller.
#[test]
fn presign_settings_default_resolves_to_builtin_set() {
    let config = build_presign_config(&PresignSettings {
        hmac_key: Some(TEST_HMAC_KEY.to_string()),
        ..PresignSettings::default()
    })
    .expect("config should build")
    .expect("presign should be enabled");

    let mut expected = types(DEFAULT_ALLOWED_CONTENT_TYPES);
    expected.sort_unstable();
    assert_eq!(config.content_type_allowlist.allowed_types(), expected);
}

/// An operator needs to know which of the two lists holds the bad entry.
#[test]
fn build_presign_config_error_names_the_extra_content_types_field() {
    let result = build_presign_config(&settings_with_policy(ContentTypePolicy {
        extra: types(&["text/html"]),
        denied: Vec::new(),
    }));

    let Err(error) = result else {
        panic!("startup must fail on a browser-executable extra type");
    };
    assert!(
        error
            .to_string()
            .contains("presigned_url_extra_content_types"),
        "error must name the field, got: {error}"
    );
}

#[test]
fn build_presign_config_error_names_the_denied_content_types_field() {
    let result = build_presign_config(&settings_with_policy(ContentTypePolicy {
        extra: Vec::new(),
        denied: types(&["image/png,image/gif"]),
    }));

    let Err(error) = result else {
        panic!("startup must fail on a malformed denied entry");
    };
    assert!(
        error
            .to_string()
            .contains("presigned_url_denied_content_types"),
        "error must name the field, got: {error}"
    );
}

/// An empty set would otherwise render as nothing at all in the startup log.
#[test]
fn describe_allowed_types_marks_an_empty_set() {
    assert_eq!(describe_allowed_types(&[]), "<none>");
}

#[test]
fn describe_allowed_types_joins_the_set() {
    assert_eq!(
        describe_allowed_types(&types(&["image/png", "text/plain"])),
        "image/png, text/plain"
    );
}
