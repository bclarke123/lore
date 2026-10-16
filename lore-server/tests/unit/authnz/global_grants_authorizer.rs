// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_base::types::RepositoryId;
use lore_server::auth::jwt::AuthorizationToken;
use lore_server::authnz::global_grants_authorizer::*;
use lore_server::authnz::repository_authorizer::RepositoryAuthorizer;
use lore_server::authnz::repository_authorizer::VerifiedToken;
use serde_json::json;
use tonic::Code;
use tonic::Status;

fn token_with_extra(extra: serde_json::Value) -> AuthorizationToken {
    let serde_json::Value::Object(extra) = extra else {
        panic!("extra claims must be a JSON object");
    };
    AuthorizationToken {
        user_id: "the u".to_string(),
        extra,
        ..Default::default()
    }
}

async fn check(
    authorizer: &GlobalGrantsAuthorizer,
    claims: &AuthorizationToken,
    repository_id: RepositoryId,
    action: Option<&str>,
) -> Result<(), Status> {
    let token = VerifiedToken { raw: "raw", claims };
    authorizer
        .check_repository_access(Some(&token), repository_id, action)
        .await
}

#[tokio::test]
async fn nested_claim_grants_the_action_on_any_partition() {
    let authorizer = GlobalGrantsAuthorizer::new(Some("realm_access.roles".to_string()));
    let claims = token_with_extra(json!({
        "realm_access": { "roles": ["obliterate"] }
    }));
    for repository in [RepositoryId::default(), RepositoryId::from([7u8; 16])] {
        check(&authorizer, &claims, repository, Some("obliterate"))
            .await
            .unwrap();
        let err = check(&authorizer, &claims, repository, Some("admin"))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
    }
}

#[tokio::test]
async fn flat_claim_grants_the_action_on_any_partition() {
    // Dex emits its grants as a flat `groups` claim.
    let authorizer = GlobalGrantsAuthorizer::new(Some("groups".to_string()));
    let claims = AuthorizationToken {
        groups: Some(vec!["obliterate".to_string()]),
        ..Default::default()
    };
    check(
        &authorizer,
        &claims,
        RepositoryId::default(),
        Some("obliterate"),
    )
    .await
    .unwrap();
    let err = check(&authorizer, &claims, RepositoryId::default(), Some("admin"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
}

#[tokio::test]
async fn no_permission_claim_permits_plain_access_and_denies_every_action() {
    let authorizer = GlobalGrantsAuthorizer::new(None);
    let claims = token_with_extra(json!({
        "realm_access": { "roles": ["obliterate"] }
    }));
    check(&authorizer, &claims, RepositoryId::default(), None)
        .await
        .unwrap();
    for action in ["obliterate", "admin", "presign"] {
        let err = check(&authorizer, &claims, RepositoryId::default(), Some(action))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
    }
}

#[tokio::test]
async fn named_action_permits_plain_access_too() {
    let authorizer = GlobalGrantsAuthorizer::new(Some("groups".to_string()));
    let claims = token_with_extra(json!({ "groups": ["obliterate"] }));
    check(&authorizer, &claims, RepositoryId::default(), None)
        .await
        .unwrap();
}

#[tokio::test]
async fn non_string_values_are_ignored_rather_than_panicking() {
    // `roles` is not a named field, so these shapes reach the reader
    // as-is instead of being shadowed by a typed field.
    let authorizer = GlobalGrantsAuthorizer::new(Some("roles".to_string()));
    // A whole claim of the wrong shape denies.
    for wrong_shape in [
        json!({ "roles": "obliterate" }),
        json!({ "roles": 42 }),
        json!({ "roles": { "obliterate": true } }),
    ] {
        let claims = token_with_extra(wrong_shape);
        let err = check(
            &authorizer,
            &claims,
            RepositoryId::default(),
            Some("obliterate"),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
    }
    // Non-string entries inside the array are skipped, not fatal.
    let claims = token_with_extra(json!({ "roles": [1, null, "obliterate"] }));
    check(
        &authorizer,
        &claims,
        RepositoryId::default(),
        Some("obliterate"),
    )
    .await
    .unwrap();
}

/// The verdict is in the token, so the sync check always answers and
/// agrees with the async one.
#[tokio::test]
async fn sync_check_answers_and_agrees_with_the_async_path() {
    let authorizer = GlobalGrantsAuthorizer::new(Some("groups".to_string()));
    let claims = token_with_extra(json!({ "groups": ["obliterate"] }));
    let token = VerifiedToken {
        raw: "raw",
        claims: &claims,
    };
    for token in [None, Some(&token)] {
        for action in [None, Some("obliterate"), Some("admin")] {
            let sync = authorizer
                .check_repository_access_sync(token, RepositoryId::default(), action)
                .expect("the token holds the verdict");
            let asynchronous = authorizer
                .check_repository_access(token, RepositoryId::default(), action)
                .await;
            assert_eq!(sync.is_ok(), asynchronous.is_ok(), "{action:?}");
        }
    }
}

#[tokio::test]
async fn no_token_denies_even_plain_access() {
    let authorizer = GlobalGrantsAuthorizer::new(Some("groups".to_string()));
    for action in [None, Some("obliterate")] {
        let err = authorizer
            .check_repository_access(None, RepositoryId::default(), action)
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::Unauthenticated);
    }
}
