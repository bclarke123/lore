// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_proto::auth::urc_auth_api_server::UrcAuthApi;
use lore_proto::rebac::rebac_api_server::RebacApi;
use lore_server::auth::local_auth::LocalAuth;
use lore_server::auth::provider::CallbackParams;
use lore_server::grpc::auth_service::*;
use tonic::Request;

fn service() -> (LoreAuthService, Arc<LocalAuth>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let settings = crate::auth::local_auth::test_auth_settings(dir.path());
    let auth = Arc::new(
        LocalAuth::from_settings(Some(&settings))
            .expect("build")
            .expect("enabled"),
    );
    (LoreAuthService::new(auth.clone()), auth, dir)
}

fn callback(pairs: &[(&str, &str)]) -> CallbackParams {
    CallbackParams {
        params: pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    }
}

async fn login(service: &LoreAuthService, auth: &LocalAuth) -> lore_proto::auth::UserToken {
    let started = service
        .start_auth_session(Request::new(lore_proto::auth::StartAuthSessionRequest {
            client_state: "client-1".to_string(),
        }))
        .await
        .expect("start")
        .into_inner();

    // Simulate the browser flow.
    let session = auth
        .sessions
        .for_callback_state(
            url::Url::parse(&started.login_url)
                .expect("login url")
                .query_pairs()
                .find(|(k, _)| k == "state")
                .map(|(_, v)| v.to_string())
                .expect("state param")
                .as_str(),
        )
        .expect("session");
    auth.complete_login(callback(&[
        ("state", &session.csrf_state),
        ("user", "alice"),
        ("secret", "s3cret"),
    ]))
    .await
    .expect("complete");

    service
        .get_auth_session(Request::new(lore_proto::auth::GetAuthSessionRequest {
            session_code: started.session_code,
            client_state: "client-1".to_string(),
        }))
        .await
        .expect("poll")
        .into_inner()
        .user_token
        .expect("token ready")
}

fn authed_request<T>(payload: T, token: &str) -> Request<T> {
    let mut request = Request::new(payload);
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {token}").parse().expect("metadata"),
    );
    request
}

#[tokio::test]
async fn start_and_poll_full_flow() {
    let (service, auth, _dir) = service();
    let token = login(&service, &auth).await;
    assert_eq!(token.user_id, "static:alice");
    assert_eq!(token.user_name, "Alice");
    assert!(!token.user_token.is_empty());
    assert!(token.expires_at > 0);
}

#[tokio::test]
async fn start_rejects_empty_client_state() {
    let (service, _auth, _dir) = service();
    let err = service
        .start_auth_session(Request::new(lore_proto::auth::StartAuthSessionRequest {
            client_state: String::new(),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn poll_pending_session_returns_empty() {
    let (service, _auth, _dir) = service();
    let started = service
        .start_auth_session(Request::new(lore_proto::auth::StartAuthSessionRequest {
            client_state: "client-1".to_string(),
        }))
        .await
        .expect("start")
        .into_inner();
    let polled = service
        .get_auth_session(Request::new(lore_proto::auth::GetAuthSessionRequest {
            session_code: started.session_code,
            client_state: "client-1".to_string(),
        }))
        .await
        .expect("poll")
        .into_inner();
    assert!(polled.user_token.is_none());
}

#[tokio::test]
async fn poll_unknown_session_is_not_found() {
    let (service, _auth, _dir) = service();
    let err = service
        .get_auth_session(Request::new(lore_proto::auth::GetAuthSessionRequest {
            session_code: "bogus".to_string(),
            client_state: "client-1".to_string(),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn poll_with_wrong_client_state_is_denied() {
    let (service, _auth, _dir) = service();
    let started = service
        .start_auth_session(Request::new(lore_proto::auth::StartAuthSessionRequest {
            client_state: "client-1".to_string(),
        }))
        .await
        .expect("start")
        .into_inner();
    let err = service
        .get_auth_session(Request::new(lore_proto::auth::GetAuthSessionRequest {
            session_code: started.session_code,
            client_state: "other".to_string(),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn exchange_requires_valid_token() {
    let (service, _auth, _dir) = service();
    let payload = lore_proto::auth::ExchangeUserTokenForMultiresourceTokenRequest {
        resource_id: vec!["urc-00000000000000000000000000000000".to_string()],
    };

    let err = service
        .exchange_user_token_for_multiresource_token(Request::new(payload.clone()))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);

    let err = service
        .exchange_user_token_for_multiresource_token(authed_request(payload, "garbage"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn exchange_mints_verifiable_authz_token() {
    let (service, auth, _dir) = service();
    let user_token = login(&service, &auth).await;

    let resource = "urc-00000000000000000000000000000000".to_string();
    let exchanged = service
        .exchange_user_token_for_multiresource_token(authed_request(
            lore_proto::auth::ExchangeUserTokenForMultiresourceTokenRequest {
                resource_id: vec![resource.clone()],
            },
            &user_token.user_token,
        ))
        .await
        .expect("exchange")
        .into_inner()
        .token
        .expect("token");

    let claims = auth
        .verifier
        .verify_token(&exchanged.user_token)
        .await
        .expect("verify");
    let resources = claims.resources.expect("resources claim");
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0].resource_id, resource);
    assert_eq!(resources[0].permission, vec!["read", "write"]);
}

#[tokio::test]
async fn exchange_rejects_empty_resource_list() {
    let (service, auth, _dir) = service();
    let user_token = login(&service, &auth).await;
    let err = service
        .exchange_user_token_for_multiresource_token(authed_request(
            lore_proto::auth::ExchangeUserTokenForMultiresourceTokenRequest {
                resource_id: vec![],
            },
            &user_token.user_token,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn permission_checks_answer_permissively_for_authenticated_users() {
    let (service, auth, _dir) = service();
    let user_token = login(&service, &auth).await;

    let checked = service
        .check_user_permission(authed_request(
            lore_proto::auth::CheckUserPermissionRequest {
                resource_id: vec!["urc-abc".to_string()],
                target_user: None,
            },
            &user_token.user_token,
        ))
        .await
        .expect("check")
        .into_inner();
    assert_eq!(checked.allowed_resource_permission.len(), 1);
    assert!(checked.denied_resource_permission.is_empty());

    let lookup = service
        .lookup_user_permissions(authed_request(
            lore_proto::auth::LookupUserPermissionsRequest {
                resource_filter: "urc".to_string(),
                context_filter: None,
                page_size: None,
                page_token: None,
            },
            &user_token.user_token,
        ))
        .await
        .expect("lookup")
        .into_inner();
    assert_eq!(lookup.resource_permission[0].resource_id, "urc-*");

    // Unauthenticated callers are refused.
    let err = service
        .check_user_permission(Request::new(lore_proto::auth::CheckUserPermissionRequest {
            resource_id: vec!["urc-abc".to_string()],
            target_user: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn get_user_info_resolves_caller_display_name() {
    let (service, auth, _dir) = service();
    let user_token = login(&service, &auth).await;

    let info = service
        .get_user_info(authed_request(
            lore_proto::auth::GetUserInfoRequest {
                resource_id: "urc-abc".to_string(),
                user_id: vec!["static:alice".to_string(), "static:bob".to_string()],
            },
            &user_token.user_token,
        ))
        .await
        .expect("info")
        .into_inner();
    assert_eq!(info.user_info[0].display_name, "Alice");
    assert_eq!(info.user_info[1].display_name, "static:bob");
}

#[tokio::test]
async fn external_exchange_gating() {
    let (service, _auth, _dir) = service();

    // Static provider: inherits the trait default → Unimplemented.
    let err = service
        .exchange_external_token_for_user_token(Request::new(
            lore_proto::auth::ExchangeExternalTokenForUserTokenRequest {
                external_token: "some-token".to_string(),
                token_type: "google-id-token".to_string(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unimplemented);

    // Unknown token type refused before touching the provider.
    let err = service
        .exchange_external_token_for_user_token(Request::new(
            lore_proto::auth::ExchangeExternalTokenForUserTokenRequest {
                external_token: "some-token".to_string(),
                token_type: "eg1".to_string(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    // Empty token refused.
    let err = service
        .exchange_external_token_for_user_token(Request::new(
            lore_proto::auth::ExchangeExternalTokenForUserTokenRequest {
                external_token: String::new(),
                token_type: "google-id-token".to_string(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn external_exchange_mints_verifiable_token() {
    use crate::auth::provider::oidc::test_support;

    // LocalAuth wired to an OIDC provider (mock backend) that trusts
    // the hub's client id for external exchange.
    let dir = tempfile::tempdir().expect("tempdir");
    let settings = crate::auth::local_auth::test_auth_settings(dir.path());
    let base = LocalAuth::from_settings(Some(&settings))
        .expect("build")
        .expect("enabled");
    let mut config = test_support::config();
    config.trusted_external_audiences = vec!["lorehub-client-id".to_string()];
    let auth = Arc::new(base.with_provider(Arc::new(
        lore_server::auth::provider::oidc::OidcProvider::new(
            config,
            Arc::new(test_support::MockBackend::new()),
        ),
    )));
    let service = LoreAuthService::new(auth.clone());

    // A hub-obtained ID token: aud = hub client id, no nonce.
    let mut claims = test_support::valid_claims("unused");
    claims["aud"] = "lorehub-client-id".into();
    claims.as_object_mut().expect("object").remove("nonce");

    let response = service
        .exchange_external_token_for_user_token(Request::new(
            lore_proto::auth::ExchangeExternalTokenForUserTokenRequest {
                external_token: test_support::id_token(&claims),
                token_type: "google-id-token".to_string(),
            },
        ))
        .await
        .expect("exchange")
        .into_inner()
        .user_token
        .expect("token");

    assert_eq!(response.user_id, "test-oidc:google-subject-1");
    let verified = auth
        .verifier
        .verify_token(&response.user_token)
        .await
        .expect("verify minted token");
    assert_eq!(verified.user_id, "test-oidc:google-subject-1");
    assert_eq!(verified.idp.as_deref(), Some("test-oidc"));
    assert_eq!(verified.resources, None);
}

#[tokio::test]
async fn rebac_noop_requires_authentication() {
    let (service, auth, _dir) = service();
    let user_token = login(&service, &auth).await;
    let rebac = LoreRebacService::new(auth.clone());

    rebac
        .create_resource(authed_request(
            lore_proto::rebac::CreateResourceRequest {
                resource_id: "urc-abc".to_string(),
                resource_name: "repo".to_string(),
            },
            &user_token.user_token,
        ))
        .await
        .expect("create");

    let err = rebac
        .delete_resource(Request::new(lore_proto::rebac::DeleteResourceRequest {
            resource_id: "urc-abc".to_string(),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}
