// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_server::auth::provider::AuthProvider;
use lore_server::auth::provider::AuthProviderError;
use lore_server::auth::provider::CallbackParams;
use lore_server::auth::provider::static_provider::*;
use lore_server::auth::session::PendingSession;
use lore_server::auth::session::SessionManager;

fn settings(users: Vec<StaticUserSettings>) -> StaticProviderSettings {
    StaticProviderSettings {
        allow_insecure_dev_login: true,
        users,
    }
}

fn alice() -> StaticUserSettings {
    StaticUserSettings {
        user: "alice".to_string(),
        secret: "s3cret".to_string(),
        name: Some("Alice Example".to_string()),
        email: Some("alice@example.com".to_string()),
    }
}

fn params(pairs: &[(&str, &str)]) -> CallbackParams {
    CallbackParams {
        params: pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    }
}

fn pending_session() -> PendingSession {
    SessionManager::new()
        .create("client-state")
        .expect("create")
}

#[test]
fn refuses_construction_without_opt_in() {
    let settings = StaticProviderSettings {
        allow_insecure_dev_login: false,
        users: vec![alice()],
    };
    assert!(matches!(
        StaticProvider::new(&settings, "http://localhost:8080"),
        Err(StaticProviderError::NotAllowed)
    ));
}

#[test]
fn refuses_construction_without_users() {
    assert!(matches!(
        StaticProvider::new(&settings(vec![]), "http://localhost:8080"),
        Err(StaticProviderError::NoUsers)
    ));
}

#[test]
fn refuses_invalid_callback_base() {
    assert!(matches!(
        StaticProvider::new(&settings(vec![alice()]), "not a url"),
        Err(StaticProviderError::InvalidCallbackBase(_))
    ));
}

#[tokio::test]
async fn begin_login_points_at_dev_login_with_state() {
    let provider =
        StaticProvider::new(&settings(vec![alice()]), "http://localhost:8080").expect("new");
    let session = pending_session();
    let url = provider.begin_login(&session).await.expect("begin");
    assert_eq!(url.path(), "/auth/dev-login");
    assert_eq!(url.host_str(), Some("localhost"));
    let state = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.to_string());
    assert_eq!(state, Some(session.csrf_state.clone()));
}

#[tokio::test]
async fn complete_login_accepts_correct_secret() {
    let provider =
        StaticProvider::new(&settings(vec![alice()]), "http://localhost:8080").expect("new");
    let identity = provider
        .complete_login(
            &pending_session(),
            &params(&[("user", "alice"), ("secret", "s3cret")]),
        )
        .await
        .expect("login");
    assert_eq!(identity.subject, "alice");
    assert_eq!(identity.idp, STATIC_PROVIDER_NAME);
    assert_eq!(identity.user_id(), "static:alice");
    assert_eq!(identity.email.as_deref(), Some("alice@example.com"));
    assert_eq!(identity.display_name.as_deref(), Some("Alice Example"));
}

#[tokio::test]
async fn complete_login_rejects_wrong_secret_and_unknown_user() {
    let provider =
        StaticProvider::new(&settings(vec![alice()]), "http://localhost:8080").expect("new");
    for bad in [
        params(&[("user", "alice"), ("secret", "wrong")]),
        params(&[("user", "mallory"), ("secret", "s3cret")]),
    ] {
        let err = provider
            .complete_login(&pending_session(), &bad)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthProviderError::Denied(_)));
    }
}

#[tokio::test]
async fn complete_login_rejects_missing_parameters() {
    let provider =
        StaticProvider::new(&settings(vec![alice()]), "http://localhost:8080").expect("new");
    for bad in [
        params(&[("user", "alice")]),
        params(&[("secret", "s3cret")]),
        params(&[]),
    ] {
        let err = provider
            .complete_login(&pending_session(), &bad)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthProviderError::Invalid(_)));
    }
}
