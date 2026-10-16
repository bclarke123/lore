// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::time::Duration;

use lore_server::auth::session::*;

fn minted() -> MintedLogin {
    MintedLogin {
        token: "tok".to_string(),
        user_id: "static:alice".to_string(),
        user_name: "Alice".to_string(),
        expires_at_ms: 1000,
        refresh_token: None,
    }
}

#[test]
fn create_then_poll_is_pending() {
    let manager = SessionManager::new();
    let session = manager.create("cs-1").expect("create");
    assert_eq!(
        manager
            .take_if_ready(&session.session_code, "cs-1")
            .expect("poll"),
        None
    );
}

#[test]
fn complete_then_poll_returns_token_once() {
    let manager = SessionManager::new();
    let session = manager.create("cs-1").expect("create");
    manager
        .complete_by_state(&session.csrf_state, Ok(minted()))
        .expect("complete");

    let token = manager
        .take_if_ready(&session.session_code, "cs-1")
        .expect("poll")
        .expect("token ready");
    assert_eq!(token, minted());

    // One-shot: the session is consumed.
    assert_eq!(
        manager.take_if_ready(&session.session_code, "cs-1"),
        Err(SessionError::NotFound)
    );
}

#[test]
fn poll_with_wrong_client_state_is_rejected() {
    let manager = SessionManager::new();
    let session = manager.create("cs-1").expect("create");
    manager
        .complete_by_state(&session.csrf_state, Ok(minted()))
        .expect("complete");
    assert_eq!(
        manager.take_if_ready(&session.session_code, "other-client"),
        Err(SessionError::ClientStateMismatch)
    );
    // The mismatch did not consume the session.
    assert!(
        manager
            .take_if_ready(&session.session_code, "cs-1")
            .expect("poll")
            .is_some()
    );
}

#[test]
fn unknown_session_and_state_are_not_found() {
    let manager = SessionManager::new();
    assert_eq!(
        manager.take_if_ready("nope", "cs"),
        Err(SessionError::NotFound)
    );
    assert_eq!(
        manager.for_callback_state("nope").unwrap_err(),
        SessionError::NotFound
    );
    assert_eq!(
        manager.complete_by_state("nope", Ok(minted())).unwrap_err(),
        SessionError::NotFound
    );
}

#[test]
fn second_callback_for_same_state_is_rejected() {
    let manager = SessionManager::new();
    let session = manager.create("cs-1").expect("create");
    manager
        .complete_by_state(&session.csrf_state, Ok(minted()))
        .expect("first callback");
    assert_eq!(
        manager
            .complete_by_state(&session.csrf_state, Ok(minted()))
            .unwrap_err(),
        SessionError::AlreadyCompleted
    );
    assert_eq!(
        manager.for_callback_state(&session.csrf_state).unwrap_err(),
        SessionError::AlreadyCompleted
    );
}

#[test]
fn failed_login_is_reported_and_consumed() {
    let manager = SessionManager::new();
    let session = manager.create("cs-1").expect("create");
    manager
        .complete_by_state(&session.csrf_state, Err("denied".to_string()))
        .expect("complete");
    assert_eq!(
        manager.take_if_ready(&session.session_code, "cs-1"),
        Err(SessionError::LoginFailed("denied".to_string()))
    );
    assert_eq!(
        manager.take_if_ready(&session.session_code, "cs-1"),
        Err(SessionError::NotFound)
    );
}

#[test]
fn expired_sessions_are_purged() {
    let manager = SessionManager::new();
    let session = manager.create("cs-1").expect("create");
    manager.age_session(&session.session_code, SESSION_TTL + Duration::from_secs(1));
    assert_eq!(
        manager.take_if_ready(&session.session_code, "cs-1"),
        Err(SessionError::NotFound)
    );
    assert_eq!(
        manager.for_callback_state(&session.csrf_state).unwrap_err(),
        SessionError::NotFound
    );
}

#[test]
fn sessions_have_unique_codes_and_states() {
    let manager = SessionManager::new();
    let first = manager.create("cs-1").expect("create");
    let second = manager.create("cs-1").expect("create");
    assert_ne!(first.session_code, second.session_code);
    assert_ne!(first.csrf_state, second.csrf_state);
    assert_ne!(first.pkce_verifier, second.pkce_verifier);
    assert_ne!(first.nonce, second.nonce);
    assert_ne!(first.user_code, second.user_code);
}

#[test]
fn user_code_resolves_pending_session_insensitively() {
    let manager = SessionManager::new();
    let session = manager.create("cs-1").expect("create");
    assert_eq!(session.user_code.len(), 9, "XXXX-XXXX");

    let typed = session.user_code.to_lowercase().replace('-', "");
    let found = manager.for_user_code(&typed).expect("lookup");
    assert_eq!(found.session_code, session.session_code);

    assert_eq!(
        manager.for_user_code("XXXX-XXXX").unwrap_err(),
        SessionError::NotFound
    );

    // A completed session no longer answers to its user code.
    manager
        .complete_by_state(&session.csrf_state, Ok(minted()))
        .expect("complete");
    assert_eq!(
        manager.for_user_code(&session.user_code).unwrap_err(),
        SessionError::AlreadyCompleted
    );
    manager
        .take_if_ready(&session.session_code, "cs-1")
        .expect("consume");
    assert_eq!(
        manager.for_user_code(&session.user_code).unwrap_err(),
        SessionError::NotFound
    );
}
