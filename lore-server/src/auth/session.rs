// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! In-process pending-login sessions for the server-local auth service.
//!
//! A [`PendingSession`] is created by `StartAuthSession`, completed by the
//! HTTP auth callback once the identity provider verifies the user, and
//! consumed (one-shot) by `GetAuthSession` polling. Sessions are short-lived
//! and node-local: losing them on restart only means the user retries
//! `lore auth login`.

use std::collections::HashMap;
use std::time::Duration;
use std::time::Instant;

use parking_lot::Mutex;
use thiserror::Error;
use uuid::Uuid;

/// How long a login session may stay pending before it expires. Generous
/// enough for a first-time provider consent screen.
const SESSION_TTL: Duration = Duration::from_secs(10 * 60);

/// Upper bound on concurrently pending sessions. Purely a memory backstop;
/// expired sessions are purged lazily on every access.
const MAX_PENDING_SESSIONS: usize = 4096;

#[derive(Debug, Error, PartialEq)]
pub enum SessionError {
    #[error("Unknown or expired login session")]
    NotFound,
    #[error("Login session does not belong to this client")]
    ClientStateMismatch,
    #[error("Login session already completed")]
    AlreadyCompleted,
    #[error("Too many pending login sessions")]
    Exhausted,
    #[error("Login failed: {0}")]
    LoginFailed(String),
}

/// A token minted for a completed login, ready to hand to the polling client.
#[derive(Debug, Clone, PartialEq)]
pub struct MintedLogin {
    pub token: String,
    pub user_id: String,
    pub user_name: String,
    /// Milliseconds since the UNIX epoch, matching Lore's timestamp
    /// convention on the wire.
    pub expires_at_ms: i64,
    pub refresh_token: Option<String>,
}

/// A login attempt awaiting completion by the browser flow.
#[derive(Debug, Clone)]
pub struct PendingSession {
    /// Opaque handle the CLI polls with.
    pub session_code: String,
    /// Client-chosen value echoed back on poll; binds the session to the
    /// CLI instance that started it.
    pub client_state: String,
    /// Single-use CSRF value carried through the provider redirect as the
    /// OAuth `state` parameter.
    pub csrf_state: String,
    /// PKCE code verifier (S256), generated for every session; OIDC
    /// providers use it, others ignore it.
    pub pkce_verifier: String,
    /// OIDC replay-protection nonce, generated for every session.
    pub nonce: String,
    created: Instant,
}

impl PendingSession {
    fn expired(&self, now: Instant) -> bool {
        now.duration_since(self.created) > SESSION_TTL
    }
}

struct SessionEntry {
    session: PendingSession,
    outcome: Option<Result<MintedLogin, String>>,
}

#[derive(Default)]
struct SessionMap {
    /// Keyed by `session_code`.
    by_code: HashMap<String, SessionEntry>,
    /// `csrf_state` → `session_code` index for callback resolution.
    by_state: HashMap<String, String>,
}

/// Thread-safe store of pending login sessions.
#[derive(Default)]
pub struct SessionManager {
    sessions: Mutex<SessionMap>,
}

/// Random URL-safe value with 128 bits of entropy.
fn random_value() -> String {
    Uuid::new_v4().simple().to_string()
}

impl SessionManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new pending session for a client-supplied `client_state`.
    pub fn create(&self, client_state: &str) -> Result<PendingSession, SessionError> {
        let session = PendingSession {
            session_code: random_value(),
            client_state: client_state.to_string(),
            csrf_state: random_value(),
            pkce_verifier: random_value(),
            nonce: random_value(),
            created: Instant::now(),
        };

        let mut map = self.sessions.lock();
        Self::purge_expired(&mut map);
        if map.by_code.len() >= MAX_PENDING_SESSIONS {
            return Err(SessionError::Exhausted);
        }
        map.by_state
            .insert(session.csrf_state.clone(), session.session_code.clone());
        map.by_code.insert(
            session.session_code.clone(),
            SessionEntry {
                session: session.clone(),
                outcome: None,
            },
        );
        Ok(session)
    }

    /// Resolve the pending session for a callback's `state` parameter.
    ///
    /// Returns a clone; the session stays pending until
    /// [`complete_by_state`](Self::complete_by_state) records an outcome.
    pub fn for_callback_state(&self, csrf_state: &str) -> Result<PendingSession, SessionError> {
        let mut map = self.sessions.lock();
        Self::purge_expired(&mut map);
        let code = map.by_state.get(csrf_state).ok_or(SessionError::NotFound)?;
        let entry = map.by_code.get(code).ok_or(SessionError::NotFound)?;
        if entry.outcome.is_some() {
            return Err(SessionError::AlreadyCompleted);
        }
        Ok(entry.session.clone())
    }

    /// Record the outcome of the browser flow for the session identified by
    /// its CSRF `state`. Each session accepts exactly one outcome; a second
    /// callback for the same `state` is rejected.
    pub fn complete_by_state(
        &self,
        csrf_state: &str,
        outcome: Result<MintedLogin, String>,
    ) -> Result<(), SessionError> {
        let mut map = self.sessions.lock();
        Self::purge_expired(&mut map);
        let code = map
            .by_state
            .get(csrf_state)
            .ok_or(SessionError::NotFound)?
            .clone();
        let entry = map.by_code.get_mut(&code).ok_or(SessionError::NotFound)?;
        if entry.outcome.is_some() {
            return Err(SessionError::AlreadyCompleted);
        }
        entry.outcome = Some(outcome);
        Ok(())
    }

    /// Poll a session by code. Returns `Ok(None)` while the browser flow is
    /// still in progress. On a recorded outcome the session is consumed:
    /// success yields the minted token exactly once, failure yields
    /// [`SessionError::LoginFailed`].
    pub fn take_if_ready(
        &self,
        session_code: &str,
        client_state: &str,
    ) -> Result<Option<MintedLogin>, SessionError> {
        let mut map = self.sessions.lock();
        Self::purge_expired(&mut map);
        let entry = map
            .by_code
            .get(session_code)
            .ok_or(SessionError::NotFound)?;
        if entry.session.client_state != client_state {
            return Err(SessionError::ClientStateMismatch);
        }
        if entry.outcome.is_none() {
            return Ok(None);
        }

        // Outcome is present: consume the session either way.
        let entry = map
            .by_code
            .remove(session_code)
            .ok_or(SessionError::NotFound)?;
        map.by_state.remove(&entry.session.csrf_state);
        match entry.outcome {
            Some(Ok(minted)) => Ok(Some(minted)),
            Some(Err(reason)) => Err(SessionError::LoginFailed(reason)),
            None => Ok(None),
        }
    }

    fn purge_expired(map: &mut SessionMap) {
        let now = Instant::now();
        let expired: Vec<String> = map
            .by_code
            .iter()
            .filter(|(_, entry)| entry.session.expired(now))
            .map(|(code, _)| code.clone())
            .collect();
        for code in expired {
            if let Some(entry) = map.by_code.remove(&code) {
                map.by_state.remove(&entry.session.csrf_state);
            }
        }
    }

    #[cfg(test)]
    fn age_session(&self, session_code: &str, by: Duration) {
        let mut map = self.sessions.lock();
        if let Some(entry) = map.by_code.get_mut(session_code) {
            entry.session.created = Instant::now() - by;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }
}
