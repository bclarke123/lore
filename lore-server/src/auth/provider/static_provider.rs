// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Configuration-driven identity provider for development and testing.
//!
//! Users and shared secrets come from server settings. The login URL points
//! at the server's own dev-login page, and `complete_login` verifies the
//! submitted secret. This provider transmits shared secrets over the auth
//! callback and MUST NOT be used in production; construction fails unless
//! the configuration opts in explicitly with `allow_insecure_dev_login`.

use async_trait::async_trait;
use serde::Deserialize;
use thiserror::Error;
use url::Url;

use super::AuthProvider;
use super::AuthProviderError;
use super::CallbackParams;
use super::ExternalIdentity;
use crate::auth::session::PendingSession;

pub const STATIC_PROVIDER_NAME: &str = "static";

#[derive(Clone, Debug, Deserialize)]
pub struct StaticUserSettings {
    pub user: String,
    pub secret: String,
    pub name: Option<String>,
    pub email: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct StaticProviderSettings {
    /// Explicit opt-in acknowledging that this provider sends shared
    /// secrets through the auth callback. Refuses to start without it.
    #[serde(default)]
    pub allow_insecure_dev_login: bool,
    #[serde(default)]
    pub users: Vec<StaticUserSettings>,
}

#[derive(Debug, Error)]
pub enum StaticProviderError {
    #[error(
        "the static auth provider is insecure (secrets travel through the login callback); \
         set allow_insecure_dev_login = true to acknowledge this for development use"
    )]
    NotAllowed,
    #[error("the static auth provider has no users configured")]
    NoUsers,
    #[error("invalid callback base URL: {0}")]
    InvalidCallbackBase(String),
}

pub struct StaticProvider {
    users: Vec<StaticUserSettings>,
    dev_login_url: Url,
}

impl StaticProvider {
    /// `callback_base_url` is the externally reachable base of the server's
    /// HTTP endpoint, e.g. `http://localhost:8080`.
    pub fn new(
        settings: &StaticProviderSettings,
        callback_base_url: &str,
    ) -> Result<Self, StaticProviderError> {
        if !settings.allow_insecure_dev_login {
            return Err(StaticProviderError::NotAllowed);
        }
        if settings.users.is_empty() {
            return Err(StaticProviderError::NoUsers);
        }
        let base = Url::parse(callback_base_url)
            .map_err(|e| StaticProviderError::InvalidCallbackBase(e.to_string()))?;
        let dev_login_url = base
            .join("/auth/dev-login")
            .map_err(|e| StaticProviderError::InvalidCallbackBase(e.to_string()))?;
        Ok(Self {
            users: settings.users.clone(),
            dev_login_url,
        })
    }
}

/// Constant-time equality so secret verification does not leak the matching
/// prefix through timing. (Length still leaks; secrets are operator-chosen
/// dev credentials, not user passwords.)
fn secrets_match(expected: &str, provided: &str) -> bool {
    let expected = expected.as_bytes();
    let provided = provided.as_bytes();
    if expected.len() != provided.len() {
        return false;
    }
    expected
        .iter()
        .zip(provided)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

#[async_trait]
impl AuthProvider for StaticProvider {
    fn name(&self) -> &'static str {
        STATIC_PROVIDER_NAME
    }

    async fn begin_login(&self, session: &PendingSession) -> Result<Url, AuthProviderError> {
        let mut url = self.dev_login_url.clone();
        url.query_pairs_mut()
            .append_pair("state", &session.csrf_state);
        Ok(url)
    }

    async fn complete_login(
        &self,
        _session: &PendingSession,
        params: &CallbackParams,
    ) -> Result<ExternalIdentity, AuthProviderError> {
        let user = params
            .get("user")
            .ok_or_else(|| AuthProviderError::Invalid("missing 'user' parameter".to_string()))?;
        let secret = params
            .get("secret")
            .ok_or_else(|| AuthProviderError::Invalid("missing 'secret' parameter".to_string()))?;

        // Always compare against some secret so unknown users cost the same
        // as known users with a wrong secret.
        let mut matched: Option<&StaticUserSettings> = None;
        for candidate in &self.users {
            if candidate.user == user && secrets_match(&candidate.secret, secret) {
                matched = Some(candidate);
            }
        }

        let user = matched
            .ok_or_else(|| AuthProviderError::Denied("unknown user or wrong secret".to_string()))?;
        Ok(ExternalIdentity {
            subject: user.user.clone(),
            email: user.email.clone(),
            display_name: user.name.clone(),
            idp: STATIC_PROVIDER_NAME.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::session::SessionManager;

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
}
