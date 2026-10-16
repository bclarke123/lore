// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Orchestration for `lore access` grant administration.
//!
//! Resolves the remote's auth endpoint, loads the caller's stored
//! authentication token, and calls the remote access service via
//! [`lore_transport::access_admin`].

use std::str::FromStr;
use std::sync::Weak;

use lore_credential::token_store;
use lore_credential::token_store::tokens_only_for_recipient_domain;
use lore_error_set::prelude::*;
pub use lore_transport::access_admin::AccessRepositoryRef;
pub use lore_transport::access_admin::GrantRecord;
use lore_transport::auth::authentication;

use crate::auth::login::LoginError;
use crate::lore::RepositoryId;

/// Parse a repository argument: a hex id, the literal `--global` sentinel
/// handled by the caller, or a repository name.
pub fn repository_ref(argument: &str) -> AccessRepositoryRef {
    match RepositoryId::from_str(argument) {
        Ok(id) => AccessRepositoryRef::Id(id),
        Err(_) => AccessRepositoryRef::Name(argument.to_string()),
    }
}

/// Load the caller's authentication token for the remote: resolves the
/// remote's auth endpoint, then picks the first stored identity holding an
/// unexpired token trusted for the remote's domain.
async fn resolve_token(remote_url: &str) -> Result<String, LoginError> {
    let (parsed_remote, protocol) =
        lore_transport::parse(remote_url).forward::<LoginError>("parsing remote URL")?;

    let environment = protocol
        .environment(Weak::default(), parsed_remote.as_str())
        .await
        .forward::<LoginError>("fetching environment")?;
    let environment = environment
        .get()
        .await
        .forward::<LoginError>("getting environment config")?;
    // The path the caller's `connect` takes, so the token store is read under
    // the endpoint key its login stored the token under.
    let mode = crate::lore::execution_context().globals().auth_mode;
    let Some(selected) = authentication::select(mode, &environment)
        .forward::<LoginError>("selecting the auth path")?
    else {
        return Err(LoginError::internal(
            "Remote does not advertise an auth endpoint",
        ));
    };
    let auth_url = selected.endpoint.url;

    let remote_domain = lore_credential::get_domain_or_empty(parsed_remote.as_str());
    let identities = token_store::load_identities(&auth_url)
        .await
        .forward::<LoginError>("loading stored identities")?;
    for identity in &identities {
        if let Ok(token) = token_store::load_user_token(
            &auth_url,
            identity,
            tokens_only_for_recipient_domain(remote_domain.clone()),
            "",
            "",
        )
        .await
            && let Some(info) = lore_credential::user_info_from_token(token.clone())
            && !lore_transport::auth::exchange::is_expired(info.expires)
        {
            return Ok(token);
        }
    }
    Err(LoginError::internal(
        "No valid authentication token stored; run `lore auth login` first",
    ))
}

pub async fn grant(
    remote_url: &str,
    repository: AccessRepositoryRef,
    principal: &str,
    role: &str,
) -> Result<(), LoginError> {
    let token = resolve_token(remote_url).await?;
    lore_transport::access_admin::grant(remote_url, &token, repository, principal, role)
        .await
        .forward::<LoginError>("granting access")
}

pub async fn revoke(
    remote_url: &str,
    repository: AccessRepositoryRef,
    principal: &str,
) -> Result<bool, LoginError> {
    let token = resolve_token(remote_url).await?;
    lore_transport::access_admin::revoke(remote_url, &token, repository, principal)
        .await
        .forward::<LoginError>("revoking access")
}

pub async fn list(
    remote_url: &str,
    repository: AccessRepositoryRef,
) -> Result<Vec<GrantRecord>, LoginError> {
    let token = resolve_token(remote_url).await?;
    lore_transport::access_admin::list(remote_url, &token, repository)
        .await
        .forward::<LoginError>("listing access grants")
}
