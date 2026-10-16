// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::collections::HashSet;

use async_trait::async_trait;
use lore_base::types::RepositoryId;
use tonic::Status;

use super::repository_authorizer::Grants;
use super::repository_authorizer::RepositoryAuthorizer;
use super::repository_authorizer::VerifiedToken;

/// Tier 1 authorizer: actions are granted globally, so the repository
/// parameter is ignored entirely. The caller's action set is read from the
/// dotted claim path named by `[server.auth].permission_claim`, which is an
/// ordinary role or group claim such as `realm_access.roles` or `groups`.
pub struct GlobalGrantsAuthorizer {
    permission_claim: Option<String>,
}

impl GlobalGrantsAuthorizer {
    pub fn new(permission_claim: Option<String>) -> Self {
        Self { permission_claim }
    }

    /// Any authenticated principal reaches every partition on this tier. The
    /// action set is the permission claim's string values, empty when the
    /// claim is unconfigured or absent.
    fn grants_for(&self, token: &VerifiedToken<'_>) -> Grants {
        let Some(claim) = &self.permission_claim else {
            return Grants::Actions(HashSet::new());
        };
        let Some(serde_json::Value::Array(values)) = token.claims.claim_at(claim) else {
            return Grants::Actions(HashSet::new());
        };
        Grants::Actions(
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(ToString::to_string)
                .collect(),
        )
    }

    /// The whole verdict is in the token, so the async and sync trait
    /// methods share this body.
    fn check(
        &self,
        token: Option<&VerifiedToken<'_>>,
        _repository_id: RepositoryId,
        action: Option<&str>,
    ) -> Result<(), Status> {
        let Some(token) = token else {
            return Err(Status::unauthenticated("No token"));
        };
        match action {
            // action == None -> just check that the user has a valid token
            None => Ok(()),
            Some(action) if self.grants_for(token).permits(action) => Ok(()),
            Some(_) => Err(Status::permission_denied("Action not permitted")),
        }
    }
}

#[async_trait]
impl RepositoryAuthorizer for GlobalGrantsAuthorizer {
    async fn check_repository_access(
        &self,
        token: Option<&VerifiedToken<'_>>,
        repository_id: RepositoryId,
        action: Option<&str>,
    ) -> Result<(), Status> {
        self.check(token, repository_id, action)
    }

    fn check_repository_access_sync(
        &self,
        token: Option<&VerifiedToken<'_>>,
        repository_id: RepositoryId,
        action: Option<&str>,
    ) -> Option<Result<(), Status>> {
        Some(self.check(token, repository_id, action))
    }

    async fn granted_actions(
        &self,
        token: Option<&VerifiedToken<'_>>,
        _repository_id: RepositoryId,
    ) -> Result<Option<Grants>, Status> {
        Ok(Some(match token {
            None => Grants::Denied,
            Some(token) => self.grants_for(token),
        }))
    }
}
