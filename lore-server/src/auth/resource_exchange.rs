// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Shared resolution of resource-exchange requests against the access store.
//!
//! Both token-exchange surfaces — the `UrcAuthApi` gRPC service and the
//! standard OAuth 2.0 token endpoint ([`crate::http::oauth`]) — answer the
//! same question: which permission verbs does this verified user hold on
//! each requested resource? This module holds that answer so the two
//! surfaces cannot drift apart.

use std::str::FromStr;

use lore_revision::lore::RepositoryId;
use tonic::Status;

use crate::auth::jwt::AuthorizationToken;
use crate::auth::jwt::ResourcePermission;

/// Permissions granted to any authenticated user until the per-repository
/// access store provides real grants.
const DEFAULT_PERMISSIONS: [&str; 2] = ["read", "write"];

pub fn default_permissions() -> Vec<String> {
    DEFAULT_PERMISSIONS
        .iter()
        .map(ToString::to_string)
        .collect()
}

/// Parse a `urc-<repository-id>` resource id. Wildcards and non-repository
/// resources yield `None`.
pub fn parse_repository_resource(resource_id: &str) -> Option<RepositoryId> {
    let hex = resource_id.strip_prefix("urc-")?;
    RepositoryId::from_str(hex).ok()
}

/// Parse an RFC 8707 resource indicator into the repository it names.
///
/// The standard form is an absolute URI whose last path segment carries the
/// repository id (the upstream proposal's `resource_template`, e.g.
/// `https://lore.example.com/partitions/{id}`); the legacy `urc-<id>` form
/// and a bare id are accepted too, so callers migrating between the gRPC
/// and HTTP exchange surfaces need not translate.
pub fn parse_resource_indicator(resource: &str) -> Option<RepositoryId> {
    if let Some(repository) = parse_repository_resource(resource) {
        return Some(repository);
    }
    if let Ok(repository) = RepositoryId::from_str(resource) {
        return Some(repository);
    }
    let url = url::Url::parse(resource).ok()?;
    let segment = url.path_segments()?.rfind(|s| !s.is_empty())?;
    parse_repository_resource(segment).or_else(|| RepositoryId::from_str(segment).ok())
}

/// One requested resource: the id to embed in the minted claim, and the
/// repository it names when it names one.
pub struct ResourceRequest {
    pub resource_id: String,
    pub repository: Option<RepositoryId>,
}

/// Resolve the caller's granted permission verbs for each requested
/// resource. Deny-by-default when the access store is installed: a request
/// naming any resource the caller holds no grant on fails whole. Without an
/// access store every authenticated user gets the default permissions,
/// preserving the pre-access-control behavior.
pub async fn resolve_resource_permissions(
    claims: &AuthorizationToken,
    requests: Vec<ResourceRequest>,
) -> Result<Vec<ResourcePermission>, Status> {
    let Some(access) = crate::access::installed() else {
        return Ok(requests
            .into_iter()
            .map(|request| ResourcePermission {
                resource_id: request.resource_id,
                permission: default_permissions(),
            })
            .collect());
    };

    let principals = crate::access::Principals::from_claims(claims);
    let mut resources = Vec::with_capacity(requests.len());
    for request in requests {
        let role = match request.repository {
            Some(repository) => access
                .role_for(&principals, repository)
                .await
                .map_err(|e| Status::internal(format!("Access lookup failed: {e}")))?,
            // Wildcards and non-repository resources are never granted to
            // users.
            None => None,
        };
        let Some(role) = role else {
            return Err(Status::permission_denied(format!(
                "No access granted for {}",
                request.resource_id
            )));
        };
        resources.push(ResourcePermission {
            resource_id: request.resource_id,
            permission: role.verbs().iter().map(ToString::to_string).collect(),
        });
    }
    Ok(resources)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_indicators_parse_in_every_accepted_form() {
        let hex = "0194b726b34e72b0b45550b88a967076";
        let repository = RepositoryId::from_str(hex).expect("repo id");

        for form in [
            format!("urc-{hex}"),
            hex.to_string(),
            format!("https://lore.example.com/partitions/{hex}"),
            format!("https://lore.example.com/partitions/{hex}/"),
            format!("https://lore.example.com/partitions/urc-{hex}"),
        ] {
            assert_eq!(
                parse_resource_indicator(&form),
                Some(repository),
                "form {form}"
            );
        }

        for rejected in [
            "urc-*",
            "not-a-repository",
            "https://lore.example.com/",
            "https://lore.example.com/partitions/xyz",
        ] {
            assert_eq!(parse_resource_indicator(rejected), None, "form {rejected}");
        }
    }
}
