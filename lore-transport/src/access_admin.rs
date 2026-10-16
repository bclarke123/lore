// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Client for `lore.access.v1.AccessService` — per-repository grant
//! administration.
//!
//! Connects to the remote's public gRPC endpoint with the caller's
//! authentication token as a bearer header; the server authorizes the
//! operation from the caller's granted role. Follows the transport's
//! scheme convention: schemes ending in `s` use TLS, others plain HTTP.

use lore_base::types::RepositoryId;
use lore_error_set::prelude::*;
use lore_proto::lore::access::v1::AccessGrantRequest;
use lore_proto::lore::access::v1::AccessListRequest;
use lore_proto::lore::access::v1::AccessRevokeRequest;
use lore_proto::lore::access::v1::RepositoryRef;
use lore_proto::lore::access::v1::access_service_client::AccessServiceClient;
use lore_proto::lore::access::v1::repository_ref::Ref;
use url::Url;

use crate::error::ProtocolError;

/// A repository addressed for grant administration.
#[derive(Debug, Clone)]
pub enum AccessRepositoryRef {
    Id(RepositoryId),
    Name(String),
    /// Server-level grants (the all-zero repository id).
    Global,
}

/// A grant record: `(principal, role)`.
pub type GrantRecord = (String, String);

impl AccessRepositoryRef {
    #[lore_macro::test_pub]
    fn into_proto(self) -> RepositoryRef {
        let reference = match self {
            AccessRepositoryRef::Id(id) => Ref::Id(id.data().to_vec().into()),
            AccessRepositoryRef::Name(name) => Ref::Name(name),
            AccessRepositoryRef::Global => Ref::Id(RepositoryId::default().data().to_vec().into()),
        };
        RepositoryRef {
            r#ref: Some(reference),
        }
    }
}

/// Map a Lore remote URL to the gRPC channel URL, mirroring the data-plane
/// convention (`grpc://` → HTTP, `grpcs://`/`https://` → TLS).
#[lore_macro::test_pub]
fn channel_url(remote_url: &str) -> Result<String, ProtocolError> {
    let parsed =
        Url::parse(remote_url).internal_with(|| format!("remote {remote_url} is invalid"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| ProtocolError::internal(format!("remote {remote_url} has no host")))?;
    let (scheme, default_port) = if parsed.scheme().ends_with('s') {
        ("https", 443)
    } else {
        ("http", 41337)
    };
    let port = parsed.port().unwrap_or(default_port);
    Ok(format!("{scheme}://{host}:{port}"))
}

async fn client(
    remote_url: &str,
) -> Result<AccessServiceClient<tonic::transport::Channel>, ProtocolError> {
    let endpoint = channel_url(remote_url)?;
    let mut endpoint = tonic::transport::Endpoint::new(endpoint.clone())
        .internal_with(|| format!("invalid access endpoint {endpoint}"))?;
    if endpoint.uri().scheme_str() == Some("https") {
        endpoint = endpoint
            .tls_config(
                tonic::transport::ClientTlsConfig::new()
                    .assume_http2(true)
                    .with_native_roots(),
            )
            .internal("configuring TLS for access service")?;
    }
    let channel = endpoint
        .connect()
        .await
        .internal_with(|| format!("failed to connect to access service at {remote_url}"))?;
    Ok(AccessServiceClient::new(channel))
}

fn with_bearer<T>(payload: T, token: &str) -> Result<tonic::Request<T>, ProtocolError> {
    let mut request = tonic::Request::new(payload);
    let mut header: tonic::metadata::MetadataValue<_> =
        format!("Bearer {token}").parse().map_err(|err| {
            ProtocolError::internal(format!("invalid authorization header value: {err}"))
        })?;
    header.set_sensitive(true);
    request.metadata_mut().insert("authorization", header);
    Ok(request)
}

pub async fn grant(
    remote_url: &str,
    token: &str,
    repository: AccessRepositoryRef,
    principal: &str,
    role: &str,
) -> Result<(), ProtocolError> {
    let mut client = client(remote_url).await?;
    client
        .access_grant(with_bearer(
            AccessGrantRequest {
                repository: Some(repository.into_proto()),
                principal: principal.to_string(),
                role: role.to_string(),
            },
            token,
        )?)
        .await
        .map_err(ProtocolError::from)?;
    Ok(())
}

/// Returns whether a grant existed.
pub async fn revoke(
    remote_url: &str,
    token: &str,
    repository: AccessRepositoryRef,
    principal: &str,
) -> Result<bool, ProtocolError> {
    let mut client = client(remote_url).await?;
    let response = client
        .access_revoke(with_bearer(
            AccessRevokeRequest {
                repository: Some(repository.into_proto()),
                principal: principal.to_string(),
            },
            token,
        )?)
        .await
        .map_err(ProtocolError::from)?;
    Ok(response.into_inner().existed)
}

pub async fn list(
    remote_url: &str,
    token: &str,
    repository: AccessRepositoryRef,
) -> Result<Vec<GrantRecord>, ProtocolError> {
    let mut client = client(remote_url).await?;
    let response = client
        .access_list(with_bearer(
            AccessListRequest {
                repository: Some(repository.into_proto()),
            },
            token,
        )?)
        .await
        .map_err(ProtocolError::from)?;
    Ok(response
        .into_inner()
        .grants
        .into_iter()
        .map(|grant| (grant.principal, grant.role))
        .collect())
}
