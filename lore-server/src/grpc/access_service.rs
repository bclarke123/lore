// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! `lore.access.v1.AccessService` — administration of per-repository
//! access-control grants.
//!
//! Only meaningful on servers running server-local authentication; without
//! installed access control every RPC answers `FailedPrecondition`. The
//! service authenticates callers itself from the bearer token (like the
//! auth service) and requires the admin role on the target repository —
//! or server administrator — for every operation. The all-zero repository
//! id addresses server-level grants.

use std::str::FromStr;
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_proto::lore::access::v1::AccessGrantRecord;
use lore_proto::lore::access::v1::AccessGrantRequest;
use lore_proto::lore::access::v1::AccessGrantResponse;
use lore_proto::lore::access::v1::AccessListRequest;
use lore_proto::lore::access::v1::AccessListResponse;
use lore_proto::lore::access::v1::AccessRevokeRequest;
use lore_proto::lore::access::v1::AccessRevokeResponse;
use lore_proto::lore::access::v1::RepositoryRef;
use lore_proto::lore::access::v1::access_service_server::AccessService;
use lore_proto::lore::access::v1::repository_ref::Ref;
use lore_revision::lore::RepositoryId;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::instrument;

use crate::access::AccessControl;
use crate::access::AccessRole;
use crate::grpc::extract_correlation_id;
use crate::util::setup_execution;

pub struct LoreAccessService {
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
}

fn bearer(metadata: &tonic::metadata::MetadataMap) -> Option<String> {
    metadata
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_string())
}

impl LoreAccessService {
    pub fn new(
        immutable_store: Arc<dyn lore_storage::ImmutableStore>,
        mutable_store: Arc<dyn lore_storage::MutableStore>,
    ) -> Self {
        Self {
            immutable_store,
            mutable_store,
        }
    }

    fn installed() -> Result<Arc<AccessControl>, Status> {
        crate::access::installed().ok_or_else(|| {
            Status::failed_precondition(
                "access control requires server-local authentication to be enabled",
            )
        })
    }

    /// Resolve a repository reference to an id. The all-zero id is allowed
    /// (server-level grants).
    #[lore_macro::test_pub]
    async fn resolve(&self, reference: Option<RepositoryRef>) -> Result<RepositoryId, Status> {
        let reference = reference
            .and_then(|r| r.r#ref)
            .ok_or_else(|| Status::invalid_argument("repository reference must be set"))?;
        match reference {
            Ref::Id(bytes) => {
                let hex = hex::encode(&bytes);
                RepositoryId::from_str(&hex)
                    .map_err(|_err| Status::invalid_argument("invalid repository id"))
            }
            Ref::Name(name) => {
                let context = lore_revision::access::server_context(
                    self.immutable_store.clone(),
                    self.mutable_store.clone(),
                    RepositoryId::default(),
                );
                lore_revision::repository::id_from_name(context, &name)
                    .await
                    .map_err(|_err| Status::not_found(format!("Repository {name} not found")))
            }
        }
    }

    /// Authenticate the caller and require the admin role on `repository`.
    async fn require_admin(
        &self,
        access: &AccessControl,
        metadata: &tonic::metadata::MetadataMap,
        repository: RepositoryId,
    ) -> Result<(), Status> {
        access
            .check_admin(bearer(metadata).as_deref(), repository)
            .await
            .map(|_| ())
    }
}

#[tonic::async_trait]
impl AccessService for LoreAccessService {
    #[instrument(name = "AccessService::AccessGrant", skip_all)]
    async fn access_grant(
        &self,
        request: Request<AccessGrantRequest>,
    ) -> Result<Response<AccessGrantResponse>, Status> {
        let access = Self::installed()?;
        let correlation_id = extract_correlation_id(&request).unwrap_or_default();
        let execution = setup_execution(module_path!(), correlation_id, String::default());
        LORE_CONTEXT
            .scope(execution, async move {
                let metadata = request.metadata().clone();
                let req = request.into_inner();

                let role = AccessRole::from_str(&req.role).map_err(Status::invalid_argument)?;
                if req.principal.trim().is_empty() {
                    return Err(Status::invalid_argument("principal must not be empty"));
                }
                let repository = self.resolve(req.repository).await?;
                self.require_admin(&access, &metadata, repository).await?;

                access
                    .grant(repository, req.principal.trim(), role)
                    .await
                    .map_err(|e| match e {
                        crate::access::AccessError::InvalidGrant(reason) => {
                            Status::invalid_argument(reason)
                        }
                        e @ crate::access::AccessError::Store(_) => {
                            Status::internal(format!("Failed to store grant: {e}"))
                        }
                    })?;
                Ok(Response::new(AccessGrantResponse {}))
            })
            .await
    }

    #[instrument(name = "AccessService::AccessRevoke", skip_all)]
    async fn access_revoke(
        &self,
        request: Request<AccessRevokeRequest>,
    ) -> Result<Response<AccessRevokeResponse>, Status> {
        let access = Self::installed()?;
        let correlation_id = extract_correlation_id(&request).unwrap_or_default();
        let execution = setup_execution(module_path!(), correlation_id, String::default());
        LORE_CONTEXT
            .scope(execution, async move {
                let metadata = request.metadata().clone();
                let req = request.into_inner();

                let repository = self.resolve(req.repository).await?;
                self.require_admin(&access, &metadata, repository).await?;

                let existed = access
                    .revoke(repository, req.principal.trim())
                    .await
                    .map_err(|e| Status::internal(format!("Failed to revoke grant: {e}")))?;
                Ok(Response::new(AccessRevokeResponse { existed }))
            })
            .await
    }

    #[instrument(name = "AccessService::AccessList", skip_all)]
    async fn access_list(
        &self,
        request: Request<AccessListRequest>,
    ) -> Result<Response<AccessListResponse>, Status> {
        let access = Self::installed()?;
        let correlation_id = extract_correlation_id(&request).unwrap_or_default();
        let execution = setup_execution(module_path!(), correlation_id, String::default());
        LORE_CONTEXT
            .scope(execution, async move {
                let metadata = request.metadata().clone();
                let req = request.into_inner();

                let repository = self.resolve(req.repository).await?;
                self.require_admin(&access, &metadata, repository).await?;

                let grants = access
                    .grants(repository)
                    .await
                    .map_err(|e| Status::internal(format!("Failed to load grants: {e}")))?;
                Ok(Response::new(AccessListResponse {
                    grants: grants
                        .into_iter()
                        .map(|(principal, role)| AccessGrantRecord {
                            principal,
                            role: role.as_str().to_string(),
                        })
                        .collect(),
                }))
            })
            .await
    }
}
