// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_base::types::RepositoryId;
use lore_proto::RepositoryMetadataSetRequest;
use lore_revision::repository::RepositoryContext;
use lore_revision::repository::RepositoryMetadata;
use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
use lore_server::authnz::repository_authorizer::RepositoryAuthorizer;
use lore_server::grpc::handlers::repository_metadata_set::*;
use tonic::Code;
use tonic::Request;
use tonic::Status;

use crate::store::test_support::test_store_create;

const REPOSITORY_ID: [u8; 16] = [1u8; 16];

/// Denies every request.
struct DenyAllRepositoryAuthorizer;

#[async_trait::async_trait]
impl RepositoryAuthorizer for DenyAllRepositoryAuthorizer {
    async fn check_repository_access(
        &self,
        _token: Option<&lore_server::authnz::repository_authorizer::VerifiedToken<'_>>,
        _repository_id: RepositoryId,
        _action: Option<&str>,
    ) -> Result<(), Status> {
        Err(Status::permission_denied("denied"))
    }
}

/// Permits, recording that the handler asked with `action: None`.
#[derive(Default)]
struct RecordingPermitAuthorizer {
    called_with_action_none: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl RepositoryAuthorizer for RecordingPermitAuthorizer {
    async fn check_repository_access(
        &self,
        _token: Option<&lore_server::authnz::repository_authorizer::VerifiedToken<'_>>,
        _repository_id: RepositoryId,
        action: Option<&str>,
    ) -> Result<(), Status> {
        self.called_with_action_none
            .store(action.is_none(), std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

async fn seed_metadata_blob(
    immutable: Arc<dyn lore_storage::ImmutableStore>,
    mutable: Arc<dyn lore_storage::MutableStore>,
) -> lore_base::types::Hash {
    let repo_ctx = Arc::new(RepositoryContext::new_server_context(
        immutable,
        mutable,
        Context::from(REPOSITORY_ID).into(),
    ));
    lore_revision::repository::metadata_store(
        repo_ctx,
        RepositoryMetadata {
            name: "test".to_string(),
            ..Default::default()
        },
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn no_auth_configured_allows_operation() {
    let (immutable, mutable, execution) = test_store_create().await.unwrap();
    LORE_CONTEXT
        .scope(execution, async move {
            let hash = seed_metadata_blob(immutable.clone(), mutable.clone()).await;
            let request = Request::new(RepositoryMetadataSetRequest {
                repository_id: REPOSITORY_ID.to_vec().into(),
                expected_hash: vec![0u8; 32].into(),
                new_hash: hash.into(),
            });
            handler(
                request,
                Arc::new(AllowAllRepositoryAuthorizer),
                immutable,
                mutable,
            )
            .await
            .unwrap();
        })
        .await;
}

#[tokio::test]
async fn auth_configured_no_access_returns_permission_denied() {
    let (immutable, mutable, _) = test_store_create().await.unwrap();
    let request = Request::new(RepositoryMetadataSetRequest {
        repository_id: REPOSITORY_ID.to_vec().into(),
        expected_hash: vec![0u8; 32].into(),
        new_hash: vec![1u8; 32].into(),
    });
    let err = handler(
        request,
        Arc::new(DenyAllRepositoryAuthorizer),
        immutable,
        mutable,
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(err.message(), "Unauthorized");
}

#[tokio::test]
async fn auth_configured_with_access_allows_operation() {
    let (immutable, mutable, execution) = test_store_create().await.unwrap();
    LORE_CONTEXT
        .scope(execution, async move {
            let hash = seed_metadata_blob(immutable.clone(), mutable.clone()).await;
            let authorizer = Arc::new(RecordingPermitAuthorizer::default());
            let request = Request::new(RepositoryMetadataSetRequest {
                repository_id: REPOSITORY_ID.to_vec().into(),
                expected_hash: vec![0u8; 32].into(),
                new_hash: hash.into(),
            });
            handler(request, authorizer.clone(), immutable, mutable)
                .await
                .unwrap();
            assert!(
                authorizer
                    .called_with_action_none
                    .load(std::sync::atomic::Ordering::SeqCst)
            );
        })
        .await;
}
