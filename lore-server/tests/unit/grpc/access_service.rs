// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::str::FromStr;

use lore_base::runtime::LORE_CONTEXT;
use lore_proto::lore::access::v1::AccessGrantRequest;
use lore_proto::lore::access::v1::AccessListRequest;
use lore_proto::lore::access::v1::AccessRevokeRequest;
use lore_proto::lore::access::v1::RepositoryRef;
use lore_proto::lore::access::v1::access_service_server::AccessService;
use lore_proto::lore::access::v1::repository_ref::Ref;
use lore_revision::lore::RepositoryId;
use lore_server::grpc::access_service::*;
use tonic::Request;

use crate::store::test_support::test_store_create;

#[tokio::test]
async fn rpcs_fail_without_access_control() {
    // The process-global access control is not installed in unit tests,
    // so every RPC reports FailedPrecondition. (Installed-path behavior
    // is covered by the access-control smoke tests.)
    let (immutable, mutable, execution) = test_store_create().await.expect("test stores");
    let service = LoreAccessService::new(immutable, mutable);

    Box::pin(LORE_CONTEXT.scope(execution, async move {
        let grant = service
            .access_grant(Request::new(AccessGrantRequest {
                repository: Some(RepositoryRef {
                    r#ref: Some(Ref::Name("repo".to_string())),
                }),
                principal: "alice".to_string(),
                role: "read".to_string(),
            }))
            .await
            .unwrap_err();
        assert_eq!(grant.code(), tonic::Code::FailedPrecondition);

        let revoke = service
            .access_revoke(Request::new(AccessRevokeRequest {
                repository: None,
                principal: "alice".to_string(),
            }))
            .await
            .unwrap_err();
        assert_eq!(revoke.code(), tonic::Code::FailedPrecondition);

        let list = service
            .access_list(Request::new(AccessListRequest { repository: None }))
            .await
            .unwrap_err();
        assert_eq!(list.code(), tonic::Code::FailedPrecondition);
    }))
    .await;
}

#[tokio::test]
async fn resolve_accepts_ids_and_rejects_garbage() {
    let (immutable, mutable, execution) = test_store_create().await.expect("test stores");
    let service = LoreAccessService::new(immutable, mutable);

    Box::pin(LORE_CONTEXT.scope(execution, async move {
        // A well-formed id resolves.
        let id_bytes = RepositoryId::from_str("0194b726b34e72b0b45550b88a967076")
            .expect("id")
            .data()
            .to_vec();
        let resolved = service
            .resolve(Some(RepositoryRef {
                r#ref: Some(Ref::Id(id_bytes.into())),
            }))
            .await
            .expect("resolve");
        assert_eq!(resolved.to_string(), "0194b726b34e72b0b45550b88a967076");

        // Garbage id refused.
        let err = service
            .resolve(Some(RepositoryRef {
                r#ref: Some(Ref::Id(vec![1, 2, 3].into())),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        // Unknown name → not found.
        let err = service
            .resolve(Some(RepositoryRef {
                r#ref: Some(Ref::Name("missing-repo".to_string())),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);

        // Missing reference refused.
        let err = service.resolve(None).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }))
    .await;
}
