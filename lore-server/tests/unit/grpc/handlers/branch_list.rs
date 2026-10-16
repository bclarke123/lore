// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_proto::BranchListRequest;
use lore_proto::BranchListResponse;
use lore_revision::branch;
use lore_revision::branch::BranchLatestStatus;
use lore_revision::repository::RepositoryContext;
use lore_server::grpc::get_write_token;
use lore_server::grpc::handlers::branch_list::*;
use lore_transport::grpc::REPOSITORY_ID_KEY;
use rand::random;
use tonic::Request;

use crate::store::test_support::test_store_create;

#[tokio::test]
async fn test_handle() {
    let repository = random::<Context>();
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");
    LORE_CONTEXT
        .scope(execution.clone(), async move {
            let repository = Arc::new(RepositoryContext::new_server_context(
                immutable_store.clone(),
                mutable_store.clone(),
                repository.into(),
            ));
            let write_token = get_write_token();
            // Create the main branch (without parent)
            let no_parent = Context::default(); // Zero, no parent
            let payload_main = random::<[u8; size_of::<Hash>()]>().to_vec();
            let hash_main = Hash::hash_buffer(&payload_main);
            let main = lore_revision::branch::create(
                repository.clone(),
                &write_token,
                Context::from(uuid::Uuid::now_v7()),
                lore_revision::branch::DEFAULT_DEFAULT_NAME,
                lore_revision::branch::default_category(),
                "MainCreator",
                1234,
                vec![],
                false,
                false,
            )
            .await
            .expect("Could not create main branch");

            let mut request = Request::new(BranchListRequest {});
            request.metadata_mut().insert_bin(
                REPOSITORY_ID_KEY,
                tonic::metadata::BinaryMetadataValue::from_bytes(repository.id.data()),
            );
            let response = handler(request, immutable_store.clone(), mutable_store.clone())
                .await
                .expect("Failed BranchList message handle");
            assert_eq!(
                BranchListResponse {
                    branches: [lore_proto::Branch {
                        id: main.into(),
                        name: lore_revision::branch::DEFAULT_DEFAULT_NAME.to_string(),
                        category: lore_revision::branch::default_category().to_string(),
                        parent_deprecated: Some(Context::default().into()),
                        latest: Hash::default().into(),
                        branch_point_deprecated: Some(Hash::default().into()),
                        creator: "MainCreator".to_string(),
                        created: 1234,
                        stack: vec![],
                    }]
                    .to_vec()
                },
                response.into_inner()
            );

            // Create another branch1
            let payload_branch1 = random::<[u8; size_of::<Hash>()]>().to_vec();
            let hash_branch1 = Hash::hash_buffer(&payload_branch1);
            let branch1 = lore_revision::branch::create(
                repository.clone(),
                &write_token,
                Context::from(uuid::Uuid::now_v7()),
                "branch1",
                lore_revision::branch::default_category(),
                "TestCreator",
                4321,
                vec![],
                false,
                false,
            )
            .await
            .expect("Could not create branch1 branch");

            // Update main branch
            branch::store_latest(
                repository.clone(),
                main,
                Hash::default(),
                hash_main,
                BranchLatestStatus::Convergent,
            )
            .await
            .expect("Failed to store latest");

            // Update branch1 branch
            branch::store_latest(
                repository.clone(),
                branch1,
                Hash::default(),
                hash_branch1,
                BranchLatestStatus::Convergent,
            )
            .await
            .expect("Failed to store latest");

            let mut request = Request::new(BranchListRequest {});
            request.metadata_mut().insert_bin(
                REPOSITORY_ID_KEY,
                tonic::metadata::BinaryMetadataValue::from_bytes(repository.id.data()),
            );
            let response = handler(request, immutable_store.clone(), mutable_store.clone())
                .await
                .expect("Failed BranchList message handle")
                .into_inner();

            assert!(response.branches.contains(&lore_proto::Branch {
                id: main.into(),
                name: lore_revision::branch::DEFAULT_DEFAULT_NAME.to_string(),
                category: lore_revision::branch::default_category().to_string(),
                parent_deprecated: Some(no_parent.into()),
                latest: hash_main.into(),
                branch_point_deprecated: Some(Hash::default().into()),
                creator: "MainCreator".to_string(),
                created: 1234,
                stack: vec![]
            }));

            assert!(response.branches.contains(&lore_proto::Branch {
                id: branch1.into(),
                name: "branch1".to_string(),
                category: lore_revision::branch::default_category().to_string(),
                parent_deprecated: Some(Context::default().into()),
                latest: hash_branch1.into(),
                branch_point_deprecated: Some(Hash::default().into()),
                creator: "TestCreator".to_string(),
                created: 4321,
                stack: vec![]
            }));
        })
        .await;
}

#[tokio::test]
async fn test_handle_no_branches() {
    let repository = random::<Context>();
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");
    LORE_CONTEXT
        .scope(execution.clone(), async move {
            let repository = Arc::new(RepositoryContext::new_server_context(
                immutable_store.clone(),
                mutable_store.clone(),
                repository.into(),
            ));
            let mut request = Request::new(BranchListRequest {});
            request.metadata_mut().insert_bin(
                REPOSITORY_ID_KEY,
                tonic::metadata::BinaryMetadataValue::from_bytes(repository.id.data()),
            );
            let response = handler(request, immutable_store.clone(), mutable_store.clone())
                .await
                .expect("Failed BranchList message handle");
            assert_eq!(
                BranchListResponse { branches: vec![] },
                response.into_inner()
            );
        })
        .await;
}
