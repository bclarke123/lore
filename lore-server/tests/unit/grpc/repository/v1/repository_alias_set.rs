// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::str::FromStr;
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_revision::lore::RepositoryId;
use lore_revision::repository;
use lore_revision::repository::RepositoryContext;
use lore_server::grpc::repository::v1::repository_alias_set::*;

use crate::store::test_support::test_store_create;

fn repo(hex: &str) -> RepositoryId {
    RepositoryId::from_str(hex).expect("repo id")
}

async fn alias_context() -> (
    Arc<RepositoryContext>,
    Arc<lore_revision::interface::ExecutionContext>,
) {
    let (immutable, mutable, execution) = test_store_create().await.expect("test stores");
    (
        Arc::new(RepositoryContext::new_server_context(
            immutable,
            mutable,
            RepositoryId::default(),
        )),
        execution,
    )
}

#[tokio::test]
async fn set_resolve_repoint_and_collision() {
    let (context, execution) = alias_context().await;
    Box::pin(LORE_CONTEXT.scope(execution, async move {
        let first = repo("0194b726b34e72b0b45550b88a967076");
        let second = repo("f6ca55437aa34198ba0f0fdc33154d51");

        set_alias(context.clone(), "ben/listyboi", first, None)
            .await
            .expect("set alias");
        assert_eq!(
            repository::id_from_name(context.clone(), "ben/listyboi")
                .await
                .expect("resolve"),
            first
        );

        // Idempotent re-issue of the same pair succeeds.
        set_alias(context.clone(), "ben/listyboi", first, None)
            .await
            .expect("idempotent set");

        // A different repository cannot claim the name.
        let err = set_alias(context.clone(), "ben/listyboi", second, None)
            .await
            .expect_err("collision");
        assert_eq!(err.code(), tonic::Code::AlreadyExists);

        // Rename: new alias in, old alias out.
        set_alias(context.clone(), "ben/listy", first, Some("ben/listyboi"))
            .await
            .expect("rename");
        assert_eq!(
            repository::id_from_name(context.clone(), "ben/listy")
                .await
                .expect("resolve renamed"),
            first
        );
        // The old name no longer resolves to the repository (tombstoned
        // to the default id or gone entirely) and is free to claim.
        if let Ok(resolved) = repository::id_from_name(context.clone(), "ben/listyboi").await {
            assert_eq!(resolved, RepositoryId::default());
        }
        set_alias(context.clone(), "ben/listyboi", second, None)
            .await
            .expect("freed name is claimable");
    }))
    .await;
}
