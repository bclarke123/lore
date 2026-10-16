// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_server::auth::provider::ExternalIdentity;
use lore_server::auth::refresh::*;

use crate::store::test_support::test_store_create;

fn identity() -> ExternalIdentity {
    ExternalIdentity {
        subject: "alice".to_string(),
        email: Some("alice@example.com".to_string()),
        display_name: Some("Alice".to_string()),
        idp: "static".to_string(),
    }
}

async fn store(
    ttl_seconds: u64,
) -> (
    RefreshTokenStore,
    Arc<lore_revision::interface::ExecutionContext>,
) {
    let (immutable, mutable, execution) = test_store_create().await.expect("test stores");
    (
        RefreshTokenStore::new(immutable, mutable, ttl_seconds),
        execution,
    )
}

#[tokio::test]
async fn issue_then_refresh_rotates() {
    let (store, execution) = store(3600).await;
    Box::pin(LORE_CONTEXT.scope(execution, async move {
        let token = store.issue(&identity()).await.expect("issue");

        let (refreshed_identity, successor) = store.refresh(&token).await.expect("refresh");
        assert_eq!(refreshed_identity, identity());
        assert_ne!(successor, token);

        // The successor works too.
        let (_, third) = store.refresh(&successor).await.expect("second refresh");
        assert_ne!(third, successor);
    }))
    .await;
}

#[tokio::test]
async fn unknown_token_is_refused() {
    let (store, execution) = store(3600).await;
    Box::pin(LORE_CONTEXT.scope(execution, async move {
        assert!(matches!(
            store.refresh("never-issued").await,
            Err(RefreshError::Unknown)
        ));
    }))
    .await;
}

#[tokio::test]
async fn expired_token_is_refused() {
    let (store, execution) = store(0).await;
    Box::pin(LORE_CONTEXT.scope(execution, async move {
        let token = store.issue(&identity()).await.expect("issue");
        assert!(matches!(
            store.refresh(&token).await,
            Err(RefreshError::Unknown)
        ));
    }))
    .await;
}

#[tokio::test]
async fn concurrent_replay_within_grace_converges_on_one_successor() {
    let (store, execution) = store(3600).await;
    Box::pin(LORE_CONTEXT.scope(execution, async move {
        let token = store.issue(&identity()).await.expect("issue");
        let (_, successor) = store.refresh(&token).await.expect("refresh");

        // A racing process replays the same token: same successor, no
        // revocation — both processes now hold the same live token.
        let (_, replayed) = store.refresh(&token).await.expect("replay in grace");
        assert_eq!(replayed, successor);
        store
            .refresh(&successor)
            .await
            .expect("family survives the race");
    }))
    .await;
}

#[tokio::test]
async fn reuse_revokes_the_family() {
    // Grace 0 = every replay is past the window (the theft path).
    let (store, execution) = store(3600).await;
    let store = store.with_reuse_grace_ms(0);
    Box::pin(LORE_CONTEXT.scope(execution, async move {
        let token = store.issue(&identity()).await.expect("issue");
        let (_, successor) = store.refresh(&token).await.expect("refresh");

        // Replaying the rotated token is reuse...
        assert!(matches!(
            store.refresh(&token).await,
            Err(RefreshError::ReuseDetected)
        ));
        // ...which revokes the active successor as well.
        assert!(matches!(
            store.refresh(&successor).await,
            Err(RefreshError::Unknown)
        ));
    }))
    .await;
}

#[tokio::test]
async fn families_are_independent() {
    let (store, execution) = store(3600).await;
    let store = store.with_reuse_grace_ms(0);
    Box::pin(LORE_CONTEXT.scope(execution, async move {
        let first_login = store.issue(&identity()).await.expect("issue");
        let second_login = store.issue(&identity()).await.expect("issue");

        // Killing the first family leaves the second alone.
        let (_, successor) = store.refresh(&first_login).await.expect("refresh");
        let _ = store.refresh(&first_login).await;
        assert!(matches!(
            store.refresh(&successor).await,
            Err(RefreshError::Unknown)
        ));

        store
            .refresh(&second_login)
            .await
            .expect("second family lives");
    }))
    .await;
}
