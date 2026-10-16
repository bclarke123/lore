// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::str::FromStr;
use std::sync::Arc;

use lore_revision::access::AccessGrants;
use lore_revision::access::AccessRole;
use lore_revision::access::PUBLIC_PRINCIPAL;
use lore_revision::lore::RepositoryId;
use lore_server::access::*;
use lore_server::auth::jwt::AuthorizationToken;
use lore_server::auth::jwt::JwtVerifier;

use crate::store::test_support::test_store_create;

async fn access_with_admins(
    admins: Vec<String>,
) -> (
    AccessControl,
    Arc<lore_revision::interface::ExecutionContext>,
) {
    let (immutable, mutable, execution) = test_store_create().await.expect("test stores");
    // Verifier is unused by the store-level tests; any instance works.
    let verifier = JwtVerifier {
        jwk_service: Arc::new(lore_server::auth::jwk::JwkServiceImpl::default()),
        jwt_issuer: None,
        jwt_audience: None,
        jwt_typ: None,
    };
    (
        AccessControl::new(immutable, mutable, verifier, admins),
        execution,
    )
}

fn repo(hex: &str) -> RepositoryId {
    RepositoryId::from_str(hex).expect("repo id")
}

fn principals(user_id: &str, email: &str) -> Principals {
    Principals::from_claims(&claims(user_id, email))
}

/// Grants written by a pre-0.9.1 server live under the discriminant
/// `AccessControl` held before the upstream merge renumbered it. They
/// must stay readable through the legacy-slot fallback and be
/// re-registered under the current slot on first load.
#[tokio::test]
async fn legacy_key_slot_grants_survive_and_upgrade() {
    let (immutable, mutable_old, execution) = test_store_create().await.expect("test stores");
    let (_imm2, mutable_new, _exec2) = test_store_create().await.expect("fresh stores");
    let verifier = || JwtVerifier {
        jwk_service: Arc::new(lore_server::auth::jwk::JwkServiceImpl::default()),
        jwt_issuer: None,
        jwt_audience: None,
        jwt_typ: None,
    };
    let access_old = AccessControl::new(
        immutable.clone(),
        mutable_old.clone(),
        verifier(),
        Vec::new(),
    );
    let access_new = AccessControl::new(
        immutable.clone(),
        mutable_new.clone(),
        verifier(),
        Vec::new(),
    );
    Box::pin(
        lore_base::runtime::LORE_CONTEXT.scope(execution, async move {
            let project = repo("0194b726b34e72b0b45550b88a967076");
            let alice = principals("static:alice", "alice@example.com");

            // Write grants through the current slot, then relocate the
            // pointer row to the legacy slot in a fresh mutable store:
            // exactly what a pre-merge store looks like to a post-merge
            // server (the blob itself lives in the shared immutable
            // store and is unaffected by the renumbering).
            access_old
                .grant(project, "static:alice", AccessRole::Write)
                .await
                .expect("grant");
            access_old
                .grant(project, PUBLIC_PRINCIPAL, AccessRole::Read)
                .await
                .expect("public grant");
            let ctx_old = lore_revision::access::server_context(
                immutable.clone(),
                mutable_old.clone(),
                project,
            );
            let (key, current_slot, legacy_slot) = lore_revision::access::grants_slots(&ctx_old);
            let pointer = ctx_old
                .read_mutable_store()
                .load(project, key, current_slot)
                .await
                .expect("pointer");
            let ctx_new = lore_revision::access::server_context(
                immutable.clone(),
                mutable_new.clone(),
                project,
            );
            ctx_new
                .try_write_mutable_store()
                .expect("write handle")
                .store(project, key, pointer, legacy_slot)
                .await
                .expect("legacy row");

            // The post-merge server reads them through the fallback...
            assert!(access_new.is_public(project).await.expect("is_public"));
            assert_eq!(
                access_new.role_for(&alice, project).await.expect("role"),
                Some(AccessRole::Write)
            );
            // ...and the first load re-registered the pointer under the
            // current slot, so the fallback read is paid only once.
            assert_eq!(
                ctx_new
                    .read_mutable_store()
                    .load(project, key, current_slot)
                    .await
                    .expect("upgraded pointer"),
                pointer
            );

            // Later modifications go through the current slot cleanly.
            access_new
                .grant(project, "static:bob", AccessRole::Read)
                .await
                .expect("post-upgrade grant");
            let bob = principals("static:bob", "bob@example.com");
            assert_eq!(
                access_new.role_for(&bob, project).await.expect("role"),
                Some(AccessRole::Read)
            );
        }),
    )
    .await;
}

#[tokio::test]
async fn deny_by_default_then_grant_then_revoke() {
    let (access, execution) = access_with_admins(vec![]).await;
    Box::pin(
        lore_base::runtime::LORE_CONTEXT.scope(execution, async move {
            let project = repo("0194b726b34e72b0b45550b88a967076");
            let alice = principals("static:alice", "alice@example.com");

            assert_eq!(access.role_for(&alice, project).await.expect("role"), None);

            access
                .grant(project, "static:alice", AccessRole::Write)
                .await
                .expect("grant");
            assert_eq!(
                access.role_for(&alice, project).await.expect("role"),
                Some(AccessRole::Write)
            );

            // Upgrading the grant replaces it.
            access
                .grant(project, "static:alice", AccessRole::Admin)
                .await
                .expect("regrant");
            assert_eq!(
                access.role_for(&alice, project).await.expect("role"),
                Some(AccessRole::Admin)
            );

            assert!(
                access
                    .revoke(project, "static:alice")
                    .await
                    .expect("revoke")
            );
            assert_eq!(access.role_for(&alice, project).await.expect("role"), None);
            // Revoking again reports no grant existed.
            assert!(
                !access
                    .revoke(project, "static:alice")
                    .await
                    .expect("revoke")
            );
        }),
    )
    .await;
}

#[tokio::test]
async fn grants_are_scoped_per_repository() {
    let (access, execution) = access_with_admins(vec![]).await;
    Box::pin(
        lore_base::runtime::LORE_CONTEXT.scope(execution, async move {
            let project1 = repo("0194b726b34e72b0b45550b88a967076");
            let project2 = repo("f6ca55437aa34198ba0f0fdc33154d51");
            let ben = principals("google:ben", "ben@example.com");

            access
                .grant(project1, "google:ben", AccessRole::Read)
                .await
                .expect("grant");

            assert_eq!(
                access.role_for(&ben, project1).await.expect("role"),
                Some(AccessRole::Read)
            );
            // ben can see project1 but not project2 unless somebody adds him.
            assert_eq!(access.role_for(&ben, project2).await.expect("role"), None);
        }),
    )
    .await;
}

#[tokio::test]
async fn email_alias_grants_match() {
    let (access, execution) = access_with_admins(vec![]).await;
    Box::pin(
        lore_base::runtime::LORE_CONTEXT.scope(execution, async move {
            let project = repo("0194b726b34e72b0b45550b88a967076");

            access
                .grant(project, "ben@example.com", AccessRole::Write)
                .await
                .expect("grant");
            let ben = principals("google:ben-subject", "ben@example.com");
            assert_eq!(
                access.role_for(&ben, project).await.expect("role"),
                Some(AccessRole::Write)
            );
        }),
    )
    .await;
}

#[tokio::test]
async fn server_admins_hold_admin_everywhere() {
    let (access, execution) = access_with_admins(vec!["ben@example.com".to_string()]).await;
    Box::pin(
        lore_base::runtime::LORE_CONTEXT.scope(execution, async move {
            let project = repo("0194b726b34e72b0b45550b88a967076");
            let ben = principals("google:ben", "ben@example.com");
            let carol = principals("google:carol", "carol@example.com");

            assert!(access.is_server_admin(&ben).await.expect("admin"));
            assert!(!access.is_server_admin(&carol).await.expect("admin"));
            assert_eq!(
                access.role_for(&ben, project).await.expect("role"),
                Some(AccessRole::Admin)
            );

            // Runtime global grant also confers server admin.
            access
                .grant(RepositoryId::default(), "google:carol", AccessRole::Admin)
                .await
                .expect("grant");
            assert!(access.is_server_admin(&carol).await.expect("admin"));
        }),
    )
    .await;
}

#[tokio::test]
async fn creator_auto_grant_and_deletion_cleanup() {
    let (access, execution) = access_with_admins(vec![]).await;
    Box::pin(
        lore_base::runtime::LORE_CONTEXT.scope(execution, async move {
            let project = repo("0194b726b34e72b0b45550b88a967076");
            let alice = principals("static:alice", "alice@example.com");

            access
                .on_repository_created(project, "static:alice")
                .await
                .expect("created");
            assert_eq!(
                access.role_for(&alice, project).await.expect("role"),
                Some(AccessRole::Admin)
            );

            access
                .on_repository_deleted(project)
                .await
                .expect("deleted");
            assert_eq!(access.role_for(&alice, project).await.expect("role"), None);
        }),
    )
    .await;
}

#[tokio::test]
async fn concurrent_grants_do_not_lose_writes() {
    let (access, execution) = access_with_admins(vec![]).await;
    let access = Arc::new(access);
    Box::pin(
        lore_base::runtime::LORE_CONTEXT.scope(execution, async move {
            let project = repo("0194b726b34e72b0b45550b88a967076");

            let mut tasks = tokio::task::JoinSet::new();
            for index in 0..8 {
                let access = access.clone();
                // lore_spawn! propagates LORE_CONTEXT into the task.
                lore_base::lore_spawn!(tasks, async move {
                    access
                        .grant(project, &format!("user-{index}"), AccessRole::Read)
                        .await
                });
            }
            while let Some(result) = tasks.join_next().await {
                result.expect("join").expect("grant");
            }

            let grants = access.grants(project).await.expect("grants");
            assert_eq!(
                grants.len(),
                8,
                "all concurrent grants survived: {grants:?}"
            );
        }),
    )
    .await;
}

fn claims(user_id: &str, email: &str) -> AuthorizationToken {
    AuthorizationToken {
        user_id: user_id.to_string(),
        preferred_username: Some(email.to_string()),
        ..AuthorizationToken::default()
    }
}

#[tokio::test]
async fn public_grant_makes_repository_readable_by_anyone() {
    let (access, execution) = access_with_admins(vec![]).await;
    Box::pin(
        lore_base::runtime::LORE_CONTEXT.scope(execution, async move {
            let project = repo("0194b726b34e72b0b45550b88a967076");
            let stranger = principals("google:stranger", "stranger@example.com");
            let carol = principals("google:carol", "carol@example.com");

            assert!(!access.is_public(project).await.expect("is_public"));
            assert_eq!(
                access.role_for(&stranger, project).await.expect("role"),
                None
            );

            access
                .grant(project, PUBLIC_PRINCIPAL, AccessRole::Read)
                .await
                .expect("grant");
            assert!(access.is_public(project).await.expect("is_public"));
            assert_eq!(
                access.role_for(&stranger, project).await.expect("role"),
                Some(AccessRole::Read)
            );

            // An explicit stronger grant still wins over the public one.
            access
                .grant(project, "google:carol", AccessRole::Write)
                .await
                .expect("grant");
            assert_eq!(
                access.role_for(&carol, project).await.expect("role"),
                Some(AccessRole::Write)
            );

            // Revoking the public grant restores deny-by-default.
            assert!(
                access
                    .revoke(project, PUBLIC_PRINCIPAL)
                    .await
                    .expect("revoke")
            );
            assert!(!access.is_public(project).await.expect("is_public"));
            assert_eq!(
                access.role_for(&stranger, project).await.expect("role"),
                None
            );
        }),
    )
    .await;
}

#[tokio::test]
async fn public_grant_validation() {
    let (access, execution) = access_with_admins(vec![]).await;
    Box::pin(
        lore_base::runtime::LORE_CONTEXT.scope(execution, async move {
            let project = repo("0194b726b34e72b0b45550b88a967076");

            for role in [AccessRole::Write, AccessRole::Admin] {
                assert!(matches!(
                    access.grant(project, PUBLIC_PRINCIPAL, role).await,
                    Err(AccessError::InvalidGrant(_))
                ));
            }
            assert!(matches!(
                access
                    .grant(RepositoryId::default(), PUBLIC_PRINCIPAL, AccessRole::Read)
                    .await,
                Err(AccessError::InvalidGrant(_))
            ));
        }),
    )
    .await;
}

#[test]
fn principals_match_canonical_id_and_email_alias() {
    let mut grants = AccessGrants::new();
    grants.insert("google:123".to_string(), AccessRole::Read);
    grants.insert("alice@example.com".to_string(), AccessRole::Write);

    let by_id = Principals::from_claims(&claims("google:123", "other@example.com"));
    assert_eq!(by_id.matches(&grants), Some(AccessRole::Read));

    let by_email = Principals::from_claims(&claims("google:999", "alice@example.com"));
    assert_eq!(by_email.matches(&grants), Some(AccessRole::Write));

    let both = Principals::from_claims(&claims("google:123", "alice@example.com"));
    // Strongest grant wins.
    assert_eq!(both.matches(&grants), Some(AccessRole::Write));

    let neither = Principals::from_claims(&claims("google:999", "bob@example.com"));
    assert_eq!(neither.matches(&grants), None);
}
