// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_revision::lore::RepositoryId;
use lore_server::hooks::context::*;
use lore_server::hooks::traits::HookPoint;

fn create_test_context() -> HookContext {
    HookContext::builder()
        .correlation_id("test-correlation-123")
        .hook_point(HookPoint::BranchPush)
        .repository(RepositoryId::default())
        .build()
}

#[test]
fn test_context_immutable_fields() {
    let ctx = HookContext::builder()
        .correlation_id("abc-123")
        .hook_point(HookPoint::BranchCreate)
        .repository(RepositoryId::default())
        .build();

    assert_eq!(ctx.correlation_id(), "abc-123");
    assert_eq!(ctx.hook_point(), HookPoint::BranchCreate);
}

#[test]
fn test_context_optional_user() {
    // Without user
    let ctx = create_test_context();
    assert!(ctx.user().is_none());

    // With user
    let ctx = HookContext::builder()
        .correlation_id("test")
        .hook_point(HookPoint::BranchPush)
        .repository(RepositoryId::default())
        .user("user@example.com")
        .build();
    assert_eq!(ctx.user(), Some("user@example.com"));
}

#[test]
fn test_context_optional_branch() {
    let ctx = create_test_context();
    assert!(ctx.branch().is_none());

    let branch = Context::default();
    let ctx = HookContext::builder()
        .correlation_id("test")
        .hook_point(HookPoint::BranchPush)
        .repository(RepositoryId::default())
        .branch(branch)
        .build();
    assert_eq!(ctx.branch(), Some(branch));
}

#[test]
fn test_context_optional_revision() {
    let ctx = create_test_context();
    assert!(ctx.revision().is_none());

    let revision = Hash::default();
    let ctx = HookContext::builder()
        .correlation_id("test")
        .hook_point(HookPoint::BranchPush)
        .repository(RepositoryId::default())
        .revision(revision)
        .build();
    assert_eq!(ctx.revision(), Some(revision));
}

#[test]
fn test_context_optional_revision_number() {
    let ctx = create_test_context();
    assert!(ctx.revision_number().is_none());

    let ctx = HookContext::builder()
        .correlation_id("test")
        .hook_point(HookPoint::BranchPush)
        .repository(RepositoryId::default())
        .revision_number(42)
        .build();
    assert_eq!(ctx.revision_number(), Some(42));
}

#[test]
fn test_context_set_revision_number() {
    let mut ctx = create_test_context();
    assert!(ctx.revision_number().is_none());

    ctx.set_revision_number(99);
    assert_eq!(ctx.revision_number(), Some(99));
}

#[test]
fn test_context_metadata() {
    let ctx = create_test_context();
    assert!(ctx.get_metadata("key1").is_none());
    assert!(ctx.metadata().is_empty());

    let ctx = HookContext::builder()
        .correlation_id("test")
        .hook_point(HookPoint::BranchPush)
        .repository(RepositoryId::default())
        .metadata("key1", "value1")
        .metadata("key2", "value2")
        .build();

    assert_eq!(ctx.get_metadata("key1"), Some("value1"));
    assert_eq!(ctx.get_metadata("key2"), Some("value2"));
    assert_eq!(ctx.metadata().len(), 2);
}

#[test]
fn test_context_builder_with_all_fields() {
    let ctx = HookContext::builder()
        .correlation_id("full-test")
        .hook_point(HookPoint::BranchPush)
        .repository(RepositoryId::default())
        .user("test@example.com")
        .branch(Context::default())
        .revision(Hash::default())
        .metadata("key1", "value1")
        .metadata("key2", "value2")
        .build();

    assert_eq!(ctx.correlation_id(), "full-test");
    assert_eq!(ctx.hook_point(), HookPoint::BranchPush);
    assert_eq!(ctx.user(), Some("test@example.com"));
    assert!(ctx.branch().is_some());
    assert!(ctx.revision().is_some());
    assert_eq!(ctx.get_metadata("key1"), Some("value1"));
    assert_eq!(ctx.get_metadata("key2"), Some("value2"));
}

#[test]
fn test_context_builder_try_build_success() {
    let result = HookContext::builder()
        .correlation_id("test")
        .hook_point(HookPoint::BranchPush)
        .repository(RepositoryId::default())
        .try_build();

    assert!(result.is_ok());
}

#[test]
fn test_context_builder_try_build_missing_correlation_id() {
    let result = HookContext::builder()
        .hook_point(HookPoint::BranchPush)
        .repository(RepositoryId::default())
        .try_build();

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("correlation_id"));
}

#[test]
fn test_context_builder_try_build_missing_hook_point() {
    let result = HookContext::builder()
        .correlation_id("test")
        .repository(RepositoryId::default())
        .try_build();

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("hook_point"));
}

#[test]
fn test_context_builder_try_build_missing_repository() {
    let result = HookContext::builder()
        .correlation_id("test")
        .hook_point(HookPoint::BranchPush)
        .try_build();

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("repository"));
}

#[test]
#[should_panic(expected = "correlation_id is required")]
fn test_context_builder_panics_without_correlation_id() {
    HookContext::builder()
        .hook_point(HookPoint::BranchPush)
        .repository(RepositoryId::default())
        .build();
}

#[test]
fn test_context_clone() {
    let ctx = HookContext::builder()
        .correlation_id("original")
        .hook_point(HookPoint::BranchPush)
        .repository(RepositoryId::default())
        .user("original_user")
        .metadata("key", "value")
        .build();

    let cloned = ctx.clone();

    // Verify cloned values match
    assert_eq!(cloned.correlation_id(), "original");
    assert_eq!(cloned.user(), Some("original_user"));
    assert_eq!(cloned.get_metadata("key"), Some("value"));
}

#[test]
fn test_context_debug() {
    let ctx = HookContext::builder()
        .correlation_id("debug-test")
        .hook_point(HookPoint::BranchPush)
        .repository(RepositoryId::default())
        .user("test_user")
        .build();

    let debug_str = format!("{ctx:?}");
    assert!(debug_str.contains("debug-test"));
    assert!(debug_str.contains("BranchPush"));
    assert!(debug_str.contains("test_user"));
}

#[test]
fn test_context_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<HookContext>();
}
