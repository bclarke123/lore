// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Tests that observe what the process-global discovery cache holds. They run in a process of
//! their own, one after the other, so no other test inserts or evicts entries meanwhile.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use lore_transport::auth::oidc::discovery::CACHE;
use lore_transport::auth::oidc::discovery::DiscoveryError;
use lore_transport::auth::oidc::discovery::MAX_CACHED_ISSUERS;
use lore_transport::auth::oidc::discovery::discover;
use tokio::sync::watch;

#[path = "support/oidc_provider.rs"]
mod provider;

use provider::*;

fn is_cached(issuer: &str) -> bool {
    CACHE.lock().slots.contains_key(issuer)
}

#[tokio::test]
async fn discovery_cache() {
    concurrent_calls_for_one_issuer_fetch_once().await;
    a_waiter_on_a_failed_fetch_refetches_once_and_caches_the_result().await;
    a_failed_fetch_leaves_no_cache_entry().await;
    a_full_cache_evicts_the_least_recently_used_issuer().await;
    an_issuer_being_fetched_is_not_evicted().await;
}

/// Both calls are waiting on the cache before the provider answers, so a second fetch
/// would reach the provider as a second request.
async fn concurrent_calls_for_one_issuer_fetch_once() {
    let (open, gate) = watch::channel(false);
    let provider = spawn_gated_provider(gate, conforming).await;

    let release = async {
        wait_for_requests(&provider, 1).await;
        open.send(true).expect("provider alive");
    };
    let (first, second, ()) = tokio::join!(
        discover(&provider.issuer),
        discover(&provider.issuer),
        release
    );

    let first = first.expect("first call succeeds");
    let second = second.expect("second call succeeds");
    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(provider.requests.load(Ordering::SeqCst), 1);

    discover(&provider.issuer).await.expect("cached");
    assert_eq!(provider.requests.load(Ordering::SeqCst), 1);
}

/// A caller waiting on a fetch that fails makes one new fetch, and its result is cached.
/// Without coordination the waiter could fetch into the removed entry while a later caller
/// fetched into a new one.
async fn a_waiter_on_a_failed_fetch_refetches_once_and_caches_the_result() {
    let (open, gate) = watch::channel(false);
    let provider = spawn_gated_provider(gate, |issuer, request| match request {
        0 => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        _ => conforming(issuer, request),
    })
    .await;

    let release = async {
        wait_for_requests(&provider, 1).await;
        open.send(true).expect("provider alive");
    };
    let (first, second, ()) = tokio::join!(
        discover(&provider.issuer),
        discover(&provider.issuer),
        release
    );

    assert!(
        matches!(first, Err(DiscoveryError::Status { status: 503, .. })),
        "{first:?}"
    );
    second.expect("the waiter fetches again and succeeds");
    discover(&provider.issuer).await.expect("cached");
    assert_eq!(provider.requests.load(Ordering::SeqCst), 2);
    assert!(is_cached(&provider.issuer));
}

/// A failed fetch leaves no entry behind, so issuers that never answer do not accumulate.
async fn a_failed_fetch_leaves_no_cache_entry() {
    let failing = spawn_provider(|_, _| StatusCode::NOT_FOUND.into_response()).await;
    let succeeding = spawn_provider(conforming).await;

    discover(&failing.issuer)
        .await
        .expect_err("the provider answers 404");
    discover(&succeeding.issuer)
        .await
        .expect("discovery succeeds");

    assert!(!is_cached(&failing.issuer));
    assert!(is_cached(&succeeding.issuer));
}

/// The cache stays at its cap, a new issuer is cached by evicting the issuer least recently
/// looked up rather than the oldest inserted, and an evicted issuer is fetched again.
async fn a_full_cache_evicts_the_least_recently_used_issuer() {
    let mut cached = Vec::new();
    for _ in 0..MAX_CACHED_ISSUERS {
        let provider = spawn_provider(conforming).await;
        discover(&provider.issuer)
            .await
            .expect("discovery succeeds");
        cached.push(provider);
    }
    discover(&cached[0].issuer).await.expect("cached");

    let overflow = spawn_provider(conforming).await;
    for _ in 0..2 {
        discover(&overflow.issuer)
            .await
            .expect("discovery succeeds");
    }
    assert_eq!(overflow.requests.load(Ordering::SeqCst), 1);
    assert!(is_cached(&overflow.issuer));
    assert!(is_cached(&cached[0].issuer));
    assert!(!is_cached(&cached[1].issuer));
    assert_eq!(CACHE.lock().slots.len(), MAX_CACHED_ISSUERS);

    discover(&cached[1].issuer).await.expect("fetched again");
    assert_eq!(cached[1].requests.load(Ordering::SeqCst), 2);
    discover(&cached[0].issuer).await.expect("cached");
    assert_eq!(cached[0].requests.load(Ordering::SeqCst), 1);
    assert_eq!(CACHE.lock().slots.len(), MAX_CACHED_ISSUERS);
}

/// An issuer whose fetch is still running is passed over for eviction, even when it is the
/// least recently used, so it is fetched once.
async fn an_issuer_being_fetched_is_not_evicted() {
    let (open, gate) = watch::channel(false);
    let pending = spawn_gated_provider(gate, conforming).await;

    let fill_behind = async {
        wait_for_requests(&pending, 1).await;
        for _ in 0..MAX_CACHED_ISSUERS {
            let provider = spawn_provider(conforming).await;
            discover(&provider.issuer)
                .await
                .expect("discovery succeeds");
        }
        assert!(is_cached(&pending.issuer), "the pending issuer survived");
        open.send(true).expect("provider alive");
    };
    let (document, ()) = tokio::join!(discover(&pending.issuer), fill_behind);

    document.expect("discovery succeeds");
    discover(&pending.issuer).await.expect("cached");
    assert_eq!(pending.requests.load(Ordering::SeqCst), 1);
    assert_eq!(CACHE.lock().slots.len(), MAX_CACHED_ISSUERS);
}
