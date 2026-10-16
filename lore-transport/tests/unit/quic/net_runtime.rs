// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_transport::quic::net_runtime::*;
use quinn::Runtime;

/// The point of the type: a spawn lands on net however the caller was reached. Without the
/// runtime it would follow the caller, which here is the test's own runtime.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn spawns_on_net_rather_than_the_calling_runtime() {
    let (sender, receiver) = tokio::sync::oneshot::channel();

    NetRuntime.spawn(Box::pin(async move {
        let thread = std::thread::current()
            .name()
            .unwrap_or_default()
            .to_string();
        let _ = sender.send(thread);
    }));

    let thread = receiver.await.expect("spawned task ran");
    assert!(
        thread.starts_with("lore-net"),
        "quinn task ran on {thread} rather than a net worker"
    );
}
