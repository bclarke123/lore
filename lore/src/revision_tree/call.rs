// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Dispatch helper for the low-level memory-based revision control API.
//!
//! `revision_tree_call` mirrors [`crate::storage::call::storage_call`] but
//! looks up a [`crate::revision_tree::handle::RevisionTreeInternal`]
//! instead of a `StoreInternal`. Every revision-tree verb goes through
//! this helper so the in-flight counter protocol and the `Complete` /
//! `End` event lifecycle apply uniformly.

use std::sync::Arc;
use std::time::Instant;

use lore_base::error::InvalidArguments;
use lore_base::runtime::LORE_CONTEXT;
use lore_error_set::FfiError;
use lore_error_set::HasTrace;
use lore_error_set::prelude::*;
use lore_revision::event::EventError;
use lore_revision::event::LoreErrorDetail;
use lore_revision::interface::LoreError;
use lore_revision::interface::LoreGlobalArgs;
use lore_revision::lore::execution_context;

use crate::call::setup_execution;
use crate::interface::LoreEventCallback;
use crate::revision_tree::handle::LoreRevisionTree;
use crate::revision_tree::handle::RevisionTreeGuard;
use crate::revision_tree::handle::RevisionTreeInternal;
use crate::util::log_command_done;
use crate::util::log_command_info;

/// Errors emitted by the dispatch helper itself (not by the verb impl).
#[lore_macro::test_pub]
#[error_set]
enum DispatchError {
    InvalidArguments,
}

impl EventError for DispatchError {
    fn translated(&self) -> LoreError {
        match self {
            DispatchError::InvalidArguments(_) => LoreError::InvalidArguments,
            DispatchError::Internal(_) => LoreError::Internal,
        }
    }

    fn inner(&self) -> String {
        self.to_string()
    }
}

/// Run a revision-tree verb behind the in-flight counter protocol.
///
/// The helper:
/// 1. Sets up an `ExecutionContext` and enters its `LORE_CONTEXT` scope.
/// 2. Acquires a [`RevisionTreeGuard`] for the handle. If the handle is
///    unknown or already closed, invokes `on_handle_miss` with the arguments
///    (letting the verb emit its own `*Complete` terminal carrying the caller
///    id, or one per entry for a batch verb), then completes with the
///    handle-miss error detail and returns its error code without invoking the
///    verb impl.
/// 3. Passes a cloned `Arc<RevisionTreeInternal>` to the verb impl
///    (ownership transferred; the impl can fan it out to spawned tasks).
/// 4. Translates the impl's `Result` into a `Complete{status}` event.
/// 5. Drops the `RevisionTreeGuard` only *after* `Complete` fires — so
///    the in-flight counter decrement orders after the last result event.
///
/// # Contract expected of `command`
///
/// All work (including spawned tasks) the verb initiates must complete
/// before the returned future resolves — no background work outlives a
/// data verb. Use `JoinSet` / `join_all` to await spawned futures before
/// returning.
///
/// The verb reaches the handle's tree through
/// [`access_shared`](crate::revision_tree::handle::RevisionTreeInternal::access_shared) or
/// [`access_exclusive`](crate::revision_tree::handle::RevisionTreeInternal::access_exclusive),
/// which is where a call states whether it can share the handle. This helper does not
/// take that lock: a verb holds it for as long as it uses the state, and taking it here
/// as well would deadlock, since `tokio::sync::RwLock` is write-preferring and a second
/// read waits behind a queued writer.
#[lore_macro::test_pub]
pub(crate) async fn revision_tree_call<Arg, T, F, Fut, ResT, ErrT, M>(
    globals: LoreGlobalArgs,
    callback: LoreEventCallback,
    handle: LoreRevisionTree,
    args: Arg,
    caller: T,
    on_handle_miss: M,
    command: F,
) -> i32
where
    ErrT: EventError + FfiError + HasTrace,
    Arg: std::fmt::Debug,
    M: FnOnce(&Arg),
    F: FnOnce(Arc<RevisionTreeInternal>, Arg) -> Fut,
    Fut: Future<Output = Result<ResT, ErrT>> + 'static,
{
    let execution = setup_execution(globals, callback);

    LORE_CONTEXT
        .scope(execution, async move {
            let Some(guard) = RevisionTreeGuard::enter(handle) else {
                on_handle_miss(&args);
                let err = DispatchError::from(InvalidArguments {
                    reason: "revision tree handle is unknown or has been closed".into(),
                });
                return execution_context()
                    .dispatcher
                    .complete(LoreErrorDetail::from_error(&err))
                    .await;
            };

            log_command_info(&caller, &args);
            let time_start = Instant::now();

            let internal = guard.internal_clone();
            let detail = LoreErrorDetail::from_result(command(internal, args).await);

            log_command_done(&caller, time_start);
            let status = execution_context().dispatcher.complete(detail).await;
            drop(guard);
            status
        })
        .await
}
