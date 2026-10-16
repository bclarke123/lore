// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_revision::repository::StoreConfig;
use lore_revision::repository::incremental_gc_options;

/// The default GC caps that back the automatic incremental GC on writes when a
/// repository has no `[store]` config must be populated and non-zero; otherwise the
/// evictor and compactor would be spawned with zero caps (`Some(0)`) and never run.
#[test]
fn client_default_yields_nonzero_gc_caps() {
    let options = StoreConfig::client_default().to_options();
    assert!(options.max_capacity.is_some_and(|c| c > 0));
    assert!(options.max_size.is_some_and(|s| s > 0));
}

#[test]
fn write_op_spawns_incremental_gc_by_default() {
    // Write op, `--no-gc` not set, no `[store]` config: incremental GC on with
    // the non-zero `client_default` caps.
    let options = incremental_gc_options(false, false, None);
    assert!(options.max_capacity.is_some_and(|c| c > 0));
    assert!(options.max_size.is_some_and(|s| s > 0));
}

#[test]
fn no_gc_suppresses_incremental_gc() {
    let options = incremental_gc_options(false, true, None);
    assert!(options.max_capacity.is_none());
    assert!(options.max_size.is_none());
}

#[test]
fn read_only_op_never_spawns_incremental_gc() {
    let options = incremental_gc_options(true, false, None);
    assert!(options.max_capacity.is_none());
    assert!(options.max_size.is_none());
}
