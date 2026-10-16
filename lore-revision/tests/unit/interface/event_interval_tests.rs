// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_revision::interface::*;

fn globals(event_interval_ms: u64) -> LoreGlobalArgs {
    LoreGlobalArgs {
        event_interval_ms,
        ..Default::default()
    }
}

#[test]
fn an_unset_interval_takes_the_default() {
    assert_eq!(
        globals(0).event_interval(),
        std::time::Duration::from_millis(DEFAULT_EVENT_INTERVAL_MS)
    );
}

/// A caller asking for a sub-millisecond tick would spend more on reporting
/// than on the commit, so the floor holds regardless of what was asked.
#[test]
fn an_interval_below_the_floor_is_raised_to_it() {
    assert_eq!(
        globals(1).event_interval(),
        std::time::Duration::from_millis(10)
    );
}

#[test]
fn an_explicit_interval_is_used_as_given() {
    assert_eq!(
        globals(2500).event_interval(),
        std::time::Duration::from_millis(2500)
    );
}
