// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_base::retry::*;

#[test]
fn deviation_is_symmetric_about_the_interval() {
    assert_eq!(jittered(100, 0.5, 0.0), 50);
    assert_eq!(jittered(100, 0.5, 0.5), 100);
    assert_eq!(jittered(100, 0.5, 1.0), 150);
}

#[test]
fn deviation_is_capped_in_both_directions() {
    assert_eq!(jittered(1_000, 0.5, 0.0), 1_000 - JITTER_CLAMP_MS);
    assert_eq!(jittered(1_000, 0.5, 1.0), 1_000 + JITTER_CLAMP_MS);
}

#[test]
fn deviation_below_the_cap_stays_proportional() {
    for interval in [1, 2, 50, 100, 199] {
        assert_eq!(jittered(interval, 0.5, 0.0), interval - interval / 2);
        assert_eq!(jittered(interval, 0.5, 1.0), interval + interval / 2);
    }
}

#[test]
fn deviation_never_underflows_the_interval() {
    assert_eq!(jittered(10, 5.0, 0.0), 0);
    assert_eq!(jittered(0, 0.5, 0.0), 0);
}

#[test]
fn sample_outside_the_unit_range_saturates() {
    assert_eq!(jittered(100, 0.5, -1.0), 50);
    assert_eq!(jittered(100, 0.5, 2.0), 150);
}

#[test]
fn zero_jitter_leaves_the_interval_alone() {
    assert_eq!(jittered(750, 0.0, 0.0), 750);
    assert_eq!(jittered(750, 0.0, 1.0), 750);
}
