// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore::interface::LoreFragmentStatsData;
use lore_client::stats_display::percent;
use lore_client::stats_display::prepared_payload;

#[test]
fn a_zero_total_yields_a_zero_share_rather_than_a_panic() {
    assert_eq!(percent(0, 0), 0.0);
    assert_eq!(percent(5, 0), 0.0);
}

#[test]
fn a_share_is_a_percentage_of_its_total() {
    assert_eq!(percent(1, 4), 25.0);
    assert_eq!(percent(4, 4), 100.0);
}

#[test]
fn prepared_payload_covers_both_kinds_of_output() {
    let fragments = LoreFragmentStatsData {
        data_payload_bytes: 900,
        fragmentlist_payload_bytes: 100,
        ..Default::default()
    };

    assert_eq!(prepared_payload(&fragments), 1000);
}
