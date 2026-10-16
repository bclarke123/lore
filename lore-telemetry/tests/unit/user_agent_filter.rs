// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_telemetry::user_agent_filter::NormalizeOutput;
use lore_telemetry::user_agent_filter::UserAgentFilter;

fn assert_known(output: NormalizeOutput, expected: &str) {
    match output {
        NormalizeOutput::KnownAgent(label) => assert_eq!(&*label, expected),
        NormalizeOutput::Unknown => panic!("expected KnownAgent, got Unknown"),
    }
}

fn assert_unknown(output: NormalizeOutput) {
    assert!(matches!(output, NormalizeOutput::Unknown));
}

#[test]
fn no_patterns_allows_all() {
    let filter = UserAgentFilter::new::<String>(&[]).unwrap();
    assert_known(filter.normalize("my-client/1.0"), "my-client/1.0");
}

#[test]
fn default_filter_allows_all() {
    let filter = UserAgentFilter::default();
    assert_known(filter.normalize("anything"), "anything");
}

#[test]
fn matching_pattern_passes_through() {
    let filter = UserAgentFilter::new(&["my-client/.*"]).unwrap();
    assert_known(filter.normalize("my-client/1.0"), "my-client/1.0");
}

#[test]
fn non_matching_maps_to_unknown() {
    let filter = UserAgentFilter::new(&["my-client/.*"]).unwrap();
    assert_unknown(filter.normalize("other-client/1.0"));
}

#[test]
fn multiple_patterns_any_match_passes_through() {
    let filter = UserAgentFilter::new(&["my-client/.*", "other-client/.*"]).unwrap();
    assert_known(filter.normalize("other-client/1.0"), "other-client/1.0");
}

#[test]
fn invalid_regex_returns_error() {
    assert!(UserAgentFilter::new(&["[invalid"]).is_err());
}

#[test]
fn partial_pattern_match_passes_through() {
    let filter = UserAgentFilter::new(&["my-client"]).unwrap();
    assert_known(filter.normalize("my-client/1.0"), "my-client/1.0");
}

#[test]
fn zero_sample_rate_always_unknown() {
    let filter = UserAgentFilter::new(&["my-client/.*"])
        .unwrap()
        .with_unknown_sample_rate(0.0);
    for _ in 0..100 {
        assert_unknown(filter.normalize("other-client/1.0"));
    }
}

#[test]
fn full_sample_rate_still_returns_unknown_label() {
    // Sampling logs the value but the metric label is always <unknown>.
    let filter = UserAgentFilter::new(&["my-client/.*"])
        .unwrap()
        .with_unknown_sample_rate(1.0);
    assert_unknown(filter.normalize("other-client/1.0"));
}

#[test]
fn sample_rate_clamped_above_one() {
    let filter = UserAgentFilter::new(&["my-client/.*"])
        .unwrap()
        .with_unknown_sample_rate(2.0);
    assert_unknown(filter.normalize("other-client/1.0"));
}

#[test]
fn sample_rate_clamped_below_zero() {
    let filter = UserAgentFilter::new(&["my-client/.*"])
        .unwrap()
        .with_unknown_sample_rate(-1.0);
    assert_unknown(filter.normalize("other-client/1.0"));
}
