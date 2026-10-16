// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_revision::node::*;

#[test]
fn clean_chain_passes() {
    let mut guard = SiblingCycleGuard::new(1);
    for id in 2..1000 {
        guard.observe(id).expect("clean chain should not trip");
    }
}

#[test]
fn self_loop_at_head_detected() {
    // A.sibling = A, walked as A, A, A, ...
    let mut guard = SiblingCycleGuard::new(1);
    guard.observe(42).unwrap();
    guard.observe(42).unwrap();
    let err = guard.observe(42).expect_err("self loop must trip");
    assert_eq!(err.node, 42);
    assert_eq!(err.expected_parent, 1);
    assert_eq!(err.actual_parent, 42);
}

#[test]
fn two_cycle_detected() {
    // A -> B -> A -> B -> ...
    let mut guard = SiblingCycleGuard::new(1);
    guard.observe(10).unwrap();
    guard.observe(20).unwrap();
    guard.observe(10).unwrap();
    guard.observe(20).expect_err("two-cycle must trip");
}

#[test]
fn three_cycle_detected() {
    // A -> B -> C -> A -> B -> C -> A ...
    let chain = [10u32, 20, 30, 10, 20, 30, 10];
    let mut guard = SiblingCycleGuard::new(1);
    let mut tripped_at = None;
    for (i, id) in chain.iter().enumerate() {
        if guard.observe(*id).is_err() {
            tripped_at = Some(i);
            break;
        }
    }
    let i = tripped_at.expect("three-cycle must trip");
    assert!(i <= 6, "expected detection within 7 steps, got step {i}");
}

#[test]
fn mid_chain_cycle_detected() {
    // A -> B -> C -> D -> E -> F -> G -> D -> E -> F -> G -> D ...
    let mut chain = vec![10u32, 20, 30, 40, 50, 60, 70];
    for _ in 0..20 {
        chain.extend_from_slice(&[40, 50, 60, 70]);
    }
    let mut guard = SiblingCycleGuard::new(1);
    let mut tripped = false;
    for id in &chain {
        if guard.observe(*id).is_err() {
            tripped = true;
            break;
        }
    }
    assert!(tripped, "mid-chain cycle must trip");
}

#[test]
fn worst_case_bound_holds_for_small_cycles() {
    // For chain length N ≤ 2^k, detection step ≤ 3N.
    // Try several cycle sizes and verify the bound.
    for cycle_len in [1u32, 2, 3, 5, 8, 10, 13, 64, 256] {
        let mut guard = SiblingCycleGuard::new(1);
        let mut steps = 0u32;
        loop {
            let id = 100 + (steps % cycle_len);
            steps += 1;
            if guard.observe(id).is_err() {
                break;
            }
            assert!(
                steps < 3 * cycle_len.max(1) + 10,
                "cycle_len={cycle_len} took {steps} steps, exceeds bound",
            );
        }
    }
}
