// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_base::types::LockData;
use lore_revision::lock::file::acquire::*;
use lore_revision::lock::util::fold_batch_results;

/// Builds a batch error shaped like the one a batch task produces: the
/// remote's denial forwarded under the generic acquire context.
fn denied_batch_error() -> AcquireError {
    AcquireError::internal("resource already locked").forward("Failed to acquire the lock")
}

#[test]
fn batch_denial_reason_survives_the_fold() {
    let denial = denied_batch_error();
    let reported = denial.to_string();

    let (locks, num_batch_success, first_batch_error) = fold_batch_results::<LockData, _>(
        vec![Err(denial), Err(AcquireError::internal("a later batch"))],
        0,
    );

    assert!(locks.is_empty());
    assert_eq!(num_batch_success, 0);
    assert_eq!(
        first_batch_error
            .expect("a failing batch keeps its error")
            .to_string(),
        reported
    );
}

#[test]
fn batch_denial_reason_reaches_the_message() {
    let reported = denied_batch_error().to_string();

    assert!(
        reported.ends_with("resource already locked"),
        "the remote's reason is not in the reported message: {reported}"
    );
}
