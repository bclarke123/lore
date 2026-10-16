// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_io::driver::*;

#[test]
fn a_recognised_backend_value_selects_it() {
    assert_eq!(
        backend_kind_from_value("psync").unwrap(),
        BackendKind::Psync
    );
    assert_eq!(
        backend_kind_from_value("PSYNC").unwrap(),
        BackendKind::Psync
    );
    assert_eq!(backend_kind_from_value("auto").unwrap(), BackendKind::Auto);
    assert_eq!(backend_kind_from_value("").unwrap(), BackendKind::Auto);
    #[cfg(target_os = "linux")]
    assert_eq!(
        backend_kind_from_value("uring").unwrap(),
        BackendKind::Uring
    );
    #[cfg(target_family = "windows")]
    assert_eq!(backend_kind_from_value("iocp").unwrap(), BackendKind::Iocp);
}

/// A backend this build has no code for is rejected rather than silently falling back, so a
/// value that works on one platform does not quietly mean something else on another.
#[test]
#[cfg(not(target_os = "linux"))]
fn a_backend_absent_from_this_build_is_rejected() {
    let error = backend_kind_from_value("uring")
        .expect_err("a backend this platform has no code for must not be accepted");

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

/// The mirror of the case above: the Windows completion backend must not be selectable on a
/// platform that has no code for it either.
#[test]
#[cfg(not(target_family = "windows"))]
fn the_completion_port_backend_is_rejected_off_windows() {
    let error = backend_kind_from_value("iocp")
        .expect_err("a backend this platform has no code for must not be accepted");

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

/// The value names the accepted set, because the caller reaching for this variable is
/// diagnosing something and a bare rejection tells them nothing.
#[test]
fn an_unrecognised_backend_value_is_a_reportable_error() {
    let error = backend_kind_from_value("iouring")
        .expect_err("a backend that does not exist must not be accepted");

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    let message = format!("{error}");
    assert!(message.contains("iouring"), "{message}");
    assert!(
        message.contains(&format!("supported: {SUPPORTED_BACKENDS}")),
        "{message}"
    );
}

/// Whatever the environment holds, the process-wide driver resolves rather than panicking.
/// Which backend it lands on depends on the machine, so the name is only checked against the
/// set this build can produce.
#[test]
fn the_global_driver_always_resolves() {
    let name = IoDriver::global().backend_name();
    assert!(["psync", "uring", "iocp"].contains(&name), "{name}");
}

/// The probe never fails: a machine that cannot give it a ring gets the portable backend.
#[test]
fn the_probe_always_yields_a_backend() {
    let driver = IoDriver::new(BackendKind::Auto).expect("auto must always resolve");
    assert!(
        ["psync", "uring", "iocp"].contains(&driver.backend_name()),
        "{driver:?}"
    );
}
