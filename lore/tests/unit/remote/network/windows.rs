// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore::remote::network::windows::*;
use windows_sys::Win32::Networking::WinSock;
use windows_sys::Win32::Networking::WinSock::SOCKADDR_UN;

fn written_path(addr: &SOCKADDR_UN) -> String {
    let bytes: Vec<u8> = addr
        .sun_path
        .iter()
        .take_while(|byte| **byte != 0)
        .map(|byte| *byte as u8)
        .collect();
    String::from_utf8(bytes).expect("the path was written as UTF-8")
}

#[test]
fn a_path_that_fits_is_written_with_its_terminator() {
    let path = r"C:\Temp\lore_service";

    let addr = sockaddr_for_path(path).expect("a short path must fit");

    assert_eq!(addr.sun_family, WinSock::AF_UNIX);
    assert_eq!(written_path(&addr), path);
    assert_eq!(addr.sun_path[path.len()], 0, "the path must be terminated");
}

/// A temporary directory or configured socket name long enough to overrun
/// `sun_path` is reported rather than overrunning the copy.
#[test]
fn a_path_longer_than_the_address_is_refused() {
    let path = format!(r"C:\Temp\{}", "n".repeat(200));

    // `SOCKADDR_UN` has no `Debug`, so the success arm is unwrapped by hand
    // rather than through `expect_err`.
    let Err(error) = sockaddr_for_path(&path) else {
        panic!("an overlong path must be refused");
    };

    assert!(error.contains("more than"), "{error}");
    assert!(
        error.contains(&path),
        "the failure must name the path: {error}"
    );
}

/// The terminator needs a byte of its own, so the longest usable path is one
/// short of the array rather than exactly its length.
#[test]
fn a_path_that_exactly_fills_the_address_is_refused() {
    let exact = "a".repeat(SUN_PATH_CAPACITY);

    assert!(
        sockaddr_for_path(&exact).is_err(),
        "a path filling every byte leaves no room to terminate it"
    );
    assert!(
        sockaddr_for_path(&exact[1..]).is_ok(),
        "one byte shorter must fit"
    );
}
