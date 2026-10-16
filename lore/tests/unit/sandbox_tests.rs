// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
/// Asserted on what the library resolves rather than on the variable, since
/// a name that did not take effect is the failure worth catching.
#[test]
fn the_global_config_resolves_inside_the_sandbox() {
    let configured = std::env::var("LORE_GLOBAL_PATH").expect("the constructor names the sandbox");
    let resolved = lore_revision::global::get_global_config_dir()
        .expect("the global config directory resolves");

    assert!(
        resolved.starts_with(&configured),
        "the library resolved {}, outside the sandbox at {configured}",
        resolved.display()
    );
}

/// On the default name, the round trip in `remote::network` binds the socket
/// a developer's own service answers on.
#[test]
fn the_service_socket_is_this_processs_own() {
    assert_ne!(
        lore::remote::service_socket_name(),
        lore::remote::LORE_SERVICE_SOCKET_NAME,
        "the default socket is the one every service on the machine answers on"
    );
}
