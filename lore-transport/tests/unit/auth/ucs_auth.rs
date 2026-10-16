// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_base::types::RepositoryId;
use lore_transport::auth::ucs_auth::*;

#[test]
fn grpc_endpoint_ucs_auth() {
    assert_eq!(
        grpc_endpoint("ucs-auth://auth.example.com"),
        "https://auth.example.com"
    );
}

#[test]
fn grpc_endpoint_insecure_maps_to_plaintext() {
    assert_eq!(
        grpc_endpoint("ucs-auth-insecure://localhost:41337"),
        "http://localhost:41337"
    );
}

#[test]
fn grpc_endpoint_https() {
    assert_eq!(
        grpc_endpoint("https://auth.example.com"),
        "https://auth.example.com"
    );
}

#[test]
fn grpc_endpoint_http_to_loopback_is_preserved() {
    assert_eq!(
        grpc_endpoint("http://127.0.0.1:41339"),
        "http://127.0.0.1:41339"
    );
    assert_eq!(
        grpc_endpoint("http://localhost:41339"),
        "http://localhost:41339"
    );
    // A parsed loopback IP literal counts, IPv6 included.
    assert_eq!(grpc_endpoint("http://[::1]:41339"), "http://[::1]:41339");
}

/// The downgrade defence: a rogue server advertising a plaintext variant
/// of a real auth host must not steer login and exchange tokens onto an
/// unencrypted channel. Any non-loopback http URL is upgraded to https.
#[test]
fn grpc_endpoint_http_to_remote_host_is_upgraded() {
    assert_eq!(
        grpc_endpoint("http://auth.example.com"),
        "https://auth.example.com"
    );
    assert_eq!(
        grpc_endpoint("http://auth.example.com:8080/path"),
        "https://auth.example.com:8080/path"
    );
    // A crafted host that merely starts with a local name is not local.
    assert_eq!(
        grpc_endpoint("http://localhost.evil.example"),
        "https://localhost.evil.example"
    );
}

/// Userinfo in the authority is the classic trick against hand-rolled
/// host extraction: the URL's host below is `auth.example.com`, and a
/// splitter taking the first `:`/`/` segment reads `localhost`. Such a
/// URL must never keep plaintext — and any URL carrying userinfo is
/// refused the loopback exemption outright.
#[test]
fn grpc_endpoint_userinfo_cannot_spoof_loopback() {
    assert_eq!(
        grpc_endpoint("http://localhost:password@auth.example.com"),
        "https://localhost:password@auth.example.com"
    );
    assert_eq!(
        grpc_endpoint("http://localhost@auth.example.com"),
        "https://localhost@auth.example.com"
    );
    // Even a genuine loopback host gets no plaintext with userinfo present.
    assert_eq!(
        grpc_endpoint("http://user:password@127.0.0.1:41339"),
        "https://user:password@127.0.0.1:41339"
    );
}

#[test]
fn grpc_endpoint_no_scheme() {
    assert_eq!(
        grpc_endpoint("auth.example.com"),
        "https://auth.example.com"
    );
}

#[test]
fn grpc_endpoint_custom_scheme() {
    assert_eq!(
        grpc_endpoint("custom://auth.example.com:8443/path"),
        "https://auth.example.com:8443/path"
    );
}

#[test]
fn resource_id_format() {
    let repo_id = RepositoryId::default();
    let rid = resource_id(repo_id);
    assert!(rid.starts_with("urc-"));
    // Default RepositoryId is all zeros, displayed as hex
    assert_eq!(rid, "urc-00000000000000000000000000000000");
}
