// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_proto::lore::access::v1::repository_ref::Ref;
use lore_transport::access_admin::*;

#[test]
fn channel_url_follows_scheme_convention() {
    assert_eq!(
        channel_url("grpc://localhost:5000").expect("url"),
        "http://localhost:5000"
    );
    assert_eq!(
        channel_url("grpcs://lore.example.com").expect("url"),
        "https://lore.example.com:443"
    );
    assert_eq!(
        channel_url("https://lore.example.com:8443").expect("url"),
        "https://lore.example.com:8443"
    );
    assert_eq!(
        channel_url("urc://lore.example.com").expect("url"),
        "http://lore.example.com:41337"
    );
    assert!(channel_url("not a url").is_err());
}

#[test]
fn repository_refs_map_to_proto() {
    let global = AccessRepositoryRef::Global.into_proto();
    match global.r#ref.expect("ref") {
        Ref::Id(bytes) => assert!(bytes.iter().all(|b| *b == 0)),
        Ref::Name(_) => panic!("expected id"),
    }
    let named = AccessRepositoryRef::Name("project1".to_string()).into_proto();
    match named.r#ref.expect("ref") {
        Ref::Name(name) => assert_eq!(name, "project1"),
        Ref::Id(_) => panic!("expected name"),
    }
}
