// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::str::FromStr;

use lore_revision::access::AccessGrants;
use lore_revision::access::AccessRole;

#[test]
fn role_verbs_are_ordered_supersets() {
    assert_eq!(AccessRole::Read.verbs(), ["read"]);
    assert_eq!(AccessRole::Write.verbs(), ["read", "write"]);
    for verb in AccessRole::Write.verbs() {
        assert!(AccessRole::Admin.verbs().contains(verb));
    }
    assert!(AccessRole::Admin.verbs().contains(&"owner"));
    assert!(AccessRole::Admin.verbs().contains(&"obliterate"));
}

#[test]
fn role_parsing_round_trips() {
    for role in [AccessRole::Read, AccessRole::Write, AccessRole::Admin] {
        assert_eq!(AccessRole::from_str(role.as_str()).unwrap(), role);
    }
    assert!(AccessRole::from_str("owner").is_err());
}

#[test]
fn grants_serialize_stably() {
    let mut grants = AccessGrants::new();
    grants.insert("google:123".to_string(), AccessRole::Admin);
    grants.insert("static:alice".to_string(), AccessRole::Read);
    let json = serde_json::to_string(&grants).unwrap();
    assert_eq!(json, r#"{"google:123":"admin","static:alice":"read"}"#);
    let parsed: AccessGrants = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, grants);
}
