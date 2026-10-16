// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::str::FromStr;

use lore_revision::lore::RepositoryId;
use lore_server::auth::resource_exchange::*;

#[test]
fn resource_indicators_parse_in_every_accepted_form() {
    let hex = "0194b726b34e72b0b45550b88a967076";
    let repository = RepositoryId::from_str(hex).expect("repo id");

    for form in [
        format!("urc-{hex}"),
        hex.to_string(),
        format!("https://lore.example.com/partitions/{hex}"),
        format!("https://lore.example.com/partitions/{hex}/"),
        format!("https://lore.example.com/partitions/urc-{hex}"),
    ] {
        assert_eq!(
            parse_resource_indicator(&form),
            Some(repository),
            "form {form}"
        );
    }

    for rejected in [
        "urc-*",
        "not-a-repository",
        "https://lore.example.com/",
        "https://lore.example.com/partitions/xyz",
    ] {
        assert_eq!(parse_resource_indicator(rejected), None, "form {rejected}");
    }
}
