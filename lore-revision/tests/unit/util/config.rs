// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
// Fixtures write config files directly; what these test is how loading and saving read them.
#![allow(clippy::disallowed_methods)]

use lore_revision::util::config::*;
use serde::Deserialize;
use serde::Serialize;

#[derive(Default, Serialize, Deserialize, PartialEq, Debug)]
struct Settings {
    name: String,
}

#[tokio::test]
async fn an_absent_config_is_the_default() {
    let dir = lore_base::test_util::TempDir::new("lore-config-test-");
    let config: Settings = load(dir.path().join("absent.toml"))
        .await
        .expect("an absent config defaults");
    assert_eq!(config, Settings::default());
}

#[tokio::test]
async fn a_config_round_trips() {
    let dir = lore_base::test_util::TempDir::new("lore-config-test-");
    let path = dir.path().join("settings.toml");
    std::fs::write(&path, b"name = \"configured\"\n").expect("write config");

    let config: Settings = load(&path).await.expect("a valid config loads");
    assert_eq!(config.name, "configured");
}

/// A present file that is not text is an error rather than a default: an empty string parses
/// as empty TOML, so defaulting here would be indistinguishable from a deliberate default.
#[tokio::test]
async fn a_config_that_is_not_text_is_an_error() {
    let dir = lore_base::test_util::TempDir::new("lore-config-test-");
    let path = dir.path().join("settings.toml");
    std::fs::write(&path, [0xFF, 0xFE, 0x00, 0x80]).expect("write config");

    assert!(load::<Settings>(&path).await.is_err());
}

#[tokio::test]
async fn a_config_that_is_not_toml_is_an_error() {
    let dir = lore_base::test_util::TempDir::new("lore-config-test-");
    let path = dir.path().join("settings.toml");
    std::fs::write(&path, b"this is not toml = = =").expect("write config");

    assert!(load::<Settings>(&path).await.is_err());
}

/// A present-but-unreadable config must not read as a default, or the next save would write
/// that default back over a configuration that was merely inaccessible.
#[tokio::test]
async fn a_config_that_cannot_be_read_is_an_error() {
    let dir = lore_base::test_util::TempDir::new("lore-config-test-");
    let path = dir.path().join("settings.toml");
    std::fs::create_dir(&path).expect("occupy the config path");

    assert!(load::<Settings>(&path).await.is_err());
}

#[test]
fn a_blocking_load_of_an_absent_config_is_the_default() {
    let dir = lore_base::test_util::TempDir::new("lore-config-test-");
    let config: Settings =
        load_blocking(dir.path().join("absent.toml")).expect("an absent config defaults");
    assert_eq!(config, Settings::default());
}

/// The blocking loader is the one the repository config uses on the startup path, and it
/// used to default on every read failure — including a `.lore` that could not be opened,
/// which presented as a repository with no remote.
#[test]
fn a_blocking_load_of_a_config_that_cannot_be_read_is_an_error() {
    let dir = lore_base::test_util::TempDir::new("lore-config-test-");
    let path = dir.path().join("settings.toml");
    std::fs::create_dir(&path).expect("occupy the config path");

    assert!(load_blocking::<Settings>(&path).is_err());
}

#[tokio::test]
async fn a_save_replaces_the_config_and_leaves_no_temporary_file() {
    let dir = lore_base::test_util::TempDir::new("lore-config-test-");
    let path = dir.path().join("settings.toml");
    std::fs::write(&path, b"name = \"original\"\n").expect("write config");

    save(
        &Settings {
            name: "replacement".to_owned(),
        },
        &path,
    )
    .await
    .expect("a save replaces the config");

    let config: Settings = load(&path).await.expect("the saved config loads");
    assert_eq!(config.name, "replacement");
    assert!(!temp_path(&path).exists());
}

/// Occupying the temporary path with a directory fails the write that precedes the rename,
/// standing in for a crash or a full disk at the same point.
#[tokio::test]
async fn a_save_that_fails_before_the_rename_keeps_the_previous_config() {
    let dir = lore_base::test_util::TempDir::new("lore-config-test-");
    let path = dir.path().join("settings.toml");
    std::fs::write(&path, b"name = \"original\"\n").expect("write config");
    std::fs::create_dir(temp_path(&path)).expect("occupy the temporary path");

    assert!(
        save(
            &Settings {
                name: "replacement".to_owned(),
            },
            &path,
        )
        .await
        .is_err()
    );

    let config: Settings = load(&path).await.expect("the previous config loads");
    assert_eq!(config.name, "original");
}

/// A save failure is the only message a user gets for an interrupted write, so it has to say
/// which file it was writing and which one still holds a good copy.
#[tokio::test]
async fn a_failed_save_names_the_target_and_the_temporary() {
    let dir = lore_base::test_util::TempDir::new("lore-config-test-");
    let path = dir.path().join("settings.toml");
    std::fs::write(&path, b"name = \"original\"\n").expect("write config");
    std::fs::create_dir(temp_path(&path)).expect("occupy the temporary path");

    let error = save(
        &Settings {
            name: "replacement".to_owned(),
        },
        &path,
    )
    .await
    .expect_err("a save onto an occupied temporary path fails");

    let message = error.to_string();
    assert!(
        message.contains(&temp_path(&path).display().to_string()),
        "the error must name the temporary it failed to write: {message}"
    );
    assert!(
        message.contains(&path.display().to_string()),
        "the error must name the config it was saving: {message}"
    );
}
