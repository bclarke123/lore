// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::collections::HashMap;

use lore_server::store::configuration::*;

#[test]
fn test_resolve_plugin_config_direct() {
    let mut plugins = HashMap::new();
    plugins.insert(
        "local".to_string(),
        toml::from_str::<toml::Value>("path = '/data'").expect("valid toml"),
    );

    let config = resolve_plugin_config(&plugins, "local", None);
    assert!(config.is_some());
    assert_eq!(
        config
            .expect("should exist")
            .get("path")
            .expect("should have path")
            .as_str()
            .expect("should be string"),
        "/data"
    );
}

#[test]
fn test_resolve_plugin_config_nested() {
    let config_str = r#"
            [http]
            timeout = 5000

            [immutable_store]
            path = "/data/immutable"
            max_size = 1000000
        "#;
    let mut plugins = HashMap::new();
    plugins.insert(
        "local".to_string(),
        toml::from_str::<toml::Value>(config_str).expect("valid toml"),
    );

    let config = resolve_plugin_config(&plugins, "local", Some("immutable_store"));
    assert!(config.is_some());
    let config = config.expect("should exist");

    // Should have both parent http settings and nested settings
    assert!(config.get("http").is_some());
    assert_eq!(
        config
            .get("path")
            .expect("should have path")
            .as_str()
            .expect("should be string"),
        "/data/immutable"
    );
}

#[test]
fn test_resolve_plugin_config_missing() {
    let plugins = HashMap::new();
    let config = resolve_plugin_config(&plugins, "nonexistent", None);
    assert!(config.is_none());
}

#[test]
fn test_resolve_plugin_config_with_fallback() {
    let mut plugins = HashMap::new();
    plugins.insert(
        "aws".to_string(),
        toml::from_str::<toml::Value>("region = 'us-east-1'").expect("valid toml"),
    );

    // Should fall back to general config when store-specific doesn't exist
    let config = resolve_plugin_config_with_fallback(&plugins, "aws", "immutable_store");
    assert!(config.is_some());
    let config = config.expect("should exist");
    assert_eq!(
        config
            .get("region")
            .expect("should have region")
            .as_str()
            .expect("should be string"),
        "us-east-1"
    );
}

#[test]
fn test_has_plugin_config() {
    let mut plugins = HashMap::new();
    plugins.insert("aws".to_string(), toml::Value::Table(toml::map::Map::new()));

    assert!(has_plugin_config(&plugins, "aws"));
    assert!(!has_plugin_config(&plugins, "nonexistent"));
}

#[test]
fn test_merge_plugin_configs() {
    let parent: toml::Value = toml::from_str(
        r#"
            shared = "value"
            [http]
            timeout = 5000
        "#,
    )
    .expect("valid toml");

    let child: toml::Value = toml::from_str(
        r#"
            path = "/data"
            shared = "overridden"
        "#,
    )
    .expect("valid toml");

    let merged = merge_plugin_configs(&parent, &child);
    let table = merged.as_table().expect("should be table");

    // Child values present
    assert_eq!(
        table
            .get("path")
            .expect("should have path")
            .as_str()
            .expect("should be string"),
        "/data"
    );
    // Child overrides parent
    assert_eq!(
        table
            .get("shared")
            .expect("should have shared")
            .as_str()
            .expect("should be string"),
        "overridden"
    );
    // Parent values preserved
    assert!(table.get("http").is_some());
}

#[test]
fn test_empty_plugin_config() {
    let config = empty_plugin_config();
    assert!(config.is_table());
    assert!(config.as_table().expect("should be table").is_empty());
}

#[test]
fn test_store_config_error_display() {
    let err = missing_config_error("aws");
    assert!(err.is_plugin_config_error());
    let msg = err.to_string();
    assert!(msg.contains("aws"));
    assert!(msg.contains("Missing plugin configuration"));
}

#[test]
fn test_store_config_error_from_plugin_not_found() {
    use lore_base::error::PluginNotFound;

    let store_error: StoreConfigError = PluginNotFound {
        plugin_name: "test".to_string(),
        available_plugins: vec!["local".to_string()],
    }
    .into();
    assert!(store_error.is_plugin_not_found());
}
