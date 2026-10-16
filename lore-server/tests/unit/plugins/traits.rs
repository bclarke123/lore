// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_base::error::PluginConfigError;
use lore_base::error::PluginInitError;
use lore_base::error::PluginNotFound;
use lore_server::plugins::traits::*;

#[test]
fn test_plugin_error_not_found_display() {
    let err: PluginError = PluginNotFound {
        plugin_name: "test_plugin".to_string(),
        available_plugins: vec!["available1".to_string(), "available2".to_string()],
    }
    .into();
    assert!(err.is_plugin_not_found());
    let msg = err.to_string();
    assert!(msg.contains("test_plugin"));
    assert!(msg.contains("not found"));
    assert!(msg.contains("available1"));
    assert!(msg.contains("available2"));
}

#[test]
fn test_plugin_error_not_found_empty_list() {
    let err: PluginError = PluginNotFound {
        plugin_name: "test_plugin".to_string(),
        available_plugins: vec![],
    }
    .into();
    let msg = err.to_string();
    assert!(msg.contains("test_plugin"));
    assert!(msg.contains("none"));
}

#[test]
fn test_plugin_error_config_display() {
    let err: PluginError = PluginConfigError {
        plugin_name: "test_plugin".to_string(),
        message: "missing field 'path'".to_string(),
    }
    .into();
    assert!(err.is_plugin_config_error());
    let msg = err.to_string();
    assert!(msg.contains("test_plugin"));
    assert!(msg.contains("configuration error"));
    assert!(msg.contains("missing field 'path'"));
}

#[test]
fn test_plugin_error_init_display() {
    let err: PluginError = PluginInitError {
        plugin_name: "test_plugin".to_string(),
        message: "failed to connect to database".to_string(),
    }
    .into();
    assert!(err.is_plugin_init_error());
    let msg = err.to_string();
    assert!(msg.contains("test_plugin"));
    assert!(msg.contains("initialization failed"));
    assert!(msg.contains("failed to connect to database"));
}
