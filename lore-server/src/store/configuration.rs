// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Store configuration helpers using the plugin system.
//!
//! This module provides functions for creating store instances via the
//! plugin registry, abstracting away the direct dependencies on specific
//! store implementations.
//!
//! # Overview
//!
//! The store configuration system follows a two-step pattern:
//!
//! 1. **Mode Selection** - Configuration files specify which plugin to use:
//!    ```toml
//!    [immutable_store]
//!    mode = "aws"  # or "local", "composite", "remote"
//!    ```
//!
//! 2. **Plugin Configuration** - Plugin-specific settings go in `[plugins.{mode}]`:
//!    ```toml
//!    [plugins.aws]
//!    immutable_store.s3_bucket = "my-bucket"
//!    immutable_store.dynamodb_fragments_table = "fragments"
//!    ```

use std::collections::HashMap;
use std::sync::Arc;

use lore_base::error::PluginConfigError;
use lore_base::error::PluginInitError;
use lore_base::error::PluginNotFound;
use lore_error_set::prelude::*;
use lore_revision::lock::LockStore;
use lore_storage::ImmutableStore;
use lore_storage::MutableStore;
use tracing::info;

use crate::plugins::PluginRegistry;

/// Error type for store configuration.
///
/// Shares the plugin variants with [`crate::plugins::PluginError`] so
/// `.forward()` from the registry preserves the actionable signal.
/// `MissingConfig` and `InvalidMode` are surfaced via `PluginConfigError`
/// with the `mode` as the plugin name — operators fix the corresponding
/// config section either way.
#[error_set]
pub enum StoreConfigError {
    PluginNotFound,
    PluginConfigError,
    PluginInitError,
}

/// Constructs a "missing plugin configuration" error with the legacy display format.
pub fn missing_config_error(mode: &str) -> StoreConfigError {
    PluginConfigError {
        plugin_name: mode.to_string(),
        message: format!(
            "Missing plugin configuration for mode '{mode}'. Expected [plugins.{mode}] section."
        ),
    }
    .into()
}

/// Constructs an "invalid store mode" error with the legacy display format.
pub fn invalid_mode_error(mode: &str) -> StoreConfigError {
    PluginConfigError {
        plugin_name: mode.to_string(),
        message: format!("Invalid store mode: {mode}"),
    }
    .into()
}

/// Creates an immutable store instance using the plugin registry.
///
/// # Arguments
///
/// * `registry` - The plugin registry containing registered factories
/// * `mode` - The plugin name to use (e.g., "aws", "local")
/// * `plugin_config` - Plugin-specific configuration from `[plugins.{mode}]`
///
/// # Returns
///
/// An `Arc<dyn ImmutableStore>` on success, or a `StoreConfigError` on failure.
///
/// # Example
///
/// ```
/// use lore_server::plugins::PluginRegistry;
/// use lore_server::store::configuration::{create_immutable_store_with_registry, StoreConfigError};
///
/// // Create a registry and register plugins
/// let mut registry = PluginRegistry::new();
/// lore_server::plugins::register_all_plugins(&mut registry);
///
/// // List available plugins
/// let available = registry.list_immutable_store_plugins();
/// println!("Available plugins: {:?}", available);
///
/// // Attempting to create a store with an unregistered plugin returns an error
/// let config: toml::Value = toml::from_str(r#"
///     path = "/data/store"
/// "#).expect("valid TOML");
///
/// let result = create_immutable_store_with_registry(&registry, "nonexistent", &config);
/// assert!(result.expect_err("should fail").is_plugin_not_found());
/// ```
pub fn create_immutable_store_with_registry(
    registry: &PluginRegistry,
    mode: &str,
    plugin_config: &toml::Value,
) -> Result<Arc<dyn ImmutableStore>, StoreConfigError> {
    info!(mode, "Creating immutable store via plugin system");
    registry
        .create_immutable_store(mode, plugin_config)
        .forward("creating immutable store")
}

/// Creates a mutable store instance using the plugin registry.
///
/// # Arguments
///
/// * `registry` - The plugin registry containing registered factories
/// * `mode` - The plugin name to use (e.g., "aws", "local")
/// * `plugin_config` - Plugin-specific configuration from `[plugins.{mode}]`
///
/// # Returns
///
/// An `Arc<dyn MutableStore>` on success, or a `StoreConfigError` on failure.
pub fn create_mutable_store_with_registry(
    registry: &PluginRegistry,
    mode: &str,
    plugin_config: &toml::Value,
    immutable_store: Arc<dyn ImmutableStore>,
) -> Result<Arc<dyn MutableStore>, StoreConfigError> {
    info!(mode, "Creating mutable store via plugin system");
    registry
        .create_mutable_store(mode, plugin_config, immutable_store)
        .forward("creating mutable store")
}

/// Creates a lock store instance using the plugin registry.
///
/// # Arguments
///
/// * `registry` - The plugin registry containing registered factories
/// * `mode` - The plugin name to use (e.g., "dynamodb", "local")
/// * `plugin_config` - Plugin-specific configuration from `[plugins.{mode}]`
///
/// # Returns
///
/// An `Arc<dyn LockStore>` on success, or a `StoreConfigError` on failure.
pub fn create_lock_store_with_registry(
    registry: &PluginRegistry,
    mode: &str,
    plugin_config: &toml::Value,
) -> Result<Arc<dyn LockStore>, StoreConfigError> {
    info!(mode, "Creating lock store via plugin system");
    registry
        .create_lock_store(mode, plugin_config)
        .forward("creating lock store")
}

/// Resolves plugin configuration for a store from settings.
///
/// This function looks up the plugin configuration from the plugins map,
/// supporting both direct plugin config and store-specific nested config.
///
/// # Priority
///
/// 1. `[plugins.{mode}.{store_type}]` - Specific store config merged with parent
/// 2. `[plugins.{mode}]` - General plugin config
///
/// # Arguments
///
/// * `plugins` - The plugins configuration map from settings
/// * `mode` - The plugin name (e.g., "aws", "local")
/// * `store_type` - Optional store type for nested config (e.g., `immutable_store`)
///
/// # Returns
///
/// The resolved configuration or None if not found.
///
/// # Example
///
/// ```
/// use std::collections::HashMap;
/// use lore_server::store::resolve_plugin_config;
///
/// // Build a plugins configuration map simulating:
/// // [plugins.aws]
/// // region = "us-east-1"
/// // [plugins.aws.http]
/// // timeout = 5000
/// // [plugins.aws.immutable_store]
/// // s3_bucket = "my-bucket"
///
/// let config_toml = r#"
///     region = "us-east-1"
///     [http]
///     timeout = 5000
///     [immutable_store]
///     s3_bucket = "my-bucket"
/// "#;
///
/// let mut plugins: HashMap<String, toml::Value> = HashMap::new();
/// plugins.insert(
///     "aws".to_string(),
///     toml::from_str(config_toml).expect("valid TOML"),
/// );
///
/// // Resolve general plugin config (no store type)
/// let general_config = resolve_plugin_config(&plugins, "aws", None);
/// assert!(general_config.is_some());
/// let general = general_config.unwrap();
/// assert_eq!(general.get("region").unwrap().as_str().unwrap(), "us-east-1");
///
/// // Resolve store-specific config, which merges parent settings
/// let store_config = resolve_plugin_config(&plugins, "aws", Some("immutable_store"));
/// assert!(store_config.is_some());
/// let config = store_config.unwrap();
///
/// // The s3_bucket from immutable_store is present
/// assert_eq!(config.get("s3_bucket").unwrap().as_str().unwrap(), "my-bucket");
///
/// // Parent http settings are also merged in
/// assert!(config.get("http").is_some());
///
/// // Returns None for non-existent plugins
/// assert!(resolve_plugin_config(&plugins, "nonexistent", None).is_none());
/// ```
pub fn resolve_plugin_config(
    plugins: &HashMap<String, toml::Value>,
    mode: &str,
    store_type: Option<&str>,
) -> Option<toml::Value> {
    let plugin_config = plugins.get(mode)?;

    if let Some(store_type) = store_type
        && let Some(nested) = plugin_config.get(store_type)
    {
        // Merge parent config (for shared settings like HTTP) with nested
        return Some(merge_plugin_configs(plugin_config, nested));
    }

    Some(plugin_config.clone())
}

/// Resolves plugin configuration, trying store-specific first then general.
///
/// This is a convenience function that tries both `[plugins.{mode}.{store_type}]`
/// and `[plugins.{mode}]` in order.
///
/// # Arguments
///
/// * `plugins` - The plugins configuration map from settings
/// * `mode` - The plugin name (e.g., "aws", "local")
/// * `store_type` - The store type (e.g., `immutable_store`, `mutable_store`)
///
/// # Returns
///
/// The resolved configuration or None if not found.
pub fn resolve_plugin_config_with_fallback(
    plugins: &HashMap<String, toml::Value>,
    mode: &str,
    store_type: &str,
) -> Option<toml::Value> {
    // Try store-specific config first
    if let Some(config) = resolve_plugin_config(plugins, mode, Some(store_type)) {
        return Some(config);
    }

    // Fall back to general plugin config
    resolve_plugin_config(plugins, mode, None)
}

/// Checks if plugin-based configuration should be used for a given mode.
///
/// Returns true if the plugins map contains configuration for the specified mode.
///
/// # Arguments
///
/// * `plugins` - The plugins configuration map from settings
/// * `mode` - The plugin name to check
pub fn has_plugin_config(plugins: &HashMap<String, toml::Value>, mode: &str) -> bool {
    plugins.contains_key(mode)
}

/// Merges parent plugin config with store-specific config.
///
/// Store-specific values override parent values. Shared settings (like HTTP)
/// from the parent are preserved if not overridden. Other store type sections
/// (`immutable_store`, `mutable_store`, `lock_store`) from the parent are excluded
/// to prevent unknown field errors.
#[lore_macro::test_pub]
fn merge_plugin_configs(parent: &toml::Value, child: &toml::Value) -> toml::Value {
    match (parent, child) {
        (toml::Value::Table(parent_table), toml::Value::Table(child_table)) => {
            let mut merged = toml::map::Map::new();

            // First, copy parent values except nested store configs
            for (key, value) in parent_table {
                // Skip nested store configs when merging to avoid unknown field errors
                if key == "immutable_store" || key == "mutable_store" || key == "lock_store" {
                    continue;
                }
                merged.insert(key.clone(), value.clone());
            }

            // Then, add/override with child table values
            for (key, value) in child_table {
                merged.insert(key.clone(), value.clone());
            }

            toml::Value::Table(merged)
        }
        // If either is not a table, prefer child
        _ => child.clone(),
    }
}

/// Creates an empty TOML table value.
///
/// Useful as a default when no plugin configuration is found.
pub fn empty_plugin_config() -> toml::Value {
    toml::Value::Table(toml::map::Map::new())
}
