// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Hook registry for managing hook factories.
//!
//! The [`HookRegistry`] is the central hub for registering hook factories and
//! creating enabled hook instances based on configuration. It maintains:
//!
//! - A map of hook factories (populated via `register_all_hooks()`)
//! - Methods for creating enabled hook instances from configuration
//!
//! # Usage
//!
//! ```
//! use lore_server::hooks::{HookRegistry, Hook, HookFactory, HookError, HookContext, HookPoint};
//! use async_trait::async_trait;
//!
//! // Define a simple hook
//! struct LogHook;
//!
//! #[async_trait]
//! impl Hook for LogHook {
//!     fn name(&self) -> &'static str { "log" }
//!     fn hook_points(&self) -> &'static [HookPoint] { &[HookPoint::BranchPush] }
//! }
//!
//! // Define a factory for the hook
//! struct LogHookFactory;
//!
//! impl HookFactory for LogHookFactory {
//!     fn name(&self) -> &'static str { "log" }
//!     fn create(&self, _config: &toml::Value) -> Result<Box<dyn Hook>, HookError> {
//!         Ok(Box::new(LogHook))
//!     }
//! }
//!
//! // Create and use the registry
//! let mut registry = HookRegistry::new();
//!
//! // Register hook factory
//! registry.register_hook(Box::new(LogHookFactory));
//!
//! // List available hooks
//! let available = registry.list_hooks();
//! assert!(available.contains(&"log".to_string()));
//!
//! // Create a hook instance
//! let config = toml::Value::Table(toml::map::Map::new());
//! let hook = registry.create_hook("log", &config).unwrap();
//! assert_eq!(hook.name(), "log");
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use lore_revision::notification::NotificationSender;
use tracing::debug;
use tracing::error;
use tracing::info;

use crate::hooks::traits::Hook;
use crate::hooks::traits::HookError;
use crate::hooks::traits::HookFactory;

/// Context providing runtime dependencies for hook factory registration.
///
/// This struct is passed to each hook's `register()` function during startup,
/// allowing hook factories to capture the dependencies they need for creating
/// hook instances.
pub struct HookRegistrationContext {
    /// Notification sender for hooks that need to send notifications.
    pub notification_sender: Arc<dyn NotificationSender>,
}

/// Registry for hook factories.
///
/// The registry maintains a map from hook names to their factories.
/// Hook factories are registered at application startup, typically via
/// the auto-generated `register_all_hooks()` function.
#[derive(Default)]
pub struct HookRegistry {
    factories: HashMap<&'static str, Box<dyn HookFactory>>,
}

impl HookRegistry {
    /// Creates a new empty hook registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a hook factory.
    ///
    /// # Arguments
    ///
    /// * `factory` - The hook factory to register
    ///
    /// # Panics
    ///
    /// Panics if a hook with the same name is already registered.
    pub fn register_hook(&mut self, factory: Box<dyn HookFactory>) {
        let name = factory.name();
        if self.factories.contains_key(name) {
            panic!("Hook '{name}' is already registered");
        }
        info!(hook_name = name, "Registered hook factory");
        self.factories.insert(name, factory);
    }

    /// Returns a list of all registered hook names.
    pub fn list_hooks(&self) -> Vec<String> {
        self.factories.keys().map(|s| (*s).to_string()).collect()
    }

    /// Creates a hook instance by name.
    ///
    /// # Arguments
    ///
    /// * `name` - Name of the hook to create
    /// * `config` - TOML configuration for the hook
    ///
    /// # Returns
    ///
    /// A boxed hook instance on success.
    ///
    /// # Errors
    ///
    /// - [`HookError::ConfigError`] - Hook not found (name not registered)
    /// - [`HookError::ConfigError`] - Configuration validation failed
    /// - [`HookError::InitError`] - Hook initialization failed
    pub fn create_hook(
        &self,
        name: &str,
        config: &toml::Value,
    ) -> Result<Box<dyn Hook>, HookError> {
        if let Some(factory) = self.factories.get(name) {
            factory.create(config).inspect_err(|e| {
                error!(
                    hook_name = name,
                    error = %e,
                    "Failed to create hook"
                );
            })
        } else {
            let available = self.list_hooks();
            error!(
                hook_name = name,
                error = "Hook not found",
                available_hooks = ?available,
                "Failed to create hook"
            );
            Err(HookError::ConfigError {
                hook_name: name.to_string(),
                message: format!("Hook '{name}' not found. Available hooks: {available:?}"),
            })
        }
    }

    /// Creates hook instances for all enabled hooks in the configuration.
    ///
    /// # Arguments
    ///
    /// * `hook_settings` - Map of hook name to (enabled flag, config)
    ///
    /// # Returns
    ///
    /// A vector of (name, hook) pairs for all successfully created enabled hooks.
    ///
    /// # Errors
    ///
    /// Returns an error if any enabled hook fails to create.
    ///
    /// # Example
    ///
    /// ```
    /// use lore_server::hooks::{HookRegistry, HookSettings, Hook, HookFactory, HookError, HookContext, HookPoint};
    /// use async_trait::async_trait;
    /// use std::collections::HashMap;
    ///
    /// // Define a simple hook
    /// struct TestHook;
    ///
    /// #[async_trait]
    /// impl Hook for TestHook {
    ///     fn name(&self) -> &'static str { "test" }
    ///     fn hook_points(&self) -> &'static [HookPoint] { &[HookPoint::BranchPush] }
    /// }
    ///
    /// struct TestHookFactory;
    ///
    /// impl HookFactory for TestHookFactory {
    ///     fn name(&self) -> &'static str { "test" }
    ///     fn create(&self, _config: &toml::Value) -> Result<Box<dyn Hook>, HookError> {
    ///         Ok(Box::new(TestHook))
    ///     }
    /// }
    ///
    /// // Set up registry
    /// let mut registry = HookRegistry::new();
    /// registry.register_hook(Box::new(TestHookFactory));
    ///
    /// // Configure hooks
    /// let mut settings = HashMap::new();
    /// settings.insert(
    ///     "test".to_string(),
    ///     HookSettings {
    ///         enabled: true,
    ///         config: toml::Value::Table(toml::map::Map::new()),
    ///     },
    /// );
    ///
    /// // Create enabled hooks
    /// let enabled_hooks = registry.create_enabled_hooks(&settings).unwrap();
    /// assert_eq!(enabled_hooks.len(), 1);
    /// assert_eq!(enabled_hooks[0].0, "test");
    /// ```
    #[allow(clippy::type_complexity)]
    pub fn create_enabled_hooks(
        &self,
        hook_settings: &HashMap<String, HookSettings>,
    ) -> Result<Vec<(String, Box<dyn Hook>)>, HookError> {
        let mut hooks = Vec::new();

        for (name, settings) in hook_settings {
            if !settings.enabled {
                debug!(hook_name = name, "Hook is disabled, skipping");
                continue;
            }

            let hook = self.create_hook(name, &settings.config)?;
            info!(
                hook_name = name,
                hook_points = ?hook.hook_points(),
                "Created enabled hook"
            );
            hooks.push((name.clone(), hook));
        }

        Ok(hooks)
    }

    /// Returns whether a hook with the given name is registered.
    pub fn has_hook(&self, name: &str) -> bool {
        self.factories.contains_key(name)
    }
}

impl std::fmt::Debug for HookRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HookRegistry")
            .field("hooks", &self.list_hooks())
            .finish()
    }
}

/// Settings for a single hook from configuration.
///
/// This struct matches the expected TOML configuration format:
///
/// ```toml
/// [hooks.compliance]
/// enabled = true
/// # ... other config fields ...
/// ```
///
/// The `enabled` flag is extracted separately, and all other fields
/// are preserved in `config` for the hook factory to deserialize.
#[derive(Debug, Clone)]
pub struct HookSettings {
    /// Whether this hook is enabled.
    pub enabled: bool,

    /// The hook's configuration (everything except 'enabled').
    pub config: toml::Value,
}

impl Default for HookSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            config: toml::Value::Table(toml::map::Map::new()),
        }
    }
}

impl<'de> serde::Deserialize<'de> for HookSettings {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut table = toml::Table::deserialize(deserializer)?;

        // Extract 'enabled' flag, defaulting to false
        let enabled = table
            .remove("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Keep remaining config
        let config = toml::Value::Table(table);

        Ok(HookSettings { enabled, config })
    }
}

impl serde::Serialize for HookSettings {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        // Get the underlying table or create empty one
        let config_table = match &self.config {
            toml::Value::Table(t) => t.clone(),
            _ => toml::map::Map::new(),
        };

        // Serialize enabled + all config fields
        let mut map = serializer.serialize_map(Some(config_table.len() + 1))?;
        map.serialize_entry("enabled", &self.enabled)?;
        for (k, v) in &config_table {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}
