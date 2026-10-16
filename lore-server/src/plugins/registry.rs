// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Plugin registry for managing plugin factories.
//!
//! The [`PluginRegistry`] is the central hub for registering and creating
//! plugin instances. It maintains separate maps for each plugin type
//! (immutable store, mutable store, topology) and provides methods for
//! registration, creation, and listing of available plugins.

use std::collections::HashMap;
use std::sync::Arc;

use lore_base::error::PluginNotFound;
use lore_revision::cluster::topology::Topology;
use lore_revision::lock::LockStore;
use lore_storage::ImmutableStore;
use lore_storage::MutableStore;
use opentelemetry_sdk::resource::ResourceDetector;
use tokio::runtime::Handle;
use tracing::error;
use tracing::info;

use crate::plugins::traits::ImmutableStorePluginFactory;
use crate::plugins::traits::LockStorePluginFactory;
use crate::plugins::traits::MutableStorePluginFactory;
use crate::plugins::traits::NotificationPlugin;
use crate::plugins::traits::NotificationPluginContext;
use crate::plugins::traits::NotificationPluginFactory;
use crate::plugins::traits::PluginError;
use crate::plugins::traits::TopologyPluginFactory;

/// Factory closure that builds an OpenTelemetry resource detector given a
/// runtime handle.
///
/// The handle is for detectors that perform async work during detection (e.g.
/// querying instance metadata).
type ResourceDetectorFactory = Box<dyn Fn(Handle) -> Box<dyn ResourceDetector> + Send + Sync>;

/// Registry for plugin factories.
///
/// The registry maintains separate maps for each type of plugin factory:
/// - Immutable store plugins (e.g., local filesystem, S3)
/// - Mutable store plugins (e.g., local filesystem, `DynamoDB`)
/// - Topology plugins (e.g., fixed, Consul)
///
/// It also holds the resource detector factories registered by plugin modules
/// (see [`register_resource_detector`](Self::register_resource_detector)).
///
/// Plugins are registered at application startup, typically via compile-time
/// feature flags. The registry is then used to create plugin instances based
/// on runtime configuration.
#[derive(Default)]
pub struct PluginRegistry {
    immutable_store_factories: HashMap<&'static str, Box<dyn ImmutableStorePluginFactory>>,
    mutable_store_factories: HashMap<&'static str, Box<dyn MutableStorePluginFactory>>,
    lock_store_factories: HashMap<&'static str, Box<dyn LockStorePluginFactory>>,
    topology_factories: HashMap<&'static str, Box<dyn TopologyPluginFactory>>,
    notification_factories: HashMap<&'static str, Box<dyn NotificationPluginFactory>>,
    resource_detector_factories: Vec<ResourceDetectorFactory>,
}

impl PluginRegistry {
    /// Creates a new empty plugin registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an OpenTelemetry resource detector factory.
    ///
    /// Plugin modules register the detector(s) describing the deployment
    /// environment they imply (for example the AWS region, or Nomad allocation
    /// and job attributes). A detector is registered by the module independently
    /// of the store or topology plugins it also registers, so that unrelated
    /// concerns are not coupled together.
    ///
    /// The factory receives a runtime handle for detectors that perform async
    /// work during detection (e.g. querying instance metadata).
    pub fn register_resource_detector<F>(&mut self, factory: F)
    where
        F: Fn(Handle) -> Box<dyn ResourceDetector> + Send + Sync + 'static,
    {
        self.resource_detector_factories.push(Box::new(factory));
    }

    /// Builds the OpenTelemetry resource detectors registered by every
    /// compiled-in plugin module.
    ///
    /// Detectors are registered via
    /// [`register_resource_detector`](Self::register_resource_detector) and
    /// gathered purely on the basis of the plugin module being compiled in; the
    /// configured backend is not consulted. The runtime handle is forwarded to
    /// each factory for detectors that perform async work during detection.
    pub fn resource_detectors(&self, runtime_handle: Handle) -> Vec<Box<dyn ResourceDetector>> {
        self.resource_detector_factories
            .iter()
            .map(|factory| factory(runtime_handle.clone()))
            .collect()
    }

    /// Registers an immutable store plugin factory.
    ///
    /// # Arguments
    /// * `factory` - The plugin factory to register
    ///
    /// # Panics
    /// Panics if a plugin with the same name is already registered.
    pub fn register_immutable_store_plugin(
        &mut self,
        factory: Box<dyn ImmutableStorePluginFactory>,
    ) {
        let name = factory.name();
        if self.immutable_store_factories.contains_key(name) {
            panic!("Immutable store plugin '{name}' is already registered");
        }
        info!(
            plugin_name = name,
            plugin_type = "immutable_store",
            "Registered plugin"
        );
        self.immutable_store_factories.insert(name, factory);
    }

    /// Validates immutable store configuration using the specified plugin.
    ///
    /// This method validates the configuration without creating the store instance,
    /// which is useful for configuration validation without connecting to external services.
    ///
    /// # Arguments
    /// * `plugin_name` - Name of the plugin to use
    /// * `config` - TOML configuration for the plugin
    ///
    /// # Returns
    /// `Ok(())` if the configuration is valid.
    ///
    /// # Errors
    /// * [`PluginError::PluginNotFound`] - Plugin is not registered (not compiled in)
    /// * [`PluginError::PluginConfigError`] - Configuration is invalid
    pub fn validate_immutable_store_config(
        &self,
        plugin_name: &str,
        config: &toml::Value,
    ) -> Result<(), PluginError> {
        if let Some(factory) = self.immutable_store_factories.get(plugin_name) {
            factory.validate_config(config).inspect_err(|e| {
                let available = self.list_immutable_store_plugins();
                error!(
                    plugin_name = plugin_name,
                    plugin_type = "immutable_store",
                    error = %e,
                    available_plugins = ?available,
                    "Failed to validate immutable store plugin config"
                );
            })
        } else {
            let available = self.list_immutable_store_plugins();
            error!(
                plugin_name = plugin_name,
                plugin_type = "immutable_store",
                error = "Plugin not found",
                available_plugins = ?available,
                "Failed to validate immutable store plugin config"
            );
            Err(PluginNotFound {
                plugin_name: plugin_name.to_string(),
                available_plugins: available,
            }
            .into())
        }
    }

    /// Creates an immutable store instance using the specified plugin.
    ///
    /// # Arguments
    /// * `plugin_name` - Name of the plugin to use
    /// * `config` - TOML configuration for the plugin
    ///
    /// # Returns
    /// An `Arc<dyn ImmutableStore>` on success.
    ///
    /// # Errors
    /// * [`PluginError::PluginNotFound`] - Plugin is not registered (not compiled in)
    /// * [`PluginError::PluginConfigError`] - Configuration is invalid
    /// * [`PluginError::PluginInitError`] - Plugin initialization failed
    pub fn create_immutable_store(
        &self,
        plugin_name: &str,
        config: &toml::Value,
    ) -> Result<Arc<dyn ImmutableStore>, PluginError> {
        if let Some(factory) = self.immutable_store_factories.get(plugin_name) {
            factory.create(config).inspect_err(|e| {
                let available = self.list_immutable_store_plugins();
                error!(
                    plugin_name = plugin_name,
                    plugin_type = "immutable_store",
                    error = %e,
                    available_plugins = ?available,
                    "Failed to create immutable store plugin"
                );
            })
        } else {
            let available = self.list_immutable_store_plugins();
            error!(
                plugin_name = plugin_name,
                plugin_type = "immutable_store",
                error = "Plugin not found",
                available_plugins = ?available,
                "Failed to create immutable store plugin"
            );
            Err(PluginNotFound {
                plugin_name: plugin_name.to_string(),
                available_plugins: available,
            }
            .into())
        }
    }

    /// Returns a list of all registered immutable store plugin names.
    pub fn list_immutable_store_plugins(&self) -> Vec<String> {
        self.immutable_store_factories
            .keys()
            .map(|s| (*s).to_string())
            .collect()
    }

    /// Registers a mutable store plugin factory.
    ///
    /// # Arguments
    /// * `factory` - The plugin factory to register
    ///
    /// # Panics
    /// Panics if a plugin with the same name is already registered.
    pub fn register_mutable_store_plugin(&mut self, factory: Box<dyn MutableStorePluginFactory>) {
        let name = factory.name();
        if self.mutable_store_factories.contains_key(name) {
            panic!("Mutable store plugin '{name}' is already registered");
        }
        info!(
            plugin_name = name,
            plugin_type = "mutable_store",
            "Registered plugin"
        );
        self.mutable_store_factories.insert(name, factory);
    }

    /// Validates mutable store configuration using the specified plugin.
    ///
    /// This method validates the configuration without creating the store instance,
    /// which is useful for configuration validation without connecting to external services.
    ///
    /// # Arguments
    /// * `plugin_name` - Name of the plugin to use
    /// * `config` - TOML configuration for the plugin
    ///
    /// # Returns
    /// `Ok(())` if the configuration is valid.
    ///
    /// # Errors
    /// * [`PluginError::PluginNotFound`] - Plugin is not registered (not compiled in)
    /// * [`PluginError::PluginConfigError`] - Configuration is invalid
    pub fn validate_mutable_store_config(
        &self,
        plugin_name: &str,
        config: &toml::Value,
    ) -> Result<(), PluginError> {
        if let Some(factory) = self.mutable_store_factories.get(plugin_name) {
            factory.validate_config(config).inspect_err(|e| {
                let available = self.list_mutable_store_plugins();
                error!(
                    plugin_name = plugin_name,
                    plugin_type = "mutable_store",
                    error = %e,
                    available_plugins = ?available,
                    "Failed to validate mutable store plugin config"
                );
            })
        } else {
            let available = self.list_mutable_store_plugins();
            error!(
                plugin_name = plugin_name,
                plugin_type = "mutable_store",
                error = "Plugin not found",
                available_plugins = ?available,
                "Failed to validate mutable store plugin config"
            );
            Err(PluginNotFound {
                plugin_name: plugin_name.to_string(),
                available_plugins: available,
            }
            .into())
        }
    }

    /// Creates a mutable store instance using the specified plugin.
    ///
    /// # Arguments
    /// * `plugin_name` - Name of the plugin to use
    /// * `config` - TOML configuration for the plugin
    ///
    /// # Returns
    /// An `Arc<dyn MutableStore>` on success.
    ///
    /// # Errors
    /// * [`PluginError::PluginNotFound`] - Plugin is not registered (not compiled in)
    /// * [`PluginError::PluginConfigError`] - Configuration is invalid
    /// * [`PluginError::PluginInitError`] - Plugin initialization failed
    pub fn create_mutable_store(
        &self,
        plugin_name: &str,
        config: &toml::Value,
        immutable_store: Arc<dyn ImmutableStore>,
    ) -> Result<Arc<dyn MutableStore>, PluginError> {
        if let Some(factory) = self.mutable_store_factories.get(plugin_name) {
            factory.create(config, immutable_store).inspect_err(|e| {
                let available = self.list_mutable_store_plugins();
                error!(
                    plugin_name = plugin_name,
                    plugin_type = "mutable_store",
                    error = %e,
                    available_plugins = ?available,
                    "Failed to create mutable store plugin"
                );
            })
        } else {
            let available = self.list_mutable_store_plugins();
            error!(
                plugin_name = plugin_name,
                plugin_type = "mutable_store",
                error = "Plugin not found",
                available_plugins = ?available,
                "Failed to create mutable store plugin"
            );
            Err(PluginNotFound {
                plugin_name: plugin_name.to_string(),
                available_plugins: available,
            }
            .into())
        }
    }

    /// Returns a list of all registered mutable store plugin names.
    pub fn list_mutable_store_plugins(&self) -> Vec<String> {
        self.mutable_store_factories
            .keys()
            .map(|s| (*s).to_string())
            .collect()
    }

    /// Registers a lock store plugin factory.
    ///
    /// # Arguments
    /// * `factory` - The plugin factory to register
    ///
    /// # Panics
    /// Panics if a plugin with the same name is already registered.
    pub fn register_lock_store_plugin(&mut self, factory: Box<dyn LockStorePluginFactory>) {
        let name = factory.name();
        if self.lock_store_factories.contains_key(name) {
            panic!("LockData store plugin '{name}' is already registered");
        }
        info!(
            plugin_name = name,
            plugin_type = "lock_store",
            "Registered plugin"
        );
        self.lock_store_factories.insert(name, factory);
    }

    /// Validates lock store configuration using the specified plugin.
    ///
    /// This method validates the configuration without creating the store instance,
    /// which is useful for configuration validation without connecting to external services.
    ///
    /// # Arguments
    /// * `plugin_name` - Name of the plugin to use
    /// * `config` - TOML configuration for the plugin
    ///
    /// # Returns
    /// `Ok(())` if the configuration is valid.
    ///
    /// # Errors
    /// * [`PluginError::PluginNotFound`] - Plugin is not registered (not compiled in)
    /// * [`PluginError::PluginConfigError`] - Configuration is invalid
    pub fn validate_lock_store_config(
        &self,
        plugin_name: &str,
        config: &toml::Value,
    ) -> Result<(), PluginError> {
        if let Some(factory) = self.lock_store_factories.get(plugin_name) {
            factory.validate_config(config).inspect_err(|e| {
                let available = self.list_lock_store_plugins();
                error!(
                    plugin_name = plugin_name,
                    plugin_type = "lock_store",
                    error = %e,
                    available_plugins = ?available,
                    "Failed to validate lock store plugin config"
                );
            })
        } else {
            let available = self.list_lock_store_plugins();
            error!(
                plugin_name = plugin_name,
                plugin_type = "lock_store",
                error = "Plugin not found",
                available_plugins = ?available,
                "Failed to validate lock store plugin config"
            );
            Err(PluginNotFound {
                plugin_name: plugin_name.to_string(),
                available_plugins: available,
            }
            .into())
        }
    }

    /// Creates a lock store instance using the specified plugin.
    ///
    /// # Arguments
    /// * `plugin_name` - Name of the plugin to use
    /// * `config` - TOML configuration for the plugin
    ///
    /// # Returns
    /// An `Arc<dyn LockStore>` on success.
    ///
    /// # Errors
    /// * [`PluginError::PluginNotFound`] - Plugin is not registered (not compiled in)
    /// * [`PluginError::PluginConfigError`] - Configuration is invalid
    /// * [`PluginError::PluginInitError`] - Plugin initialization failed
    pub fn create_lock_store(
        &self,
        plugin_name: &str,
        config: &toml::Value,
    ) -> Result<Arc<dyn LockStore>, PluginError> {
        if let Some(factory) = self.lock_store_factories.get(plugin_name) {
            factory.create(config).inspect_err(|e| {
                let available = self.list_lock_store_plugins();
                error!(
                    plugin_name = plugin_name,
                    plugin_type = "lock_store",
                    error = %e,
                    available_plugins = ?available,
                    "Failed to create lock store plugin"
                );
            })
        } else {
            let available = self.list_lock_store_plugins();
            error!(
                plugin_name = plugin_name,
                plugin_type = "lock_store",
                error = "Plugin not found",
                available_plugins = ?available,
                "Failed to create lock store plugin"
            );
            Err(PluginNotFound {
                plugin_name: plugin_name.to_string(),
                available_plugins: available,
            }
            .into())
        }
    }

    /// Returns a list of all registered lock store plugin names.
    pub fn list_lock_store_plugins(&self) -> Vec<String> {
        self.lock_store_factories
            .keys()
            .map(|s| (*s).to_string())
            .collect()
    }

    /// Registers a topology plugin factory.
    ///
    /// # Arguments
    /// * `factory` - The plugin factory to register
    ///
    /// # Panics
    /// Panics if a plugin with the same name is already registered.
    pub fn register_topology_plugin(&mut self, factory: Box<dyn TopologyPluginFactory>) {
        let name = factory.name();
        if self.topology_factories.contains_key(name) {
            panic!("Topology plugin '{name}' is already registered");
        }
        info!(
            plugin_name = name,
            plugin_type = "topology",
            "Registered plugin"
        );
        self.topology_factories.insert(name, factory);
    }

    /// Validates topology configuration using the specified plugin.
    ///
    /// This method validates the configuration without creating the topology instance,
    /// which is useful for configuration validation without connecting to external services.
    ///
    /// # Arguments
    /// * `plugin_name` - Name of the plugin to use
    /// * `config` - TOML configuration for the plugin
    ///
    /// # Returns
    /// `Ok(())` if the configuration is valid.
    ///
    /// # Errors
    /// * [`PluginError::PluginNotFound`] - Plugin is not registered (not compiled in)
    /// * [`PluginError::PluginConfigError`] - Configuration is invalid
    pub fn validate_topology_config(
        &self,
        plugin_name: &str,
        config: &toml::Value,
    ) -> Result<(), PluginError> {
        if let Some(factory) = self.topology_factories.get(plugin_name) {
            factory.validate_config(config).inspect_err(|e| {
                let available = self.list_topology_plugins();
                error!(
                    plugin_name = plugin_name,
                    plugin_type = "topology",
                    error = %e,
                    available_plugins = ?available,
                    "Failed to validate topology plugin config"
                );
            })
        } else {
            let available = self.list_topology_plugins();
            error!(
                plugin_name = plugin_name,
                plugin_type = "topology",
                error = "Plugin not found",
                available_plugins = ?available,
                "Failed to validate topology plugin config"
            );
            Err(PluginNotFound {
                plugin_name: plugin_name.to_string(),
                available_plugins: available,
            }
            .into())
        }
    }

    /// Creates a topology instance using the specified plugin.
    ///
    /// # Arguments
    /// * `plugin_name` - Name of the plugin to use
    /// * `config` - TOML configuration for the plugin
    ///
    /// # Returns
    /// An `Arc<dyn Topology + Send + Sync>` on success.
    ///
    /// # Errors
    /// * [`PluginError::PluginNotFound`] - Plugin is not registered (not compiled in)
    /// * [`PluginError::PluginConfigError`] - Configuration is invalid
    /// * [`PluginError::PluginInitError`] - Plugin initialization failed
    pub fn create_topology(
        &self,
        plugin_name: &str,
        config: &toml::Value,
    ) -> Result<Arc<dyn Topology + Send + Sync>, PluginError> {
        if let Some(factory) = self.topology_factories.get(plugin_name) {
            factory.create(config).inspect_err(|e| {
                let available = self.list_topology_plugins();
                error!(
                    plugin_name = plugin_name,
                    plugin_type = "topology",
                    error = %e,
                    available_plugins = ?available,
                    "Failed to create topology plugin"
                );
            })
        } else {
            let available = self.list_topology_plugins();
            error!(
                plugin_name = plugin_name,
                plugin_type = "topology",
                error = "Plugin not found",
                available_plugins = ?available,
                "Failed to create topology plugin"
            );
            Err(PluginNotFound {
                plugin_name: plugin_name.to_string(),
                available_plugins: available,
            }
            .into())
        }
    }

    /// Returns a list of all registered topology plugin names.
    pub fn list_topology_plugins(&self) -> Vec<String> {
        self.topology_factories
            .keys()
            .map(|s| (*s).to_string())
            .collect()
    }

    /// Registers a notification plugin factory.
    ///
    /// # Arguments
    /// * `name` - Unique name for this notification plugin
    /// * `factory` - The plugin factory to register
    ///
    /// # Panics
    /// Panics if a plugin with the same name is already registered.
    pub fn register_notification_plugin(&mut self, factory: Box<dyn NotificationPluginFactory>) {
        if self.notification_factories.contains_key(factory.name()) {
            panic!(
                "Notification plugin '{}' is already registered",
                factory.name()
            );
        }
        info!(
            plugin_name = factory.name(),
            plugin_type = "notification",
            "Registered plugin"
        );
        self.notification_factories.insert(factory.name(), factory);
    }

    /// Validates notification configuration using the specified plugin.
    pub fn validate_notification_config(
        &self,
        plugin_name: &str,
        config: &toml::Value,
    ) -> Result<(), PluginError> {
        if let Some(factory) = self.notification_factories.get(plugin_name) {
            factory.validate_config(config).inspect_err(|e| {
                let available = self.list_notification_plugins();
                error!(
                    plugin_name = plugin_name,
                    plugin_type = "notification",
                    error = %e,
                    available_plugins = ?available,
                    "Failed to validate notification plugin config"
                );
            })
        } else {
            let available = self.list_notification_plugins();
            error!(
                plugin_name = plugin_name,
                plugin_type = "notification",
                error = "Plugin not found",
                available_plugins = ?available,
                "Failed to validate notification plugin config"
            );
            Err(PluginNotFound {
                plugin_name: plugin_name.to_string(),
                available_plugins: available,
            }
            .into())
        }
    }

    /// Creates a notification plugin instance using the specified plugin.
    ///
    /// This method is async because notification plugins may require network I/O
    /// during initialization.
    pub async fn create_notification(
        &self,
        plugin_name: &str,
        config: &toml::Value,
        context: &NotificationPluginContext,
    ) -> Result<NotificationPlugin, PluginError> {
        if let Some(factory) = self.notification_factories.get(plugin_name) {
            factory.create(config, context).await.inspect_err(|e| {
                let available = self.list_notification_plugins();
                error!(
                    plugin_name = plugin_name,
                    plugin_type = "notification",
                    error = %e,
                    available_plugins = ?available,
                    "Failed to create notification plugin"
                );
            })
        } else {
            let available = self.list_notification_plugins();
            error!(
                plugin_name = plugin_name,
                plugin_type = "notification",
                error = "Plugin not found",
                available_plugins = ?available,
                "Failed to create notification plugin"
            );
            Err(PluginNotFound {
                plugin_name: plugin_name.to_string(),
                available_plugins: available,
            }
            .into())
        }
    }

    /// Returns a list of all registered notification plugin names.
    pub fn list_notification_plugins(&self) -> Vec<String> {
        self.notification_factories
            .keys()
            .map(|s| (*s).to_string())
            .collect()
    }
}

impl std::fmt::Debug for PluginRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginRegistry")
            .field(
                "immutable_store_plugins",
                &self.list_immutable_store_plugins(),
            )
            .field("mutable_store_plugins", &self.list_mutable_store_plugins())
            .field("lock_store_plugins", &self.list_lock_store_plugins())
            .field("topology_plugins", &self.list_topology_plugins())
            .field("notification_plugins", &self.list_notification_plugins())
            .finish()
    }
}
