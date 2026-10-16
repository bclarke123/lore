// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Plugin traits for compile-time pluggable storage and topology backends.
//!
//! This module defines factory traits that allow different implementations
//! of storage backends (immutable and mutable stores) and topology discovery
//! to be plugged in at compile-time via feature flags.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use lore_base::error::PluginConfigError;
use lore_base::error::PluginInitError;
use lore_base::error::PluginNotFound;
use lore_error_set::prelude::*;
use lore_revision::cluster::topology::Topology;
use lore_revision::lock::LockStore;
use lore_revision::notification::NotificationSender;
use lore_storage::ImmutableStore;
use lore_storage::MutableStore;

/// Errors that can occur during plugin operations.
///
/// Each named variant points operators at a specific, fixable root cause:
/// `PluginNotFound` means the plugin is not compiled in (install it or
/// correct the name), `PluginConfigError` means the TOML config is wrong
/// (fix the config), `PluginInitError` means the plugin failed to start
/// (check credentials, endpoints, etc.).
#[error_set]
pub enum PluginError {
    PluginNotFound,
    PluginConfigError,
    PluginInitError,
}

/// Factory trait for creating immutable store instances.
///
/// Implementations of this trait are responsible for creating configured
/// instances of [`ImmutableStore`] based on TOML configuration.
pub trait ImmutableStorePluginFactory: Send + Sync {
    /// Validates the configuration without creating the store instance.
    ///
    /// This method parses and validates the configuration to ensure it's correct
    /// without actually initializing the store or connecting to external services.
    /// This is useful for configuration validation during startup or in tests.
    ///
    /// # Arguments
    /// * `config` - TOML configuration value for this plugin
    ///
    /// # Returns
    /// `Ok(())` if the configuration is valid.
    ///
    /// # Errors
    /// * [`PluginError::PluginConfigError`] - Configuration parsing/validation failed
    fn validate_config(&self, config: &toml::Value) -> Result<(), PluginError>;

    /// Creates a new immutable store instance from the provided configuration.
    ///
    /// # Arguments
    /// * `config` - TOML configuration value for this plugin
    ///
    /// # Returns
    /// An `Arc<dyn ImmutableStore>` on success, or a `PluginError` on failure.
    ///
    /// # Errors
    /// * [`PluginError::PluginConfigError`] - Configuration parsing/validation failed
    /// * [`PluginError::PluginInitError`] - Store initialization failed
    fn create(&self, config: &toml::Value) -> Result<Arc<dyn ImmutableStore>, PluginError>;

    /// Returns the unique name of this plugin.
    ///
    /// This name is used to identify the plugin in configuration files
    /// and error messages.
    fn name(&self) -> &'static str;
}

/// Factory trait for creating mutable store instances.
///
/// Implementations of this trait are responsible for creating configured
/// instances of [`MutableStore`] based on TOML configuration.
pub trait MutableStorePluginFactory: Send + Sync {
    /// Validates the configuration without creating the store instance.
    ///
    /// This method parses and validates the configuration to ensure it's correct
    /// without actually initializing the store or connecting to external services.
    /// This is useful for configuration validation during startup or in tests.
    ///
    /// # Arguments
    /// * `config` - TOML configuration value for this plugin
    ///
    /// # Returns
    /// `Ok(())` if the configuration is valid.
    ///
    /// # Errors
    /// * [`PluginError::PluginConfigError`] - Configuration parsing/validation failed
    fn validate_config(&self, config: &toml::Value) -> Result<(), PluginError>;

    /// Creates a new mutable store instance from the provided configuration.
    ///
    /// # Arguments
    /// * `config` - TOML configuration value for this plugin
    ///
    /// # Returns
    /// An `Arc<dyn MutableStore>` on success, or a `PluginError` on failure.
    ///
    /// # Errors
    /// * [`PluginError::PluginConfigError`] - Configuration parsing/validation failed
    /// * [`PluginError::PluginInitError`] - Store initialization failed
    fn create(
        &self,
        config: &toml::Value,
        immutable_store: Arc<dyn ImmutableStore>,
    ) -> Result<Arc<dyn MutableStore>, PluginError>;

    /// Returns the unique name of this plugin.
    ///
    /// This name is used to identify the plugin in configuration files
    /// and error messages.
    fn name(&self) -> &'static str;
}

/// Factory trait for creating topology discovery instances.
///
/// Implementations of this trait are responsible for creating configured
/// instances of [`Topology`] based on TOML configuration.
pub trait TopologyPluginFactory: Send + Sync {
    /// Validates the configuration without creating the topology instance.
    ///
    /// This method parses and validates the configuration to ensure it's correct
    /// without actually initializing the topology or connecting to external services.
    /// This is useful for configuration validation during startup or in tests.
    ///
    /// # Arguments
    /// * `config` - TOML configuration value for this plugin
    ///
    /// # Returns
    /// `Ok(())` if the configuration is valid.
    ///
    /// # Errors
    /// * [`PluginError::PluginConfigError`] - Configuration parsing/validation failed
    fn validate_config(&self, config: &toml::Value) -> Result<(), PluginError>;

    /// Creates a new topology instance from the provided configuration.
    ///
    /// # Arguments
    /// * `config` - TOML configuration value for this plugin
    ///
    /// # Returns
    /// An `Arc<dyn Topology>` on success, or a `PluginError` on failure.
    ///
    /// # Errors
    /// * [`PluginError::PluginConfigError`] - Configuration parsing/validation failed
    /// * [`PluginError::PluginInitError`] - Topology initialization failed
    fn create(&self, config: &toml::Value) -> Result<Arc<dyn Topology + Send + Sync>, PluginError>;

    /// Returns the unique name of this plugin.
    ///
    /// This name is used to identify the plugin in configuration files
    /// and error messages.
    fn name(&self) -> &'static str;
}

/// Factory trait for creating lock store instances.
///
/// Implementations of this trait are responsible for creating configured
/// instances of [`LockStore`] based on TOML configuration.
pub trait LockStorePluginFactory: Send + Sync {
    /// Validates the configuration without creating the lock store instance.
    ///
    /// This method parses and validates the configuration to ensure it's correct
    /// without actually initializing the store or connecting to external services.
    /// This is useful for configuration validation during startup or in tests.
    ///
    /// # Arguments
    /// * `config` - TOML configuration value for this plugin
    ///
    /// # Returns
    /// `Ok(())` if the configuration is valid.
    ///
    /// # Errors
    /// * [`PluginError::PluginConfigError`] - Configuration parsing/validation failed
    fn validate_config(&self, config: &toml::Value) -> Result<(), PluginError>;

    /// Creates a new lock store instance from the provided configuration.
    ///
    /// # Arguments
    /// * `config` - TOML configuration value for this plugin
    ///
    /// # Returns
    /// An `Arc<dyn LockStore>` on success, or a `PluginError` on failure.
    ///
    /// # Errors
    /// * [`PluginError::PluginConfigError`] - Configuration parsing/validation failed
    /// * [`PluginError::PluginInitError`] - Store initialization failed
    fn create(&self, config: &toml::Value) -> Result<Arc<dyn LockStore>, PluginError>;

    /// Returns the unique name of this plugin.
    ///
    /// This name is used to identify the plugin in configuration files
    /// and error messages.
    fn name(&self) -> &'static str;
}

/// A background task returned by a notification plugin.
///
/// These are long-running futures (e.g., notification listeners) whose lifecycle
/// is managed by the server's `JoinSet` (TD-14).
pub type NotificationReceiver = Pin<Box<dyn Future<Output = Result<(), PluginError>> + Send>>;

/// Context provided to notification plugin factories during creation.
///
/// Contains environment-level information and optional references to server
/// infrastructure that notification plugins may need during initialization.
pub struct NotificationPluginContext {
    /// Environment configuration (namespace, region, etc.)
    pub environment: Option<lore_revision::environment::EnvironmentConfig>,
    /// Optional reference to the local immutable store.
    /// Some notification plugins need this for event processing (e.g., obliterate propagation).
    pub immutable_store: Option<Arc<dyn ImmutableStore>>,
}

/// Output from creating a notification plugin instance.
///
/// This is a compound type that captures the dual roles of notification
/// plugins: event publishing via the sender, and optional background receiver
/// tasks (e.g., event listeners for obliterate propagation).
pub struct NotificationPlugin {
    /// The notification sender for publishing events to handlers.
    pub sender: Arc<dyn NotificationSender>,
    /// Background receiver tasks that should be spawned by the server.
    /// These are long-running futures of notification listeners whose lifecycle
    /// should be managed by the server's runtime.
    pub receivers: Vec<NotificationReceiver>,
}

/// Factory trait for creating notification plugin instances.
///
/// Unlike other plugin factories, this trait uses async creation
/// because notification backends typically require network I/O during
/// initialization (e.g., establishing gRPC channels).
#[async_trait]
pub trait NotificationPluginFactory: Send + Sync {
    /// Validates the configuration without creating the plugin instance.
    ///
    /// # Arguments
    /// * `config` - TOML configuration for the plugin
    ///
    /// # Errors
    /// * [`PluginError::PluginConfigError`] - Configuration is invalid
    fn validate_config(&self, config: &toml::Value) -> Result<(), PluginError>;

    /// Creates a new notification plugin instance from the provided configuration and context.
    ///
    /// This method is async because notification backends may require network I/O
    /// during initialization (e.g., connecting to external services).
    ///
    /// # Arguments
    /// * `config` - TOML configuration for the plugin
    /// * `context` - Server context providing environment config and infrastructure references
    ///
    /// # Returns
    /// A [`NotificationPlugin`] containing the notification sender and any background tasks.
    ///
    /// # Errors
    /// * [`PluginError::PluginConfigError`] - Configuration is invalid
    /// * [`PluginError::PluginInitError`] - Plugin initialization failed
    async fn create(
        &self,
        config: &toml::Value,
        context: &NotificationPluginContext,
    ) -> Result<NotificationPlugin, PluginError>;

    /// Returns the unique name of this plugin.
    ///
    /// This name is used to identify the plugin in configuration files
    /// and error messages.
    fn name(&self) -> &'static str;
}
