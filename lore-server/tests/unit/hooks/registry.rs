// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::collections::HashMap;

use async_trait::async_trait;
use lore_server::hooks::registry::*;
use lore_server::hooks::traits::Hook;
use lore_server::hooks::traits::HookError;
use lore_server::hooks::traits::HookFactory;
use lore_server::hooks::traits::HookPoint;

struct MockHook {
    name: &'static str,
    points: &'static [HookPoint],
}

#[async_trait]
impl Hook for MockHook {
    fn name(&self) -> &'static str {
        self.name
    }

    fn hook_points(&self) -> &'static [HookPoint] {
        self.points
    }
}

struct MockHookFactory {
    name: &'static str,
    points: &'static [HookPoint],
    should_fail_config: bool,
    should_fail_init: bool,
}

impl MockHookFactory {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            points: &[HookPoint::BranchPush],
            should_fail_config: false,
            should_fail_init: false,
        }
    }

    fn with_config_error(mut self) -> Self {
        self.should_fail_config = true;
        self
    }

    fn with_init_error(mut self) -> Self {
        self.should_fail_init = true;
        self
    }
}

impl HookFactory for MockHookFactory {
    fn name(&self) -> &'static str {
        self.name
    }

    fn create(&self, config: &toml::Value) -> Result<Box<dyn Hook>, HookError> {
        if self.should_fail_config {
            return Err(HookError::ConfigError {
                hook_name: self.name.to_string(),
                message: format!("Invalid config: {config:?}"),
            });
        }
        if self.should_fail_init {
            return Err(HookError::InitError {
                hook_name: self.name.to_string(),
                message: "Failed to initialize".to_string(),
            });
        }
        Ok(Box::new(MockHook {
            name: self.name,
            points: self.points,
        }))
    }
}

#[test]
fn test_register_hook() {
    let mut registry = HookRegistry::new();
    registry.register_hook(Box::new(MockHookFactory::new("test")));

    let hooks = registry.list_hooks();
    assert_eq!(hooks.len(), 1);
    assert!(hooks.contains(&"test".to_string()));
}

#[test]
fn test_register_multiple_hooks() {
    let mut registry = HookRegistry::new();
    registry.register_hook(Box::new(MockHookFactory::new("hook1")));
    registry.register_hook(Box::new(MockHookFactory::new("hook2")));

    let hooks = registry.list_hooks();
    assert_eq!(hooks.len(), 2);
    assert!(hooks.contains(&"hook1".to_string()));
    assert!(hooks.contains(&"hook2".to_string()));
}

#[test]
#[should_panic(expected = "already registered")]
fn test_register_duplicate_hook_panics() {
    let mut registry = HookRegistry::new();
    registry.register_hook(Box::new(MockHookFactory::new("test")));
    registry.register_hook(Box::new(MockHookFactory::new("test")));
}

#[test]
fn test_create_hook_success() {
    let mut registry = HookRegistry::new();
    registry.register_hook(Box::new(MockHookFactory::new("test")));

    let config = toml::Value::Table(toml::map::Map::new());
    let result = registry.create_hook("test", &config);
    assert!(result.is_ok());
}

#[test]
fn test_create_hook_not_found() {
    let mut registry = HookRegistry::new();
    registry.register_hook(Box::new(MockHookFactory::new("other")));

    let config = toml::Value::Table(toml::map::Map::new());
    let result = registry.create_hook("missing", &config);

    match result {
        Err(HookError::ConfigError { hook_name, message }) => {
            assert_eq!(hook_name, "missing");
            assert!(message.contains("not found"));
            assert!(message.contains("other"));
        }
        _ => panic!("Expected ConfigError"),
    }
}

#[test]
fn test_create_hook_config_error() {
    let mut registry = HookRegistry::new();
    registry.register_hook(Box::new(MockHookFactory::new("test").with_config_error()));

    let config = toml::Value::Table(toml::map::Map::new());
    let result = registry.create_hook("test", &config);

    match result {
        Err(HookError::ConfigError { hook_name, .. }) => {
            assert_eq!(hook_name, "test");
        }
        _ => panic!("Expected ConfigError"),
    }
}

#[test]
fn test_create_hook_init_error() {
    let mut registry = HookRegistry::new();
    registry.register_hook(Box::new(MockHookFactory::new("test").with_init_error()));

    let config = toml::Value::Table(toml::map::Map::new());
    let result = registry.create_hook("test", &config);

    match result {
        Err(HookError::InitError { hook_name, .. }) => {
            assert_eq!(hook_name, "test");
        }
        _ => panic!("Expected InitError"),
    }
}

#[test]
fn test_has_hook() {
    let mut registry = HookRegistry::new();
    registry.register_hook(Box::new(MockHookFactory::new("test")));

    assert!(registry.has_hook("test"));
    assert!(!registry.has_hook("nonexistent"));
}

#[test]
fn test_empty_registry() {
    let registry = HookRegistry::new();
    assert!(registry.list_hooks().is_empty());
    assert!(!registry.has_hook("anything"));
}

#[test]
fn test_registry_debug() {
    let mut registry = HookRegistry::new();
    registry.register_hook(Box::new(MockHookFactory::new("hook1")));
    registry.register_hook(Box::new(MockHookFactory::new("hook2")));

    let debug_str = format!("{registry:?}");
    assert!(debug_str.contains("hook1"));
    assert!(debug_str.contains("hook2"));
}

#[test]
fn test_create_enabled_hooks_empty() {
    let registry = HookRegistry::new();
    let settings: HashMap<String, HookSettings> = HashMap::new();

    let result = registry.create_enabled_hooks(&settings);
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[test]
fn test_create_enabled_hooks_all_disabled() {
    let mut registry = HookRegistry::new();
    registry.register_hook(Box::new(MockHookFactory::new("hook1")));
    registry.register_hook(Box::new(MockHookFactory::new("hook2")));

    let mut settings = HashMap::new();
    settings.insert(
        "hook1".to_string(),
        HookSettings {
            enabled: false,
            config: toml::Value::Table(toml::map::Map::new()),
        },
    );
    settings.insert(
        "hook2".to_string(),
        HookSettings {
            enabled: false,
            config: toml::Value::Table(toml::map::Map::new()),
        },
    );

    let result = registry.create_enabled_hooks(&settings).unwrap();
    assert!(result.is_empty());
}

#[test]
fn test_create_enabled_hooks_some_enabled() {
    let mut registry = HookRegistry::new();
    registry.register_hook(Box::new(MockHookFactory::new("hook1")));
    registry.register_hook(Box::new(MockHookFactory::new("hook2")));

    let mut settings = HashMap::new();
    settings.insert(
        "hook1".to_string(),
        HookSettings {
            enabled: true,
            config: toml::Value::Table(toml::map::Map::new()),
        },
    );
    settings.insert(
        "hook2".to_string(),
        HookSettings {
            enabled: false,
            config: toml::Value::Table(toml::map::Map::new()),
        },
    );

    let result = registry.create_enabled_hooks(&settings).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].0, "hook1");
}

#[test]
fn test_create_enabled_hooks_all_enabled() {
    let mut registry = HookRegistry::new();
    registry.register_hook(Box::new(MockHookFactory::new("hook1")));
    registry.register_hook(Box::new(MockHookFactory::new("hook2")));

    let mut settings = HashMap::new();
    settings.insert(
        "hook1".to_string(),
        HookSettings {
            enabled: true,
            config: toml::Value::Table(toml::map::Map::new()),
        },
    );
    settings.insert(
        "hook2".to_string(),
        HookSettings {
            enabled: true,
            config: toml::Value::Table(toml::map::Map::new()),
        },
    );

    let result = registry.create_enabled_hooks(&settings).unwrap();
    assert_eq!(result.len(), 2);
}

#[test]
fn test_create_enabled_hooks_error_propagates() {
    let mut registry = HookRegistry::new();
    registry.register_hook(Box::new(MockHookFactory::new("good")));
    registry.register_hook(Box::new(MockHookFactory::new("bad").with_init_error()));

    let mut settings = HashMap::new();
    settings.insert(
        "good".to_string(),
        HookSettings {
            enabled: true,
            config: toml::Value::Table(toml::map::Map::new()),
        },
    );
    settings.insert(
        "bad".to_string(),
        HookSettings {
            enabled: true,
            config: toml::Value::Table(toml::map::Map::new()),
        },
    );

    let result = registry.create_enabled_hooks(&settings);
    assert!(result.is_err());
}

#[test]
fn test_create_enabled_hooks_missing_factory() {
    let registry = HookRegistry::new();

    let mut settings = HashMap::new();
    settings.insert(
        "nonexistent".to_string(),
        HookSettings {
            enabled: true,
            config: toml::Value::Table(toml::map::Map::new()),
        },
    );

    let result = registry.create_enabled_hooks(&settings);
    assert!(result.is_err());
}

#[test]
fn test_hook_settings_default() {
    let settings = HookSettings::default();
    assert!(!settings.enabled);
    assert!(matches!(settings.config, toml::Value::Table(_)));
}

#[test]
fn test_hook_settings_deserialize() {
    let toml_str = r#"
            enabled = true
            some_config = "value"
            number = 42
        "#;

    let settings: HookSettings = toml::from_str(toml_str).unwrap();

    assert!(settings.enabled);

    // Config should have the remaining fields
    let table = settings.config.as_table().unwrap();
    assert_eq!(table.get("some_config").unwrap().as_str(), Some("value"));
    assert_eq!(table.get("number").unwrap().as_integer(), Some(42));
    assert!(!table.contains_key("enabled"));
}

#[test]
fn test_hook_settings_deserialize_default_enabled() {
    let toml_str = r#"
            some_config = "value"
        "#;

    let settings: HookSettings = toml::from_str(toml_str).unwrap();

    assert!(!settings.enabled); // Default to false
}

#[test]
fn test_hook_settings_deserialize_empty() {
    let toml_str = "";

    let settings: HookSettings = toml::from_str(toml_str).unwrap();

    assert!(!settings.enabled);
    assert!(settings.config.as_table().unwrap().is_empty());
}

#[test]
fn test_hook_settings_serialize() {
    let settings = HookSettings {
        enabled: true,
        config: toml::Value::Table({
            let mut t = toml::map::Map::new();
            t.insert("key".to_string(), toml::Value::String("value".to_string()));
            t
        }),
    };

    let serialized = toml::to_string(&settings).unwrap();
    assert!(serialized.contains("enabled = true"));
    assert!(serialized.contains("key = \"value\""));
}

#[test]
fn test_hook_settings_roundtrip() {
    let original = HookSettings {
        enabled: true,
        config: toml::Value::Table({
            let mut t = toml::map::Map::new();
            t.insert("key".to_string(), toml::Value::String("value".to_string()));
            t.insert("number".to_string(), toml::Value::Integer(42));
            t
        }),
    };

    let serialized = toml::to_string(&original).unwrap();
    let deserialized: HookSettings = toml::from_str(&serialized).unwrap();

    assert_eq!(deserialized.enabled, original.enabled);
    assert_eq!(
        deserialized.config.as_table().unwrap().get("key"),
        original.config.as_table().unwrap().get("key")
    );
    assert_eq!(
        deserialized.config.as_table().unwrap().get("number"),
        original.config.as_table().unwrap().get("number")
    );
}
