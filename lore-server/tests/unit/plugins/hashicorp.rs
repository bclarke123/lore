// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_server::plugins::PluginRegistry;
use lore_server::plugins::TopologyPluginFactory;
use lore_server::plugins::hashicorp::*;
use tokio::runtime::Handle;

#[test]
fn test_consul_topology_factory_name() {
    let factory = ConsulTopologyPluginFactory;
    assert_eq!(factory.name(), "consul");
}

#[tokio::test]
async fn test_register_adds_nomad_resource_detector() {
    let mut registry = PluginRegistry::new();
    register(&mut registry);

    // The module registers the Nomad resource detector independently of the
    // Consul topology plugin.
    assert_eq!(registry.resource_detectors(Handle::current()).len(), 1);
}

#[test]
fn test_consul_topology_config_parsing_error() {
    let factory = ConsulTopologyPluginFactory;

    let config = toml::Value::Table(toml::map::Map::new());
    let result = factory.create(&config);

    let Err(e) = result else {
        panic!("Expected config error, got Ok");
    };
    let config_err = e
        .as_plugin_config_error()
        .expect("should be PluginConfigError");
    assert_eq!(config_err.plugin_name, "consul");
    assert!(config_err.message.contains("Failed to deserialize"));
}

#[test]
fn test_consul_topology_config_deserialization_with_all_fields() {
    let config_str = r#"
            service_name = "urc-server"
            ignore_address = "127.0.0.1"
            poll_interval_secs = 30
        "#;

    let config: toml::Value = toml::from_str(config_str).expect("Failed to parse TOML");
    let plugin_config: ConsulTopologyPluginConfig =
        config.try_into().expect("Failed to deserialize config");

    assert_eq!(plugin_config.service_name, "urc-server");
    assert_eq!(plugin_config.ignore_address, Some("127.0.0.1".to_string()));
    assert_eq!(plugin_config.poll_interval_secs, Some(30));
}

#[test]
fn test_register_adds_consul_topology_plugin() {
    let mut registry = PluginRegistry::new();
    register(&mut registry);

    let topology_plugins = registry.list_topology_plugins();
    assert!(
        topology_plugins.contains(&"consul".to_string()),
        "Expected 'consul' in topology plugins, found: {topology_plugins:?}"
    );
}

#[test]
fn test_consul_topology_creation_success() {
    let factory = ConsulTopologyPluginFactory;

    let config_str = r#"
            address = "http://localhost:8500"
            service_name = "test-service"
        "#;

    let config: toml::Value = toml::from_str(config_str).expect("Failed to parse TOML");
    let result = factory.create(&config);

    assert!(result.is_ok(), "Expected Ok, got: {:?}", result.err());
}
