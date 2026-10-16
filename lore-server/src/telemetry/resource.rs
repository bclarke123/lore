// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::collections::HashMap;

use lore_base::version::LORE_LIBRARY_VERSION;
use opentelemetry::Key;
use opentelemetry::KeyValue;
use opentelemetry_sdk::resource::Resource;
use opentelemetry_semantic_conventions::SCHEMA_URL;
use opentelemetry_semantic_conventions::resource::DEPLOYMENT_ENVIRONMENT_NAME;
use opentelemetry_semantic_conventions::resource::SERVICE_NAME;
use opentelemetry_semantic_conventions::resource::SERVICE_VERSION;
use tokio::runtime::Handle;

use super::resource_provider::ResourceDetectorProvider;

/// Creates Resource entities to add to providers.
///
/// This function builds an OpenTelemetry Resource with:
/// - Environment attributes from `LORE_ENV`, `PLATFORM_INSTANCE_ID`
/// - Additional custom labels from the configuration
/// - Resource detectors provided by the [`ResourceDetectorProvider`]
pub fn resource(
    additional_labels: &Option<HashMap<String, String>>,
    runtime_handle: Handle,
    resource_detector_provider: Option<&dyn ResourceDetectorProvider>,
) -> Resource {
    let mut attributes = vec![];

    attributes.push(KeyValue::new(
        Key::new(SERVICE_NAME),
        if let Ok(app) = std::env::var("LORE_APP") {
            app
        } else {
            "lore".to_string()
        },
    ));
    attributes.push(KeyValue::new(
        Key::new(SERVICE_VERSION),
        LORE_LIBRARY_VERSION.as_str(),
    ));

    if let Ok(service_env) = std::env::var("LORE_ENV") {
        attributes.push(KeyValue::new(
            Key::new(DEPLOYMENT_ENVIRONMENT_NAME),
            service_env,
        ));
    }

    if let Ok(instance_id) = std::env::var("PLATFORM_INSTANCE_ID") {
        attributes.push(KeyValue::new("instance", instance_id));
    }

    if let Some(additional_labels) = additional_labels {
        for (k, v) in additional_labels {
            attributes.push(KeyValue::new(k.to_owned(), v.to_owned()));
        }
    }

    let mut builder = Resource::builder()
        .with_attributes(attributes.clone())
        .with_schema_url(attributes, SCHEMA_URL);

    if let Some(provider) = resource_detector_provider {
        for detector in provider.detectors(runtime_handle) {
            builder = builder.with_detector(detector);
        }
    }

    builder.build()
}
