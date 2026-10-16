// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::collections::HashMap;

use lore_server::telemetry::resource::*;
use opentelemetry::Key;
use opentelemetry::Value;
use tokio::runtime::Handle;
#[tokio::test(flavor = "multi_thread")]
async fn base_resource_labels() {
    temp_env::with_vars([("PLATFORM_INSTANCE_ID", Some("i-mine"))], || {
        let resource = resource(&None, Handle::current(), None);

        assert_eq!(
            resource.get(&Key::from_static_str("instance")),
            Some(Value::from("i-mine"))
        );
    });
}

#[tokio::test(flavor = "multi_thread")]
async fn test_resource_with_additional_labels() {
    let labels = Some(HashMap::from([(
        "some-key".to_owned(),
        "some-value".to_owned(),
    )]));
    let resource = resource(&labels, Handle::current(), None);

    let mut found = false;
    for (k, v) in resource.iter() {
        if k.as_str() == "some-key" {
            assert_eq!(v.as_str(), "some-value");
            found = true;
        }
    }

    assert!(found);
}
