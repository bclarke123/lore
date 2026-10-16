// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::LazyLock;

use lore_telemetry::InstrumentProvider;
use lore_telemetry::METRICS_OPERATION_CONTEXT_ATTRIBUTE_NAME;
use opentelemetry::KeyValue;

// Test for InstrumentProvider trait
static TEST_PROVIDER_ATTRIBUTES: LazyLock<[KeyValue; 2]> = LazyLock::new(|| {
    [
        KeyValue::new("key1".to_string(), "value1".to_string()),
        KeyValue::new("key2".to_string(), "value2".to_string()),
    ]
});

struct TestProvider {}
impl InstrumentProvider for TestProvider {
    fn namespace(&self) -> &'static str {
        "test-namespace"
    }

    fn labels(&self) -> &[KeyValue] {
        TEST_PROVIDER_ATTRIBUTES.as_slice()
    }
}

#[test]
fn can_concatenate_context_label() {
    let test_provider = TestProvider {};

    let all_labels = test_provider.get_labels_for_operation_context("my-test-context");
    assert_eq!(all_labels.len(), 3);
    assert_eq!(all_labels[0].key.as_str(), "key1");
    assert_eq!(all_labels[0].value.as_str(), "value1");
    assert_eq!(all_labels[1].key.as_str(), "key2");
    assert_eq!(all_labels[1].value.as_str(), "value2");

    assert_eq!(
        all_labels[2].key.as_str(),
        METRICS_OPERATION_CONTEXT_ATTRIBUTE_NAME
    );
    assert_eq!(all_labels[2].value.as_str(), "my-test-context");
}
