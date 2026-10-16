// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::lore_spawn;
use lore_server::protocol::attribute_map::*;
use lore_server::protocol::client_identify::UserAgentValue;
use lore_telemetry::USER_AGENT_NONE;

mod user_agent_label {
    use opentelemetry::Value;
    use opentelemetry_semantic_conventions::attribute::USER_AGENT_NAME;

    use super::*;

    #[test]
    fn the_announced_client_is_reported() {
        let context = AttributeMap::default();
        context.insert(UserAgentValue(Arc::from("agent/1")));

        let label = context.user_agent_label();

        assert_eq!(label.key.as_str(), USER_AGENT_NAME);
        assert_eq!(label.value, Value::String("agent/1".into()));
    }

    /// A client announces itself in a message, so a connection reports this until it does.
    /// Recorded rather than left off so that a series exists to compare against once it has.
    #[test]
    fn a_client_that_has_not_announced_itself_reports_the_absent_value() {
        let label = AttributeMap::default().user_agent_label();

        assert_eq!(label.value, Value::String(USER_AGENT_NONE.as_ref().into()));
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TestData {
    foo: &'static str,
    bar: Vec<u8>,
}

#[tokio::test]
async fn test_attribute_map() {
    let map = Arc::new(AttributeMap::default());

    let m: Arc<AttributeMap> = Arc::clone(&map);
    lore_spawn!(async move {
        m.insert(42);
    })
    .await
    .expect("failed to await");

    assert_eq!(&42, &*map.get::<i32>().unwrap());

    let m: Arc<AttributeMap> = Arc::clone(&map);
    lore_spawn!(async move {
        m.insert(834);
    })
    .await
    .expect("failed to await");

    assert_eq!(&834, &*map.get::<i32>().unwrap());

    let data = TestData {
        foo: "bar",
        bar: b"hello".to_vec(),
    };
    let data_clone = data.clone();

    let m: Arc<AttributeMap> = Arc::clone(&map);
    lore_spawn!(async move {
        m.insert(data_clone);
    })
    .await
    .expect("failed to await");

    assert_eq!(&data, &*map.get::<TestData>().unwrap());
}

#[test]
fn test_get_or() {
    let map = AttributeMap::default();

    map.insert(42);

    assert_eq!(
        &42,
        &*map.get_or::<i32, &str>("Not Found").expect("failed to get")
    );

    assert_eq!(
        "Not Found",
        map.get_or::<TestData, &str>("Not Found")
            .expect_err("should have returned an error")
    );
}
