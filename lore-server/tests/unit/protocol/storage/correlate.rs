// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::str::FromStr;
use std::sync::Arc;

use bytes::Bytes;
use lore_server::authnz::repository_authorizer::RepositoryAuthorizer;
use lore_server::correlation::CorrelationId;
use lore_server::protocol::attribute_map::AttributeMap;
use lore_server::protocol::storage::correlate::*;
use lore_server::protocol::storage::messages::LoreResponse;
use lore_server::protocol::storage::messages::Message;
use lore_server::protocol::storage::messages::Response;

use crate::store::test_support::test_store_create;

fn allow_all() -> Arc<dyn RepositoryAuthorizer> {
    Arc::new(lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer)
}

#[test]
fn test_parse() {
    let correlation_id = uuid::Uuid::new_v4().to_string();

    let bytes = bytes::Bytes::from(correlation_id.clone());

    assert_eq!(
        Correlate::parse(bytes),
        Ok(Correlate {
            correlation_id: Some(correlation_id)
        })
    );
}

#[test]
fn test_parse_correlation_id_too_short() {
    assert_eq!(
        Correlate::parse(bytes::Bytes::from(
            "a".repeat(MIN_CORRELATION_ID_LENGTH - 1),
        )),
        Ok(Correlate {
            correlation_id: None
        })
    );
}

#[test]
fn test_parse_correlation_id_too_long() {
    assert_eq!(
        Correlate::parse(bytes::Bytes::from(
            "a".repeat(MAX_CORRELATION_ID_LENGTH + 1),
        )),
        Ok(Correlate {
            correlation_id: None
        })
    );
}

#[test]
fn test_parse_correlation_id_non_ascii() {
    assert_eq!(
        Correlate::parse(bytes::Bytes::from("🙅‍♂️🙋‍♂️🔑".repeat(3),)),
        Ok(Correlate {
            correlation_id: None
        })
    );
}

#[tokio::test]
async fn test_handle() {
    let correlation_id = uuid::Uuid::new_v4().to_string();

    let message = Correlate {
        correlation_id: Some(correlation_id.clone()),
    };

    let context = Arc::new(AttributeMap::default());

    let (immutable_store, _mutable_store, _execution) =
        test_store_create().await.expect("Failed to create stores");

    let response = message
        .handle(context.clone(), immutable_store, allow_all())
        .await
        .unwrap();
    assert_eq!(
        LoreResponse::Correlate(CorrelateResponse {
            correlation_id: correlation_id.clone()
        }),
        response
    );

    assert_eq!(correlation_id, **context.get::<CorrelationId>().unwrap());

    assert_eq!(
        vec![Bytes::copy_from_slice(correlation_id.as_bytes())],
        response.data()
    );
}

#[tokio::test]
async fn test_handle_correlation_id_already_set() {
    let context = Arc::new(AttributeMap::default());
    context.insert(CorrelationId::new(uuid::Uuid::new_v4()));

    let correlation_id = uuid::Uuid::new_v4().to_string();
    let message = Correlate {
        correlation_id: Some(correlation_id.clone()),
    };

    let (immutable_store, _mutable_store, _execution) =
        test_store_create().await.expect("Failed to create stores");

    assert_eq!(
        LoreResponse::Correlate(CorrelateResponse {
            correlation_id: correlation_id.clone()
        }),
        message
            .handle(context.clone(), immutable_store, allow_all())
            .await
            .unwrap()
    );

    assert_eq!(correlation_id, **context.get::<CorrelationId>().unwrap());
}

#[tokio::test]
async fn test_handle_correlation_id_missing() {
    let message = Correlate {
        correlation_id: None,
    };

    let context = Arc::new(AttributeMap::default());
    let correlation_id = uuid::Uuid::new_v4();
    context.insert(CorrelationId::new(correlation_id));

    let (immutable_store, _mutable_store, _execution) =
        test_store_create().await.expect("Failed to create stores");

    assert_eq!(
        LoreResponse::Correlate(CorrelateResponse {
            correlation_id: correlation_id.to_string()
        }),
        message
            .handle(context.clone(), immutable_store, allow_all())
            .await
            .unwrap()
    );

    assert_eq!(
        correlation_id.to_string(),
        **context.get::<CorrelationId>().unwrap()
    );
}

#[tokio::test]
async fn test_handle_correlation_id_missing_not_set_in_context() {
    let message = Correlate {
        correlation_id: None,
    };

    let context = Arc::new(AttributeMap::default());

    let (immutable_store, _mutable_store, _execution) =
        test_store_create().await.expect("Failed to create stores");

    match message
        .handle(context.clone(), immutable_store, allow_all())
        .await
        .unwrap()
    {
        LoreResponse::Correlate(CorrelateResponse { correlation_id }) => {
            uuid::Uuid::from_str(&correlation_id).expect("Correlation id was invalid");
        }
        default => {
            panic!("Unexpected response from Correlate::handle: {default:?}");
        }
    }
}
