// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use bytes::Bytes;
use lore_server::authnz::repository_authorizer::RepositoryAuthorizer;
use lore_server::protocol::attribute_map::AttributeMap;
use lore_server::protocol::storage::messages::LoreResponse;
use lore_server::protocol::storage::messages::Message;
use lore_server::protocol::storage::ping::*;
use rand::random;

use crate::store::test_support::test_store_create;

fn allow_all() -> Arc<dyn RepositoryAuthorizer> {
    Arc::new(lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer)
}

#[test]
fn test_parse() {
    let value = random::<i64>();
    let bytes = Bytes::copy_from_slice(&value.to_le_bytes());

    assert_eq!(Ping::parse(bytes), Ok(Ping { value }));
}

#[tokio::test]
async fn test_handle() {
    let value = random::<i64>();
    let ping_message = Ping { value };

    let (immutable_store, _mutable_store, _execution) =
        test_store_create().await.expect("Failed to create stores");

    match ping_message
        .handle(
            Arc::new(AttributeMap::default()),
            immutable_store,
            allow_all(),
        )
        .await
    {
        Ok(LoreResponse::Ping(response)) => assert_eq!(response, PingResponse { value }),
        default => panic!("Got unexpected response from handling ping message: {default:?}"),
    }
}
