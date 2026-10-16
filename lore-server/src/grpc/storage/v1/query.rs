// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use bytes::BytesMut;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_base::types::TypedBytesMut;
use lore_proto::lore::storage::v1 as storage_v1;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::Instrument;
use zerocopy::IntoBytes;

use crate::grpc::extract_correlation_id;
use crate::grpc::get_repository;
use crate::grpc::get_user_id;
use crate::grpc::log_server_error;
use crate::grpc::simple_map_message_handle_error;
use crate::protocol::storage::messages::LoreResponse;
use crate::protocol::storage::query::handle_query;
use crate::util::setup_execution;

#[tracing::instrument(name = "StorageServiceV1::Query", skip_all)]
pub async fn handler(
    request: Request<storage_v1::QueryRequest>,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
) -> Result<Response<storage_v1::QueryResponse>, Status> {
    let repository = get_repository(request.metadata())?;
    let user_id = get_user_id(request.extensions());
    let correlation_id = extract_correlation_id(&request).unwrap_or_default();

    let execution = setup_execution(module_path!(), correlation_id, user_id);

    LORE_CONTEXT
        .scope(
            execution,
            async move {
                let req = request.into_inner();

                if req.addresses.len() > crate::protocol::storage::query::MAX_FRAGMENTS {
                    return Err(Status::invalid_argument(format!(
                        "too many addresses: {} exceeds limit {}",
                        req.addresses.len(),
                        crate::protocol::storage::query::MAX_FRAGMENTS,
                    )));
                }

                let mut address = BytesMut::with_count_capacity::<Address>(req.addresses.len());
                for addr in req.addresses {
                    address.extend_from_slice(
                        Address {
                            hash: Hash::from(addr.hash),
                            context: Context::from(addr.context),
                        }
                        .as_bytes(),
                    );
                }
                let address = address.freeze();

                handle_query(&address, repository, immutable_store)
                    .await
                    .map(|resp| {
                        let LoreResponse::Query(resp) = resp else {
                            panic!("Query handler returned the wrong response type");
                        };

                        let results = resp.results.iter().map(|res| *res as i32).collect();
                        Response::new(storage_v1::QueryResponse { results })
                    })
                    .map_err(simple_map_message_handle_error)
                    .inspect_err(log_server_error)
            }
            .in_current_span(),
        )
        .await
}
