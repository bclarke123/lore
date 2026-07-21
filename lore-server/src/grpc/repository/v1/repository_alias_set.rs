// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_proto::lore::repository::v1::RepositoryAliasSetRequest;
use lore_proto::lore::repository::v1::RepositoryAliasSetResponse;
use lore_revision::lore::RepositoryId;
use lore_revision::repository;
use lore_revision::repository::RepositoryContext;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::info;

use crate::grpc::ServerResultExt;
use crate::grpc::extract_correlation_id;
use crate::grpc::get_user_id;
use crate::util::setup_execution;

/// `lore.repository.v1.RepositoryService.RepositoryAliasSet` handler.
///
/// Sets (or re-points) an entry in the server-wide mutable name → id table
/// so that `name` resolves to `id` in name lookups and clone URLs, and
/// optionally deletes an outgoing alias in the same call (rename/transfer).
/// The alias table is independent of the immutable metadata `name`.
///
/// The alias namespace is global to the server, so the RPC is restricted to
/// server administrators (the hub control plane, which owns the naming
/// scheme); per-repository admins must not be able to claim arbitrary
/// names. Requires server-local access control to be installed.
#[tracing::instrument(name = "RepositoryAliasSet::v1::handle", skip_all)]
pub async fn handler(
    request: Request<RepositoryAliasSetRequest>,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
) -> Result<Response<RepositoryAliasSetResponse>, Status> {
    let user_id = get_user_id(request.extensions());
    let correlation_id = extract_correlation_id(&request).unwrap_or_default();
    let authorization = request
        .metadata()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_string());
    let req = request.into_inner();

    let access = crate::access::installed().ok_or_else(|| {
        Status::unimplemented("Alias management requires server-local access control")
    })?;
    access.check_server_admin(authorization.as_deref()).await?;

    let name = req.name;
    let id: RepositoryId = Context::from(req.id).into();
    let remove_name = req.remove_name.filter(|n| !n.is_empty() && *n != name);

    if !repository::is_valid_name(&name) {
        return Err(Status::invalid_argument(format!(
            "Invalid alias name: {name}"
        )));
    }
    if id == RepositoryId::default() {
        return Err(Status::invalid_argument("Repository id must be set"));
    }
    if let Some(remove) = remove_name.as_deref()
        && !repository::is_valid_name(remove)
    {
        return Err(Status::invalid_argument(format!(
            "Invalid alias name: {remove}"
        )));
    }

    let execution = setup_execution(module_path!(), correlation_id, user_id);
    // Alias entries live under the server-wide default partition.
    let repository = Arc::new(RepositoryContext::new_server_context(
        immutable_store,
        mutable_store,
        RepositoryId::default(),
    ));

    LORE_CONTEXT
        .scope(execution, async move {
            set_alias(repository, &name, id, remove_name.as_deref()).await?;
            Ok(Response::new(RepositoryAliasSetResponse {}))
        })
        .await
}

/// Store the alias after the collision guard, then drop the outgoing alias
/// (rename/transfer). Runs against the server-wide default partition
/// context. Split from the handler so the alias semantics are testable
/// without the process-global access control.
pub(super) async fn set_alias(
    repository: Arc<RepositoryContext>,
    name: &str,
    id: RepositoryId,
    remove_name: Option<&str>,
) -> Result<(), Status> {
    // Collision guard: the global namespace is first-writer-wins. A
    // tombstoned entry resolves to the default id and is free to claim;
    // re-issuing the same name → id pair is an idempotent success.
    match repository::id_from_name(repository.clone(), name).await {
        Ok(existing) if existing != RepositoryId::default() && existing != id => {
            return Err(Status::already_exists(format!(
                "Alias {name} already resolves to repository {existing}"
            )));
        }
        _ => {}
    }

    repository::store_name_to_id(repository.clone(), name, id)
        .await
        .warn_map_err(|err| {
            Status::internal(format!("Failed to store alias {name} -> {id}: {err}"))
        })?;

    if let Some(remove) = remove_name {
        repository::delete_name_to_id(repository.clone(), remove)
            .await
            .warn_map_err(|err| {
                Status::internal(format!("Failed to remove alias {remove}: {err}"))
            })?;
        info!("Alias {remove} removed");
    }

    info!("Alias {name} -> {id} set");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::store::test_store_create;

    fn repo(hex: &str) -> RepositoryId {
        RepositoryId::from_str(hex).expect("repo id")
    }

    async fn alias_context() -> (
        Arc<RepositoryContext>,
        Arc<lore_revision::interface::ExecutionContext>,
    ) {
        let (immutable, mutable, execution) = test_store_create().await.expect("test stores");
        (
            Arc::new(RepositoryContext::new_server_context(
                immutable,
                mutable,
                RepositoryId::default(),
            )),
            execution,
        )
    }

    #[tokio::test]
    async fn set_resolve_repoint_and_collision() {
        let (context, execution) = alias_context().await;
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let first = repo("0194b726b34e72b0b45550b88a967076");
            let second = repo("f6ca55437aa34198ba0f0fdc33154d51");

            set_alias(context.clone(), "ben/listyboi", first, None)
                .await
                .expect("set alias");
            assert_eq!(
                repository::id_from_name(context.clone(), "ben/listyboi")
                    .await
                    .expect("resolve"),
                first
            );

            // Idempotent re-issue of the same pair succeeds.
            set_alias(context.clone(), "ben/listyboi", first, None)
                .await
                .expect("idempotent set");

            // A different repository cannot claim the name.
            let err = set_alias(context.clone(), "ben/listyboi", second, None)
                .await
                .expect_err("collision");
            assert_eq!(err.code(), tonic::Code::AlreadyExists);

            // Rename: new alias in, old alias out.
            set_alias(context.clone(), "ben/listy", first, Some("ben/listyboi"))
                .await
                .expect("rename");
            assert_eq!(
                repository::id_from_name(context.clone(), "ben/listy")
                    .await
                    .expect("resolve renamed"),
                first
            );
            // The old name no longer resolves to the repository (tombstoned
            // to the default id or gone entirely) and is free to claim.
            if let Ok(resolved) = repository::id_from_name(context.clone(), "ben/listyboi").await {
                assert_eq!(resolved, RepositoryId::default());
            }
            set_alias(context.clone(), "ben/listyboi", second, None)
                .await
                .expect("freed name is claimable");
        }))
        .await;
    }
}
