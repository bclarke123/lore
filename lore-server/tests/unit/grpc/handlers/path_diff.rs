// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::str::FromStr;
use std::sync::Arc;

use bytes::Bytes;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_proto::Path;
use lore_proto::PathDiff;
use lore_proto::PathType;
use lore_revision::change::Flags;
use lore_revision::change::NodeChange;
use lore_revision::change::NodeChangeState;
use lore_revision::link::LinkPinChange;
use lore_revision::lore::RepositoryId;
use lore_revision::node::INVALID_NODE;
use lore_revision::node::NodeFlags;
use lore_revision::repository::RepositoryContext;
use lore_revision::repository::RepositoryContextCreationArgs;
use lore_revision::state;
use lore_revision::util::path::RelativePath;
use lore_server::grpc::handlers::path_diff::link_pin_change_to_path_diff;
use lore_server::grpc::handlers::path_diff::map_to_path_diff;
use lore_transport::ProtocolError;

pub async fn new_test_context() -> Arc<lore_revision::repository::RepositoryContext> {
    let immutable = lore_storage::local::immutable_store::LocalImmutableStore::new(
        None,
        lore_storage::local::immutable_store::ImmutableStoreSettings::default(),
    )
    .await
    .expect("Failed to create store");
    let mutable = Arc::new(
        lore_storage::local::mutable_store::LocalMutableStore::new(
            None::<&std::path::Path>,
            lore_storage::MutableStoreSettings::default(),
            immutable.clone(),
        )
        .await
        .expect("Failed to create store"),
    );
    Arc::new(RepositoryContext::new(RepositoryContextCreationArgs {
        paths: None,
        immutable_store: immutable,
        mutable_store: mutable,
        id: Context::default().into(),
        instance_id: lore_revision::instance::InstanceId::generate(),
        remote: Err(ProtocolError::from(lore_base::error::NoRemote)),
        filter: Arc::default(),
        filesystem_provider: None,
    }))
}

#[tokio::test]
async fn test_mapping_addition() {
    let a_context = Context::default();
    let a_hash = Hash::hash_buffer(&[0, 1, 2, 3]);
    let address_to = Address {
        hash: a_hash,
        context: a_context,
    };

    let repository = new_test_context().await;
    let state = state::State::new();

    let addition = NodeChange {
        action: lore_revision::change::FileAction::Add,
        flags: Flags::None,
        from: NodeChangeState {
            mapping: lore_revision::state::NodeMapping {
                path: RelativePath::from_str("Samples/Content/file.uasset").unwrap(),
                node: 1,
                repository: repository.clone(),
                state: state.clone(),
            },
            address: Address::default(),
            observed: None,
            mode: 0,
            flags: NodeFlags::NoFlags,
        },
        to: NodeChangeState {
            mapping: lore_revision::state::NodeMapping {
                path: RelativePath::from_str("Samples/Content/file.uasset").unwrap(),
                node: 2,
                repository: repository.clone(),
                state: state.clone(),
            },
            address: address_to,
            observed: None,
            mode: 0,
            flags: NodeFlags::File,
        },
    };
    let mapped = map_to_path_diff(&addition, repository.id).await;
    assert_eq!(
        mapped,
        Some(PathDiff {
            from: None,
            to: Some(Path {
                path: "Samples/Content/file.uasset".to_string(),
                address: address_to.into(),
                r#type: PathType::File as i32,
                tracking: false,
            }),
            automerged: false,
            link_partition: Bytes::new(),
            tracking: false,
        })
    );
}

#[tokio::test]
async fn test_mapping_deletion() {
    let a_context = Context::default();
    let a_hash = Hash::hash_buffer(&[0, 1, 2, 3]);
    let address_from = Address {
        hash: a_hash,
        context: a_context,
    };

    let repository = new_test_context().await;
    let state = state::State::new();

    let deletion = NodeChange {
        action: lore_revision::change::FileAction::Delete,
        flags: Flags::None,
        from: NodeChangeState {
            mapping: lore_revision::state::NodeMapping {
                path: RelativePath::from_str("Samples/Content/file.uasset").unwrap(),
                node: 1,
                repository: repository.clone(),
                state: state.clone(),
            },
            address: address_from,
            observed: None,
            mode: 0,
            flags: NodeFlags::File,
        },
        to: NodeChangeState {
            mapping: lore_revision::state::NodeMapping {
                path: RelativePath::from_str("Samples/Content/file.uasset").unwrap(),
                node: 2,
                repository: repository.clone(),
                state: state.clone(),
            },
            address: Address::default(),
            observed: None,
            mode: 0,
            flags: NodeFlags::File,
        },
    };
    let mapped = map_to_path_diff(&deletion, repository.id).await;
    assert_eq!(
        mapped,
        Some(PathDiff {
            from: Some(Path {
                path: "Samples/Content/file.uasset".to_string(),
                address: address_from.into(),
                r#type: PathType::File as i32,
                tracking: false,
            }),
            to: None,
            automerged: false,
            link_partition: Bytes::new(),
            tracking: false,
        })
    );
}

#[tokio::test]
async fn test_mapping_modification() {
    let a_context = Context::default();
    let a_hash = Hash::hash_buffer(&[0, 1, 2, 3]);
    let address_from = Address {
        hash: a_hash,
        context: a_context,
    };
    let address_to = Address {
        hash: a_hash,
        context: a_context,
    };

    let repository = new_test_context().await;
    let state = state::State::new();

    let modification = NodeChange {
        action: lore_revision::change::FileAction::Keep,
        flags: Flags::None,
        from: NodeChangeState {
            mapping: lore_revision::state::NodeMapping {
                path: RelativePath::from_str("Samples/Content/file.uasset").unwrap(),
                node: 1,
                repository: repository.clone(),
                state: state.clone(),
            },
            address: address_from,
            observed: None,
            mode: 0,
            flags: NodeFlags::File,
        },
        to: NodeChangeState {
            mapping: lore_revision::state::NodeMapping {
                path: RelativePath::from_str("Samples/Content/file.uasset").unwrap(),
                node: 2,
                repository: repository.clone(),
                state: state.clone(),
            },
            address: address_to,
            observed: None,
            mode: 0,
            flags: NodeFlags::File,
        },
    };
    let mapped = map_to_path_diff(&modification, repository.id).await;
    assert_eq!(
        mapped,
        Some(PathDiff {
            from: Some(Path {
                path: "Samples/Content/file.uasset".to_string(),
                address: address_from.into(),
                r#type: PathType::File as i32,
                tracking: false,
            }),
            to: Some(Path {
                path: "Samples/Content/file.uasset".to_string(),
                address: address_to.into(),
                r#type: PathType::File as i32,
                tracking: false,
            }),
            automerged: false,
            link_partition: Bytes::new(),
            tracking: false,
        })
    );
}

#[tokio::test]
async fn test_mapping_empty_files_with_zero_hash() {
    let a_context = Context::default();
    let a_hash = Hash::default();
    let address_to = Address {
        hash: a_hash,
        context: a_context,
    };

    let repository = new_test_context().await;
    let state = state::State::new();

    let addition = NodeChange {
        action: lore_revision::change::FileAction::Add,
        flags: Flags::None,
        from: NodeChangeState {
            mapping: lore_revision::state::NodeMapping {
                path: RelativePath::from_str("Samples/Content/file.uasset").unwrap(),
                node: 1,
                repository: repository.clone(),
                state: state.clone(),
            },
            address: Address::default(),
            observed: None,
            mode: 0,
            flags: NodeFlags::NoFlags,
        },
        to: NodeChangeState {
            mapping: lore_revision::state::NodeMapping {
                path: RelativePath::from_str("Samples/Content/file.uasset").unwrap(),
                node: 2,
                repository: repository.clone(),
                state: state.clone(),
            },
            address: address_to,
            observed: None,
            mode: 0,
            flags: NodeFlags::File,
        },
    };
    let mapped = map_to_path_diff(&addition, repository.id).await;
    assert_eq!(
        mapped,
        Some(PathDiff {
            from: None,
            to: Some(Path {
                path: "Samples/Content/file.uasset".to_string(),
                address: address_to.into(),
                r#type: PathType::File as i32,
                tracking: false,
            }),
            automerged: false,
            link_partition: Bytes::new(),
            tracking: false,
        })
    );
}

#[tokio::test]
async fn test_mapping_link_addition() {
    let a_context = Context::default();
    let a_hash = Hash::hash_buffer(&[4, 5, 6, 7]);
    let address_to = Address {
        hash: a_hash,
        context: a_context,
    };

    let repository = new_test_context().await;
    let state = state::State::new();

    let link_addition = NodeChange {
        action: lore_revision::change::FileAction::Add,
        flags: Flags::None,
        from: NodeChangeState {
            mapping: lore_revision::state::NodeMapping {
                path: RelativePath::from_str("Samples/Content/submodule").unwrap(),
                node: 1,
                repository: repository.clone(),
                state: state.clone(),
            },
            address: Address::default(),
            observed: None,
            mode: 0,
            flags: NodeFlags::NoFlags,
        },
        to: NodeChangeState {
            mapping: lore_revision::state::NodeMapping {
                path: RelativePath::from_str("Samples/Content/submodule").unwrap(),
                node: 2,
                repository: repository.clone(),
                state: state.clone(),
            },
            address: address_to,
            observed: None,
            mode: 0,
            flags: NodeFlags::Link,
        },
    };
    let mapped = map_to_path_diff(&link_addition, repository.id).await;
    assert_eq!(
        mapped,
        Some(PathDiff {
            from: None,
            to: Some(Path {
                path: "Samples/Content/submodule".to_string(),
                address: address_to.into(),
                r#type: PathType::Link as i32,
                tracking: false,
            }),
            automerged: false,
            link_partition: Bytes::new(),
            tracking: false,
        })
    );
}

#[tokio::test]
async fn test_mapping_link_deletion() {
    let a_context = Context::default();
    let a_hash = Hash::hash_buffer(&[8, 9, 10, 11]);
    let address_from = Address {
        hash: a_hash,
        context: a_context,
    };

    let repository = new_test_context().await;
    let state = state::State::new();

    let link_deletion = NodeChange {
        action: lore_revision::change::FileAction::Delete,
        flags: Flags::None,
        from: NodeChangeState {
            mapping: lore_revision::state::NodeMapping {
                path: RelativePath::from_str("Samples/Content/submodule").unwrap(),
                node: 1,
                repository: repository.clone(),
                state: state.clone(),
            },
            address: address_from,
            observed: None,
            mode: 0,
            flags: NodeFlags::Link,
        },
        to: NodeChangeState {
            mapping: lore_revision::state::NodeMapping {
                path: RelativePath::from_str("Samples/Content/submodule").unwrap(),
                node: 2,
                repository: repository.clone(),
                state: state.clone(),
            },
            address: Address::default(),
            observed: None,
            mode: 0,
            flags: NodeFlags::Link,
        },
    };
    let mapped = map_to_path_diff(&link_deletion, repository.id).await;
    assert_eq!(
        mapped,
        Some(PathDiff {
            from: Some(Path {
                path: "Samples/Content/submodule".to_string(),
                address: address_from.into(),
                r#type: PathType::Link as i32,
                tracking: false,
            }),
            to: None,
            automerged: false,
            link_partition: Bytes::new(),
            tracking: false,
        })
    );
}

#[tokio::test]
async fn test_mapping_link_modification() {
    let a_context = Context::default();
    let a_hash_from = Hash::hash_buffer(&[12, 13, 14, 15]);
    let a_hash_to = Hash::hash_buffer(&[16, 17, 18, 19]);
    let address_from = Address {
        hash: a_hash_from,
        context: a_context,
    };
    let address_to = Address {
        hash: a_hash_to,
        context: a_context,
    };

    let repository = new_test_context().await;
    let state = state::State::new();

    let link_modification = NodeChange {
        action: lore_revision::change::FileAction::Keep,
        flags: Flags::None,
        from: NodeChangeState {
            mapping: lore_revision::state::NodeMapping {
                path: RelativePath::from_str("Samples/Content/submodule").unwrap(),
                node: 1,
                repository: repository.clone(),
                state: state.clone(),
            },
            address: address_from,
            observed: None,
            mode: 0,
            flags: NodeFlags::Link,
        },
        to: NodeChangeState {
            mapping: lore_revision::state::NodeMapping {
                path: RelativePath::from_str("Samples/Content/submodule").unwrap(),
                node: 2,
                repository: repository.clone(),
                state: state.clone(),
            },
            address: address_to,
            observed: None,
            mode: 0,
            flags: NodeFlags::Link,
        },
    };
    let mapped = map_to_path_diff(&link_modification, repository.id).await;
    assert_eq!(
        mapped,
        Some(PathDiff {
            from: Some(Path {
                path: "Samples/Content/submodule".to_string(),
                address: address_from.into(),
                r#type: PathType::Link as i32,
                tracking: false,
            }),
            to: Some(Path {
                path: "Samples/Content/submodule".to_string(),
                address: address_to.into(),
                r#type: PathType::Link as i32,
                tracking: false,
            }),
            automerged: false,
            link_partition: Bytes::new(),
            tracking: false,
        })
    );
}

#[tokio::test]
async fn test_mapping_automerged_conflict() {
    let a_context = Context::default();
    let a_hash_from = Hash::hash_buffer(&[20, 21, 22, 23]);
    let a_hash_to = Hash::hash_buffer(&[24, 25, 26, 27]);
    let address_from = Address {
        hash: a_hash_from,
        context: a_context,
    };
    let address_to = Address {
        hash: a_hash_to,
        context: a_context,
    };

    let repository = new_test_context().await;
    let state = state::State::new();

    let automerged_change = NodeChange {
        action: lore_revision::change::FileAction::Keep,
        flags: Flags::ConflictAutomerged,
        from: NodeChangeState {
            mapping: lore_revision::state::NodeMapping {
                path: RelativePath::from_str("Samples/Content/merged.txt").unwrap(),
                node: 1,
                repository: repository.clone(),
                state: state.clone(),
            },
            address: address_from,
            observed: None,
            mode: 0,
            flags: NodeFlags::File,
        },
        to: NodeChangeState {
            mapping: lore_revision::state::NodeMapping {
                path: RelativePath::from_str("Samples/Content/merged.txt").unwrap(),
                node: 2,
                repository: repository.clone(),
                state: state.clone(),
            },
            address: address_to,
            observed: None,
            mode: 0,
            flags: NodeFlags::File,
        },
    };
    let mapped = map_to_path_diff(&automerged_change, repository.id).await;
    assert_eq!(
        mapped,
        Some(PathDiff {
            from: Some(Path {
                path: "Samples/Content/merged.txt".to_string(),
                address: address_from.into(),
                r#type: PathType::File as i32,
                tracking: false,
            }),
            to: Some(Path {
                path: "Samples/Content/merged.txt".to_string(),
                address: address_to.into(),
                r#type: PathType::File as i32,
                tracking: false,
            }),
            automerged: true,
            link_partition: Bytes::new(),
            tracking: false,
        })
    );
}

/// A link into a different repository stamps `link_partition` with that
/// target repository id.
#[tokio::test]
async fn test_mapping_cross_link_sets_partition() {
    let repository = new_test_context().await;
    let state = state::State::new();

    let target_repository = RepositoryId::from(uuid::Uuid::now_v7());
    let a_hash = Hash::hash_buffer(&[30, 31, 32, 33]);
    let address_to = Address {
        hash: a_hash,
        context: target_repository.into(),
    };

    let link_addition = NodeChange {
        action: lore_revision::change::FileAction::Add,
        flags: Flags::None,
        from: NodeChangeState {
            mapping: lore_revision::state::NodeMapping {
                path: RelativePath::from_str("Samples/Content/submodule").unwrap(),
                node: 1,
                repository: repository.clone(),
                state: state.clone(),
            },
            address: Address::default(),
            observed: None,
            mode: 0,
            flags: NodeFlags::NoFlags,
        },
        to: NodeChangeState {
            mapping: lore_revision::state::NodeMapping {
                path: RelativePath::from_str("Samples/Content/submodule").unwrap(),
                node: 2,
                repository: repository.clone(),
                state: state.clone(),
            },
            address: address_to,
            observed: None,
            mode: 0,
            flags: NodeFlags::Link,
        },
    };

    let mapped = map_to_path_diff(&link_addition, repository.id)
        .await
        .expect("link addition maps to a diff");
    assert_eq!(
        mapped.link_partition,
        Bytes::from(target_repository),
        "cross-repository link change carries the target repository partition",
    );
    // No link reference is recorded, so tracking falls back to pinned.
    assert!(!mapped.tracking);
}

/// A link into the request's own repository leaves `link_partition` empty.
#[tokio::test]
async fn test_mapping_same_repo_partition_empty() {
    let repository = new_test_context().await;
    let state = state::State::new();

    let a_hash = Hash::hash_buffer(&[40, 41, 42, 43]);
    let address_to = Address {
        hash: a_hash,
        // new_test_context uses the default context as its repository id.
        context: Context::default(),
    };

    let link_addition = NodeChange {
        action: lore_revision::change::FileAction::Add,
        flags: Flags::None,
        from: NodeChangeState {
            mapping: lore_revision::state::NodeMapping {
                path: RelativePath::from_str("Samples/Content/submodule").unwrap(),
                node: 1,
                repository: repository.clone(),
                state: state.clone(),
            },
            address: Address::default(),
            observed: None,
            mode: 0,
            flags: NodeFlags::NoFlags,
        },
        to: NodeChangeState {
            mapping: lore_revision::state::NodeMapping {
                path: RelativePath::from_str("Samples/Content/submodule").unwrap(),
                node: 2,
                repository: repository.clone(),
                state: state.clone(),
            },
            address: address_to,
            observed: None,
            mode: 0,
            flags: NodeFlags::Link,
        },
    };

    let mapped = map_to_path_diff(&link_addition, repository.id)
        .await
        .expect("link addition maps to a diff");
    assert!(
        mapped.link_partition.is_empty(),
        "same-repository change leaves the partition empty",
    );
    assert!(!mapped.tracking);
}

/// Content walked out of a linked repository carries that repository as
/// its partition, even though nothing in its address identifies it.
#[tokio::test]
async fn test_mapping_content_inside_link_sets_partition() {
    let repository = new_test_context().await;
    let state = state::State::new();

    let linked_repository_id = RepositoryId::from(uuid::Uuid::now_v7());
    let linked_repository = repository.to_link_context(linked_repository_id).await;

    let hash_from = Hash::hash_buffer(&[50, 51, 52, 53]);
    let hash_to = Hash::hash_buffer(&[54, 55, 56, 57]);
    let file_context = Context::default();

    let modification = NodeChange {
        action: lore_revision::change::FileAction::Keep,
        flags: Flags::None,
        from: NodeChangeState {
            mapping: lore_revision::state::NodeMapping {
                path: RelativePath::from_str("libs/shared/a.txt").unwrap(),
                node: 3,
                repository: linked_repository.clone(),
                state: state.clone(),
            },
            address: Address {
                hash: hash_from,
                context: file_context,
            },
            observed: None,
            mode: 0,
            flags: NodeFlags::File,
        },
        to: NodeChangeState {
            mapping: lore_revision::state::NodeMapping {
                path: RelativePath::from_str("libs/shared/a.txt").unwrap(),
                node: 4,
                repository: linked_repository.clone(),
                state: state.clone(),
            },
            address: Address {
                hash: hash_to,
                context: file_context,
            },
            observed: None,
            mode: 0,
            flags: NodeFlags::File,
        },
    };

    let mapped = map_to_path_diff(&modification, repository.id)
        .await
        .expect("link content modification maps to a diff");
    assert_eq!(
        mapped.link_partition,
        Bytes::from(linked_repository_id),
        "content walked out of a linked repository must carry that \
             repository as its partition so consumers fetch from the right one",
    );
    assert_eq!(
        mapped.to.expect("modification has a to side").r#type,
        PathType::File as i32,
        "the entry is still a file, only its partition differs",
    );
    assert!(
        !mapped.tracking,
        "tracking is only meaningful on a LINK entry; a node inside a \
             linked repository has no link reference of its own",
    );
}

/// A deletion resolves its partition from the surviving `from` side.
#[tokio::test]
async fn test_mapping_deleted_content_inside_link_sets_partition() {
    let repository = new_test_context().await;
    let state = state::State::new();

    let linked_repository_id = RepositoryId::from(uuid::Uuid::now_v7());
    let linked_repository = repository.to_link_context(linked_repository_id).await;

    let deletion = NodeChange {
        action: lore_revision::change::FileAction::Delete,
        flags: Flags::None,
        from: NodeChangeState {
            mapping: lore_revision::state::NodeMapping {
                path: RelativePath::from_str("libs/shared/gone.txt").unwrap(),
                node: 3,
                repository: linked_repository.clone(),
                state: state.clone(),
            },
            address: Address {
                hash: Hash::hash_buffer(&[60, 61, 62, 63]),
                context: Context::default(),
            },
            observed: None,
            mode: 0,
            flags: NodeFlags::File,
        },
        to: NodeChangeState {
            mapping: lore_revision::state::NodeMapping {
                path: RelativePath::from_str("libs/shared/gone.txt").unwrap(),
                node: INVALID_NODE,
                repository: linked_repository.clone(),
                state: state.clone(),
            },
            address: Address::default(),
            observed: None,
            mode: 0,
            flags: NodeFlags::NoFlags,
        },
    };

    let mapped = map_to_path_diff(&deletion, repository.id)
        .await
        .expect("link content deletion maps to a diff");
    assert_eq!(
        mapped.link_partition,
        Bytes::from(linked_repository_id),
        "a deletion resolves its partition from the surviving `from` side",
    );
}

/// Ordinary parent-repository content is unaffected: no partition.
#[tokio::test]
async fn test_mapping_parent_content_leaves_partition_empty() {
    let repository = new_test_context().await;
    let state = state::State::new();

    let modification = NodeChange {
        action: lore_revision::change::FileAction::Keep,
        flags: Flags::None,
        from: NodeChangeState {
            mapping: lore_revision::state::NodeMapping {
                path: RelativePath::from_str("README.txt").unwrap(),
                node: 1,
                repository: repository.clone(),
                state: state.clone(),
            },
            address: Address {
                hash: Hash::hash_buffer(&[70, 71]),
                context: Context::default(),
            },
            observed: None,
            mode: 0,
            flags: NodeFlags::File,
        },
        to: NodeChangeState {
            mapping: lore_revision::state::NodeMapping {
                path: RelativePath::from_str("README.txt").unwrap(),
                node: 1,
                repository: repository.clone(),
                state: state.clone(),
            },
            address: Address {
                hash: Hash::hash_buffer(&[72, 73]),
                context: Context::default(),
            },
            observed: None,
            mode: 0,
            flags: NodeFlags::File,
        },
    };

    let mapped = map_to_path_diff(&modification, repository.id)
        .await
        .expect("parent content modification maps to a diff");
    assert!(
        mapped.link_partition.is_empty(),
        "content in the request's own repository has no partition",
    );
}

fn pin_change(link_repository: RepositoryId) -> LinkPinChange {
    LinkPinChange {
        link_path: "libs/shared".to_string(),
        link_repository,
        revision_from: Hash::hash_buffer(&[80, 81]),
        revision_to: Hash::hash_buffer(&[82, 83]),
        tracking_from: false,
        tracking_to: true,
    }
}

/// Both sides carry their own revision and tracking flag.
#[test]
fn test_pin_change_maps_both_sides() {
    let parent = RepositoryId::from(uuid::Uuid::now_v7());
    let linked = RepositoryId::from(uuid::Uuid::now_v7());
    let change = pin_change(linked);

    let mapped = link_pin_change_to_path_diff(&change, parent);
    let from = mapped.from.expect("updated pin has a from side");
    let to = mapped.to.expect("updated pin has a to side");

    assert_eq!(from.path, "libs/shared");
    assert_eq!(to.path, "libs/shared");
    assert_eq!(from.r#type, PathType::Link as i32);
    assert_eq!(to.r#type, PathType::Link as i32);
    assert_ne!(from.address, to.address, "the pin moved");
    assert_eq!(
        from.address,
        Bytes::from(Address {
            hash: change.revision_from,
            context: linked.into(),
        }),
        "a link's content address is the revision it is pinned to, under \
             the linked repository's context",
    );
    assert!(!from.tracking);
    assert!(to.tracking);
    assert!(mapped.tracking, "the entry reports the target side");
    assert_eq!(mapped.link_partition, Bytes::from(linked));
    assert!(!mapped.automerged);
}

/// A link into the request's own repository needs no partition.
#[test]
fn test_pin_change_same_repository_leaves_partition_empty() {
    let parent = RepositoryId::from(uuid::Uuid::now_v7());
    let change = pin_change(parent);

    let mapped = link_pin_change_to_path_diff(&change, parent);
    assert!(mapped.link_partition.is_empty());
}
