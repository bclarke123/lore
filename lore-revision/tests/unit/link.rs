// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_base::runtime::LORE_CONTEXT;
use lore_revision::link::*;
use lore_revision::lore::RepositoryId;
use lore_revision::node::NodeID;
use lore_revision::repository::RepositoryContext;
use lore_revision::state::State;

use crate::fs::filesystem_provider::setup_test_execution;
use crate::fs::filesystem_provider::test_store_create;

fn link(link_repository_id: RepositoryId, link_node_id: NodeID) -> LinkContext {
    LinkContext {
        link_repository_id,
        link_node_id,
        parent_repository_id: RepositoryId::from([9; 16]),
        link_state: State::new(),
    }
}

/// A node change marks the links into the linked repository it is in, and
/// nothing when it is in the top-level repository, even for a link whose
/// target has the top-level repository's id.
#[tokio::test]
async fn only_a_node_change_in_a_linked_repository_marks_links() {
    LORE_CONTEXT
        .scope(setup_test_execution(), async {
            let (immutable_store, mutable_store, _execution) =
                test_store_create().await.expect("making test stores");
            let top_level = RepositoryContext::new_null_context(immutable_store, mutable_store);
            let linked = top_level.to_link_context(RepositoryId::from([1; 16])).await;

            let tracker = LinkTracker::new();
            tracker.add_link(link(top_level.id, 10));
            tracker.add_link(link(linked.id, 20));

            tracker.on_node_changed(&top_level);
            assert!(
                !tracker.has_modifications(),
                "a change in the top-level repository marked a link"
            );

            tracker.on_node_changed(&linked);
            assert_eq!(
                tracker.get_links_needing_rehash(),
                vec![link(linked.id, 20)]
            );
        })
        .await;
}
