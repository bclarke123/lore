// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_revision::interface::LoreGlobalArgs;

pub fn address_with_random_context(address: lore_storage::Address) -> lore_storage::Address {
    lore_storage::Address {
        context: rand::random::<lore_storage::Context>(),
        hash: address.hash,
    }
}

pub fn setup_test_execution() -> std::sync::Arc<lore_revision::interface::ExecutionContext> {
    std::sync::Arc::new(lore_revision::interface::ExecutionContext::new_client(
        LoreGlobalArgs::default(),
        lore_revision::relay::EventDispatcher::no_dispatch(),
    ))
}
