// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use async_trait::async_trait;
use lore_base::types::Address;
use lore_base::types::Hash;
use lore_base::types::LockResource;
use lore_revision::lore::BranchId;
use lore_revision::lore::RepositoryId;
use lore_revision::notification::NotificationError;
use lore_revision::notification::NotificationSender;

mockall::mock! {
    pub NotificationSender {}

    #[async_trait]
    impl NotificationSender for NotificationSender {

        async fn branch_created(
            &self,
            repository: RepositoryId,
            branch: BranchId,
        );

        async fn branch_pushed(
            &self,
            repository: RepositoryId,
            branch: BranchId,
            user_id: &str,
            revision: Hash,
            revision_number: u64,
        );

        async fn branch_deleted(
            &self,
            repository: RepositoryId,
            branch: BranchId,
        );

        async fn resource_locked(
            &self,
            repository: RepositoryId,
            branch: BranchId,
            user_id: &str,
            resources: &[LockResource],
        );

        async fn resource_unlocked(
            &self,
            repository: RepositoryId,
            branch: BranchId,
            user_id: &str,
            resources: &[LockResource],
        );

        async fn obliterate(
            &self,
            repository: RepositoryId,
            address: Address,
        ) -> Result<(), NotificationError>;

        #[allow(clippy::too_many_arguments)]
        async fn compliance_check(
            &self,
            stream_name: &str,
            repository: RepositoryId,
            branch: BranchId,
            user_id: &str,
            revision: Hash,
            revision_number: u64,
            ip_addr: Option<String>,
        );
    }
}
