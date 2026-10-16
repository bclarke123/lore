// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_storage::local::immutable_store::info::*;
use zerocopy::IntoBytes;

const INFO_SIZE: usize = size_of::<ImmutableStoreInfo>();

fn info_at(next_group_index_to_migrate_oodle: i32) -> ImmutableStoreInfo {
    ImmutableStoreInfo {
        next_group_index_to_migrate_oodle,
        ..Default::default()
    }
}

/// Bytes of a valid info file, with `corrupt` applied before they are written.
fn corrupted_bytes(corrupt: impl FnOnce(&mut [u8; INFO_SIZE])) -> [u8; INFO_SIZE] {
    let mut bytes = [0u8; INFO_SIZE];
    bytes.copy_from_slice(info_at(7).as_bytes());
    corrupt(&mut bytes);
    bytes
}

mod read_info_file {
    use super::*;

    #[tokio::test]
    async fn an_absent_file_reads_as_no_info() {
        let dir = lore_base::test_util::TempDir::new("is_info_absent_");
        let info = read_info_file(&info_path_for_store_root(dir.path()))
            .await
            .expect("an absent info file is not a failure");
        assert!(info.is_none());
    }

    #[tokio::test]
    async fn a_written_file_reads_back_unchanged() {
        let dir = lore_base::test_util::TempDir::new("is_info_round_trip_");
        let path = info_path_for_store_root(dir.path());

        write_info_file(&info_at(42), &path)
            .await
            .expect("info file writes");

        let info = read_info_file(&path)
            .await
            .expect("info file reads")
            .expect("info file is present");
        assert_eq!(info.next_group_index_to_migrate_oodle, 42);
        assert_eq!(info.magic, INFO_MAGIC);
        assert_eq!(info.version, ImmutableStoreInfoVersion::Initial as u32);
    }

    #[tokio::test]
    async fn a_truncated_file_is_rejected() {
        let dir = lore_base::test_util::TempDir::new("is_info_short_");
        let path = info_path_for_store_root(dir.path());
        std::fs::write(&path, &corrupted_bytes(|_| {})[..INFO_SIZE - 1])
            .expect("short file writes");

        let err = read_info_file(&path)
            .await
            .expect_err("a file too short to hold the header is rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn a_foreign_magic_is_rejected() {
        let dir = lore_base::test_util::TempDir::new("is_info_magic_");
        let path = info_path_for_store_root(dir.path());
        let bytes = corrupted_bytes(|bytes| bytes[..4].copy_from_slice(b"XXXX"));
        std::fs::write(&path, bytes).expect("file writes");

        let err = read_info_file(&path)
            .await
            .expect_err("a file that is not an info file is rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn an_unsupported_version_is_rejected() {
        let dir = lore_base::test_util::TempDir::new("is_info_version_");
        let path = info_path_for_store_root(dir.path());
        let unsupported = ImmutableStoreInfoVersion::Initial as u32 + 1;
        let bytes =
            corrupted_bytes(|bytes| bytes[4..8].copy_from_slice(&unsupported.to_ne_bytes()));
        std::fs::write(&path, bytes).expect("file writes");

        let err = read_info_file(&path)
            .await
            .expect_err("a layout this binary cannot parse is rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}

mod write_info_file {
    use super::*;

    #[tokio::test]
    async fn a_rewrite_leaves_no_trailing_bytes_of_the_previous_file() {
        let dir = lore_base::test_util::TempDir::new("is_info_rewrite_");
        let path = info_path_for_store_root(dir.path());
        std::fs::write(&path, [0xAB; INFO_SIZE * 4]).expect("oversized file writes");

        write_info_file(&info_at(3), &path)
            .await
            .expect("info file writes");

        assert_eq!(
            std::fs::metadata(&path).expect("info file exists").len(),
            INFO_SIZE as u64
        );
        assert!(
            !path.with_extension("tmp").exists(),
            "the file the atomic write renames from must not outlive it"
        );
        let info = read_info_file(&path)
            .await
            .expect("info file reads")
            .expect("info file is present");
        assert_eq!(info.next_group_index_to_migrate_oodle, 3);
    }
}

/// The on-disk layout, which `#[repr(C)]` is what fixes. A field moving would put something
/// other than the magic at offset 0, and every info file already written would stop parsing.
#[test]
fn the_magic_leads_the_serialized_form() {
    let info = info_at(7);
    let bytes = info.as_bytes();
    assert_eq!(bytes.len(), INFO_SIZE);
    assert_eq!(bytes[..4], INFO_MAGIC.to_ne_bytes());
    assert_eq!(
        bytes[8..12],
        7i32.to_ne_bytes(),
        "the resume index trails the magic and version"
    );
}

mod get_or_init_disk_info {
    use super::*;

    #[tokio::test]
    async fn a_store_with_no_info_file_records_the_seed() {
        let dir = lore_base::test_util::TempDir::new("is_info_init_seed_");
        let info = get_or_init_disk_info(dir.path(), 17)
            .await
            .expect("info file initialises");
        assert_eq!(info.next_group_index_to_migrate_oodle, 17);

        let on_disk = read_info_file(&info_path_for_store_root(dir.path()))
            .await
            .expect("info file reads")
            .expect("the seed was persisted, not just returned");
        assert_eq!(on_disk.next_group_index_to_migrate_oodle, 17);
    }

    /// A store with no written group has nothing to migrate, and the seed says so.
    #[tokio::test]
    async fn a_seed_of_minus_one_leaves_nothing_to_migrate() {
        let dir = lore_base::test_util::TempDir::new("is_info_init_empty_");
        let info = get_or_init_disk_info(dir.path(), -1)
            .await
            .expect("info file initialises");
        assert_eq!(info.next_group_index_to_migrate_oodle, -1);
    }

    /// The seed describes the store as it was first seen. Once progress is on disk it is
    /// authoritative, or a pass would restart from the top on every open.
    #[tokio::test]
    async fn an_existing_file_wins_over_the_seed() {
        let dir = lore_base::test_util::TempDir::new("is_info_init_existing_");
        write_info_file(&info_at(5), &info_path_for_store_root(dir.path()))
            .await
            .expect("info file writes");

        let info = get_or_init_disk_info(dir.path(), 200)
            .await
            .expect("info file loads");
        assert_eq!(info.next_group_index_to_migrate_oodle, 5);
    }

    #[tokio::test]
    async fn a_corrupt_file_is_reported_rather_than_replaced() {
        let dir = lore_base::test_util::TempDir::new("is_info_init_corrupt_");
        let path = info_path_for_store_root(dir.path());
        let bytes = corrupted_bytes(|bytes| bytes[..4].copy_from_slice(b"XXXX"));
        std::fs::write(&path, bytes).expect("file writes");

        let err = get_or_init_disk_info(dir.path(), 9)
            .await
            .expect_err("a corrupt info file is not silently overwritten");
        assert!(err.is_internal());

        let after = std::fs::read(&path).expect("info file still exists");
        assert_eq!(&after[..4], b"XXXX", "the corrupt file was left in place");
    }
}
