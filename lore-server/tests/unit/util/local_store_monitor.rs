// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::path::Path;
use std::path::PathBuf;

use lore_server::util::local_store_monitor::*;

fn mount_for<'a>(path: &str, mounts: &'a [(&'a str, u64)]) -> Option<(&'a Path, u64)> {
    mount_holding(
        Path::new(path),
        mounts
            .iter()
            .map(|(mount_point, available_bytes)| (Path::new(*mount_point), *available_bytes)),
    )
}

fn space_for(path: &str, mounts: &[(&str, u64)]) -> Option<u64> {
    mount_for(path, mounts).map(|(_, available_bytes)| available_bytes)
}

/// The volumes `paths` land on, as mount point and the stores held there.
fn volumes_for<'a>(
    paths: &'a [&'a str],
    mounts: &'a [(&'a str, u64)],
) -> Vec<(&'a Path, Vec<&'a Path>)> {
    let mut volumes = Volumes::new();

    for path in paths {
        if let Some((mount_point, available_bytes)) = mount_for(path, mounts) {
            add_store_to_volume(&mut volumes, mount_point, available_bytes, Path::new(*path));
        }
    }

    volumes
        .into_iter()
        .map(|volume| (volume.mount_point, volume.stores.into_vec()))
        .collect()
}

#[test]
fn a_path_under_a_root_is_under_it() {
    let roots = vec![PathBuf::from("/tmp"), PathBuf::from("/var/tmp")];

    assert!(is_under_any(Path::new("/tmp/lore-server"), &roots));
    assert!(is_under_any(Path::new("/var/tmp/lore-server"), &roots));
}

#[test]
fn a_root_is_under_itself() {
    let roots = vec![PathBuf::from("/tmp")];

    assert!(is_under_any(Path::new("/tmp"), &roots));
}

#[test]
fn a_path_outside_every_root_is_not_under_any() {
    let roots = vec![PathBuf::from("/tmp"), PathBuf::from("/var/tmp")];

    assert!(!is_under_any(Path::new("/srv/lore/store"), &roots));
}

#[test]
fn a_root_matches_only_on_whole_components() {
    let roots = vec![PathBuf::from("/var")];

    assert!(!is_under_any(Path::new("/variable/lore-server"), &roots));
}

/// Forward slashes so the components split alike on every platform.
#[test]
fn a_differently_cased_root_matches() {
    assert!(starts_with_components(
        Path::new("/Users/u/appdata/local/temp/lore-server"),
        Path::new("/Users/u/AppData/Local/Temp"),
    ));
}

#[test]
fn ignoring_case_still_matches_only_whole_components() {
    assert!(!starts_with_components(
        Path::new("/VARIABLE/lore-server"),
        Path::new("/var"),
    ));
}

#[test]
fn a_root_longer_than_the_path_does_not_match() {
    assert!(!starts_with_components(
        Path::new("/tmp"),
        Path::new("/tmp/lore-server"),
    ));
}

/// Mirrors macOS, where a store at `/tmp` is caught only by the
/// conventional roots.
#[test]
fn a_per_user_temp_dir_does_not_hide_the_conventional_roots() {
    let roots = vec![
        PathBuf::from("/var/folders/ab/cd1234/T"),
        PathBuf::from("/tmp"),
        PathBuf::from("/var/tmp"),
    ];

    assert!(is_under_any(Path::new("/tmp/lore-server"), &roots));
    assert!(is_under_any(
        Path::new("/var/folders/ab/cd1234/T/lore-server"),
        &roots
    ));
}

#[test]
fn temporary_roots_carry_the_system_temp_dir() {
    assert!(temporary_roots().contains(&std::env::temp_dir()));
}

/// Mirrors macOS, where `/tmp` and `/var` are symlinks into `/private`.
#[cfg(unix)]
#[test]
fn a_symlinked_root_is_carried_in_both_forms() {
    let dir = lore_base::test_util::TempDir::new("local-store-monitor-symlink-");
    let target = dir.child("target");
    let link = dir.child("link");
    std::fs::create_dir(&target).expect("create target directory");
    std::os::unix::fs::symlink(&target, &link).expect("create symlink");

    let roots = with_real_locations([link.clone()]);

    assert!(roots.contains(&link));
    assert!(roots.contains(&target.canonicalize().expect("resolve target")));
}

#[cfg(unix)]
#[test]
fn a_path_under_a_symlinked_root_is_matched_before_it_exists() {
    let dir = lore_base::test_util::TempDir::new("local-store-monitor-unborn-");
    let target = dir.child("target");
    let link = dir.child("link");
    std::fs::create_dir(&target).expect("create target directory");
    std::os::unix::fs::symlink(&target, &link).expect("create symlink");

    let roots = with_real_locations([link]);
    let store = target
        .canonicalize()
        .expect("resolve target")
        .join("lore-server");

    assert!(!store.exists());
    assert!(is_under_any(&store, &roots));
}

#[test]
fn a_directory_in_the_system_temp_dir_is_temporary() {
    let dir = lore_base::test_util::TempDir::new("local-store-monitor-temporary-");

    assert!(is_temporary_path(dir.path()));
}

#[test]
fn a_persistent_path_is_not_temporary() {
    assert!(!is_temporary_path(Path::new("/srv/lore/store")));
}

/// A lexical prefix says nothing once `..` is involved.
#[test]
fn a_parent_component_leading_out_of_the_temp_dir_is_not_temporary() {
    assert!(!is_temporary_path(&std::env::temp_dir().join("..")));
}

#[test]
fn a_parent_component_is_settled_against_the_filesystem() {
    let dir = lore_base::test_util::TempDir::new("local-store-monitor-parent-");
    let inside = dir.child("inside");
    std::fs::create_dir(&inside).expect("create directory");

    let through_parent = inside.join("..").join("inside").join("store");
    let settled = real_location(&inside)
        .expect("resolve directory")
        .join("store");

    assert!(!through_parent.exists());
    assert_eq!(resolved_location(&through_parent), settled);
}

#[test]
fn space_comes_from_the_only_matching_mount() {
    assert_eq!(space_for("/srv/lore", &[("/", 100)]), Some(100));
}

#[test]
fn the_longest_matching_mount_point_wins() {
    assert_eq!(
        space_for("/var/tmp/lore", &[("/", 100), ("/var", 50)]),
        Some(50)
    );
}

#[test]
fn the_longest_matching_mount_point_wins_whatever_the_order() {
    assert_eq!(
        space_for("/var/tmp/lore", &[("/var", 50), ("/", 100)]),
        Some(50)
    );
}

#[test]
fn a_mount_point_equal_to_the_path_matches() {
    assert_eq!(space_for("/data", &[("/data", 50)]), Some(50));
}

#[test]
fn a_textual_prefix_is_not_a_matching_mount() {
    assert_eq!(space_for("/variable/lore", &[("/var", 50)]), None);
}

#[test]
fn a_path_on_no_known_mount_has_no_reading() {
    assert_eq!(space_for("/srv/lore", &[("/data", 50)]), None);
}

#[test]
fn the_volume_is_the_longest_matching_mount_point() {
    assert_eq!(
        mount_for("/var/tmp/lore", &[("/", 100), ("/var", 50)]),
        Some((Path::new("/var"), 50))
    );
}

/// One reading covers the filesystem, so two stores on it are one entry.
#[test]
fn two_stores_on_one_volume_are_checked_once() {
    assert_eq!(
        volumes_for(
            &["/data/immutable", "/data/mutable"],
            &[("/", 100), ("/data", 50)]
        ),
        vec![(
            Path::new("/data"),
            vec![Path::new("/data/immutable"), Path::new("/data/mutable")]
        )]
    );
}

#[test]
fn stores_on_separate_volumes_are_checked_apart() {
    assert_eq!(
        volumes_for(
            &["/data/immutable", "/srv/mutable"],
            &[("/", 100), ("/data", 50)]
        ),
        vec![
            (Path::new("/data"), vec![Path::new("/data/immutable")]),
            (Path::new("/"), vec![Path::new("/srv/mutable")]),
        ]
    );
}

/// A repeated path joins the volume rather than opening a second one.
/// `start_local_store_monitor` drops duplicates before the check runs.
#[test]
fn a_repeated_path_joins_the_volume_it_already_sits_on() {
    assert_eq!(
        volumes_for(&["/data/store", "/data/store"], &[("/data", 50)]),
        vec![(
            Path::new("/data"),
            vec![Path::new("/data/store"), Path::new("/data/store")]
        )]
    );
}

#[test]
fn a_store_on_no_known_mount_lands_on_no_volume() {
    assert!(volumes_for(&["/srv/lore"], &[("/data", 50)]).is_empty());
}

#[test]
fn a_path_list_separates_paths_with_commas() {
    let paths = [Path::new("/data/immutable"), Path::new("/data/mutable")];

    assert_eq!(
        PathList(&paths).to_string(),
        "/data/immutable, /data/mutable"
    );
}

/// `TMPDIR=""` makes `std::env::temp_dir()` empty, and a root that matched
/// every path would report every store as ephemeral.
#[test]
fn an_empty_root_matches_nothing() {
    assert!(!starts_with_components(
        Path::new("/srv/lore/store"),
        Path::new(""),
    ));
    assert!(!is_under_any(
        Path::new("/srv/lore/store"),
        &[PathBuf::new()]
    ));
}

#[test]
fn an_empty_mount_point_holds_nothing() {
    assert_eq!(space_for("/srv/lore", &[("", 50)]), None);
}

fn plainly(path: &str) -> PathBuf {
    plain_prefix(PathBuf::from(path))
}

/// Windows canonicalization spells a drive verbatim, the mount table does
/// not, and a store on a drive matches no mount until the two agree.
#[test]
fn a_verbatim_disk_is_spelled_as_the_mount_table_spells_it() {
    assert_eq!(
        plainly(r"\\?\C:\lore\store"),
        PathBuf::from(r"C:\lore\store")
    );
}

#[test]
fn a_verbatim_share_is_spelled_as_the_mount_table_spells_it() {
    assert_eq!(
        plainly(r"\\?\UNC\server\share\store"),
        PathBuf::from(r"\\server\share\store")
    );
}

/// A volume name has no plain spelling to fall back on.
#[test]
fn a_verbatim_volume_name_stands() {
    let volume = r"\\?\Volume{b75e2c83-0000-0000-0000-602f00000000}\store";

    assert_eq!(plainly(volume), PathBuf::from(volume));
}

#[test]
fn a_path_carrying_no_verbatim_prefix_stands() {
    assert_eq!(plainly("/srv/lore/store"), PathBuf::from("/srv/lore/store"));
}

/// A directory that exists, so `resolved_location` settles the store paths
/// under a mount point the test names, whatever the platform spells one.
///
/// Read through [`real_location`], which is how the check spells a path it
/// resolves: `canonicalize` alone answers a verbatim path on Windows, and a
/// mount point spelled that way matches none of the stores under it.
fn mount_root(prefix: &str) -> (lore_base::test_util::TempDir, PathBuf) {
    let dir = lore_base::test_util::TempDir::new(prefix);
    let root = real_location(dir.path()).expect("resolve temporary directory");

    (dir, root)
}

fn check(root: &Path, paths: &[PathBuf], mounted: bool, warned: &mut [bool]) -> Vec<Vec<PathBuf>> {
    let mount = [(root, 50u64)];
    let mounts = if mounted { &mount[..] } else { &[][..] };

    volumes_holding(paths, || mounts.iter().copied(), warned)
        .into_iter()
        .map(|volume| volume.stores.iter().map(PathBuf::from).collect())
        .collect()
}

#[test]
fn stores_under_one_mount_share_a_volume() {
    let (_dir, root) = mount_root("local-store-monitor-one-volume-");
    let paths = [root.join("one"), root.join("two")];

    assert_eq!(
        check(&root, &paths, true, &mut [false, false]),
        vec![paths.to_vec()]
    );
}

#[test]
fn a_path_no_mount_matches_yields_no_volume() {
    let (_dir, root) = mount_root("local-store-monitor-no-mount-");
    let paths = [root.join("one")];

    assert!(check(&root, &paths, false, &mut [false]).is_empty());
}

/// The flag holds the warning back for as long as the condition lasts, and
/// a reading releases it so the next spell is reported afresh.
#[test]
fn an_unreadable_path_warns_once_per_spell() {
    let (_dir, root) = mount_root("local-store-monitor-spell-");
    let paths = [root.join("one")];
    let mut warned = [false];

    check(&root, &paths, false, &mut warned);
    assert_eq!(warned, [true]);

    check(&root, &paths, false, &mut warned);
    assert_eq!(warned, [true]);

    check(&root, &paths, true, &mut warned);
    assert_eq!(warned, [false]);

    check(&root, &paths, false, &mut warned);
    assert_eq!(warned, [true]);
}
