// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::path::Path;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use lore_base::lore_spawn;
use smallvec::SmallVec;
use sysinfo::DiskRefreshKind;
use sysinfo::Disks;
use tokio::time::MissedTickBehavior;
use tracing::debug;
use tracing::info;
use tracing::warn;

use crate::settings::LocalStoreMonitorSettings;

/// Returns true when `path` starts with every component of `root`.
///
/// Compares whole components, so `/variable` does not start with `/var`, and
/// ignores ASCII case, so a case-insensitive volume given a differently cased
/// path still matches. A path a case-sensitive volume holds apart from its root
/// matches all the same, which costs a warning naming the wrong location and
/// never a missed one. A root with no components matches nothing, so an empty
/// temporary root or mount point does not claim every path.
#[lore_macro::test_pub]
fn starts_with_components(path: &Path, root: &Path) -> bool {
    if root.as_os_str().is_empty() {
        return false;
    }

    let mut path_components = path.components();

    for root_component in root.components() {
        let Some(component) = path_components.next() else {
            return false;
        };

        if !component
            .as_os_str()
            .eq_ignore_ascii_case(root_component.as_os_str())
        {
            return false;
        }
    }

    true
}

/// `path` with a Windows verbatim prefix replaced by the plain spelling.
///
/// Canonicalization returns `\\?\C:\dir` and `\\?\UNC\server\share`, where the
/// mount table and the configuration carry `C:\dir` and `\\server\share`. A
/// verbatim volume name has no plain spelling and is left as it stands.
#[lore_macro::test_pub]
fn plain_prefix(path: PathBuf) -> PathBuf {
    let plain = path.to_str().and_then(|text| {
        let rest = text.strip_prefix(r"\\?\")?;

        if let Some(share) = rest.strip_prefix(r"UNC\") {
            return Some(format!(r"\\{share}"));
        }

        let spelling = rest.as_bytes();

        (spelling.first().is_some_and(u8::is_ascii_alphabetic) && spelling.get(1) == Some(&b':'))
            .then(|| rest.to_owned())
    });

    plain.map_or(path, PathBuf::from)
}

/// `path` resolved against the filesystem, spelled as the mount table is.
#[lore_macro::test_pub]
fn real_location(path: &Path) -> Option<PathBuf> {
    path.canonicalize().ok().map(plain_prefix)
}

/// `path` with its deepest existing ancestor resolved and the remainder kept.
///
/// Settles `..` and symlinks the way the filesystem does, which no lexical pass
/// can: `/srv/../tmp` is `/tmp` only while `/srv` is not a symlink. The ancestor
/// resolves before the path itself exists, which is when a store is classified.
#[lore_macro::test_pub]
fn resolved_location(path: &Path) -> PathBuf {
    for ancestor in path.ancestors() {
        let Some(real) = real_location(ancestor) else {
            continue;
        };

        return real.join(path.strip_prefix(ancestor).unwrap_or(Path::new("")));
    }

    path.to_path_buf()
}

/// Each path alongside its real location, where the two differ.
///
/// A path that does not exist cannot be resolved, so a symlinked directory is
/// matched in both forms.
#[lore_macro::test_pub]
fn with_real_locations(paths: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
    let mut resolved = Vec::new();

    for path in paths {
        if let Some(real) = real_location(&path) {
            resolved.push(real);
        }
        resolved.push(path);
    }

    resolved.sort();
    resolved.dedup();
    resolved
}

/// The directories this platform hands out for temporary files.
///
/// On macOS the system temporary directory is a per-user path under
/// `/var/folders`, so the conventional Unix roots are carried too, each in both
/// forms because they are symlinks into `/private` there. Resolved once; they
/// do not move under a running server.
#[lore_macro::test_pub]
fn temporary_roots() -> &'static [PathBuf] {
    static ROOTS: OnceLock<Vec<PathBuf>> = OnceLock::new();

    ROOTS.get_or_init(|| {
        with_real_locations([
            std::env::temp_dir(),
            PathBuf::from("/tmp"),
            PathBuf::from("/var/tmp"),
        ])
    })
}

/// Returns true when `path` sits inside any of `roots`.
#[lore_macro::test_pub]
fn is_under_any(path: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|root| starts_with_components(path, root))
}

/// Returns true when `path` is a temporary location that does not survive a reboot.
pub fn is_temporary_path(path: &Path) -> bool {
    is_under_any(&resolved_location(path), temporary_roots())
}

/// A mounted filesystem and the local stores kept on it.
#[lore_macro::test_pub]
struct Volume<'a> {
    mount_point: &'a Path,
    available_bytes: u64,
    stores: SmallVec<[&'a Path; STORES_PER_CHECK]>,
}

/// Local store paths a server configures, past which the check spills onto the
/// heap.
const STORES_PER_CHECK: usize = 4;

/// The volumes one check found, and the stores on each.
#[lore_macro::test_pub]
type Volumes<'a> = SmallVec<[Volume<'a>; STORES_PER_CHECK]>;

/// Comma-separated paths, formatted only where the message is emitted.
#[lore_macro::test_pub]
struct PathList<'a>(&'a [&'a Path]);

impl std::fmt::Display for PathList<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, path) in self.0.iter().enumerate() {
            if index > 0 {
                formatter.write_str(", ")?;
            }

            write!(formatter, "{}", path.display())?;
        }

        Ok(())
    }
}

/// The mount backing `path`, from `mounts` as pairs of mount point and
/// available bytes.
///
/// The longest matching mount point wins, being the filesystem the path lives
/// on. `path` is matched as written, so the caller resolves it once rather than
/// once per mount.
#[lore_macro::test_pub]
fn mount_holding<'a>(
    path: &Path,
    mounts: impl Iterator<Item = (&'a Path, u64)>,
) -> Option<(&'a Path, u64)> {
    mounts
        .filter(|(mount_point, _)| starts_with_components(path, mount_point))
        .max_by_key(|(mount_point, _)| mount_point.components().count())
}

/// Records `store` on the volume mounted at `mount_point`, adding the volume
/// when it is the first store found there.
///
/// Free space is a property of the filesystem, not of the directory, so stores
/// sharing one volume are read and reported together rather than once each. One
/// filesystem mounted at two points is two volumes here: the mount point is the
/// only key sysinfo reports uniquely, device names repeating across
/// pseudo-filesystems.
#[lore_macro::test_pub]
fn add_store_to_volume<'a>(
    volumes: &mut Volumes<'a>,
    mount_point: &'a Path,
    available_bytes: u64,
    store: &'a Path,
) {
    match volumes
        .iter_mut()
        .find(|volume| volume.mount_point == mount_point)
    {
        Some(volume) => volume.stores.push(store),
        None => volumes.push(Volume {
            mount_point,
            available_bytes,
            stores: SmallVec::from_slice(&[store]),
        }),
    }
}

/// Warns when a volume holds less free space than the threshold.
fn report_volume(volume: &Volume<'_>, threshold_bytes: u64) {
    if volume.available_bytes >= threshold_bytes {
        debug!(
            mount_point = %volume.mount_point.display(),
            available_bytes = volume.available_bytes,
            "Local store disk space checked",
        );

        return;
    }

    warn!(
        mount_point = %volume.mount_point.display(),
        stores = %PathList(&volume.stores),
        available_bytes = volume.available_bytes,
        threshold_bytes,
        "The volume mounted at {} is running out of disk space. Free space has fallen to {} \
         bytes, below the configured threshold of {} bytes. Local stores held there: {}. Free \
         space or move the stores to a larger volume.",
        volume.mount_point.display(),
        volume.available_bytes,
        threshold_bytes,
        PathList(&volume.stores),
    );
}

/// The volumes holding `paths`, warning once per path no mount matches.
///
/// `mounts` yields the mount table afresh for each path, the caller holding it.
/// Each path is placed on the volume backing it, so several stores on one
/// filesystem draw one reading.
///
/// An unreadable path warns rather than passing quietly, so a monitor taking no
/// reading is not mistaken for one reporting all clear. It warns once per spell,
/// `warned_unreadable` holding one flag per entry in `paths`, so a mount table
/// that keeps a path unmatched is reported once and a path that comes back and
/// goes again is reported anew. A lost reading never stops the remaining paths
/// from being checked.
#[lore_macro::test_pub]
fn volumes_holding<'a, M, I>(
    paths: &'a [PathBuf],
    mounts: M,
    warned_unreadable: &mut [bool],
) -> Volumes<'a>
where
    M: Fn() -> I,
    I: Iterator<Item = (&'a Path, u64)>,
{
    let mut volumes = Volumes::new();

    for (path, warned) in paths.iter().zip(warned_unreadable.iter_mut()) {
        let resolved = resolved_location(path);

        match mount_holding(&resolved, mounts()) {
            Some((mount_point, available_bytes)) => {
                *warned = false;
                add_store_to_volume(&mut volumes, mount_point, available_bytes, path);
            }
            None if !*warned => {
                *warned = true;
                warn!(
                    path = %path.display(),
                    "Cannot check the disk space available to the local store at {}: no mounted \
                     filesystem matches that path. Free space is going unmonitored.",
                    path.display(),
                );
            }
            None => {}
        }
    }

    volumes
}

/// Warns for every volume below the threshold.
///
/// Only the space figures are refreshed. Device kind and per-disk I/O counters
/// cost syscalls the check has no use for.
fn check_available_space(
    disks: &mut Disks,
    paths: &[PathBuf],
    threshold_bytes: u64,
    warned_unreadable: &mut [bool],
) {
    disks.refresh_specifics(true, DiskRefreshKind::nothing().with_storage());

    let volumes = volumes_holding(
        paths,
        || {
            disks
                .list()
                .iter()
                .map(|disk| (disk.mount_point(), disk.available_space()))
        },
        warned_unreadable,
    );

    for volume in &volumes {
        report_volume(volume, threshold_bytes);
    }
}

/// Starts periodic monitoring of the disk space available to the local stores.
///
/// The first tick fires immediately, so a server starting on a full volume says
/// so at once. Duplicate paths are collapsed, stores sharing a volume are
/// checked once, and a `check_interval_seconds` of zero turns monitoring off.
/// One mount table is kept for the server's life and refreshed in place.
pub fn start_local_store_monitor(mut paths: Vec<PathBuf>, settings: &LocalStoreMonitorSettings) {
    paths.sort();
    paths.dedup();

    if paths.is_empty() {
        return;
    }

    if settings.check_interval_seconds == 0 {
        info!("Local store disk space monitoring is disabled by configuration");
        return;
    }

    let threshold_bytes = settings.low_space_threshold_bytes;
    let interval = Duration::from_secs(settings.check_interval_seconds);

    lore_spawn!(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut warned_unreadable = vec![false; paths.len()];
        let mut disks = Disks::new();

        loop {
            ticker.tick().await;
            check_available_space(&mut disks, &paths, threshold_bytes, &mut warned_unreadable);
        }
    });
}
