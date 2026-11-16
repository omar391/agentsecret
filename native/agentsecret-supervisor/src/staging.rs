//! Race-resistant copying of explicitly granted host files into a fresh guest workspace.
//!
//! The caller must supply the trusted host project root out of band. This module
//! never accepts a caller-selected root and never follows a symlink in a granted
//! file path. Read-only mode is represented in the returned manifest and by
//! restrictive staged permissions; the VM backend must still enforce read-only
//! access at the mount or virtual-filesystem boundary.

use crate::{FileMode, ValidatedRunPlan};
use rustix::fs::{Mode, OFlags, fstat, mkdir, open, openat};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

const DEFAULT_PER_FILE_LIMIT: u64 = 64 * 1024 * 1024;
const DEFAULT_TOTAL_LIMIT: u64 = 128 * 1024 * 1024;

/// Static failure codes. They intentionally exclude host paths and file contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StagingError {
    InvalidWorkspace,
    DestinationAlreadyExists,
    SourceOutsideWorkspace,
    UnsafeSource,
    FileTooLarge,
    TotalTooLarge,
    Io,
}

impl std::fmt::Display for StagingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidWorkspace => "run_workspace_invalid",
            Self::DestinationAlreadyExists => "run_workspace_exists",
            Self::SourceOutsideWorkspace => "run_file_outside_workspace",
            Self::UnsafeSource => "run_file_unsafe",
            Self::FileTooLarge => "run_file_too_large",
            Self::TotalTooLarge => "run_files_total_too_large",
            Self::Io => "run_file_staging_failed",
        })
    }
}

impl std::error::Error for StagingError {}

/// File copied into the isolated guest workspace and its requested access mode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedFile {
    pub guest_path: String,
    pub mode: FileMode,
    pub byte_length: u64,
}

/// Create a private, fresh workspace and copy only declared regular files.
///
/// `trusted_host_root` is selected by the trusted launcher, not read from the
/// request. `destination` must not already exist. File paths are opened relative
/// to a pinned root descriptor with `O_NOFOLLOW` on every component, preventing
/// symlink replacement from redirecting a later copy outside that root.
///
/// The default bounds are 64 MiB per file and 128 MiB total. The destination is
/// removed if any copy fails. The returned manifest must be consumed by a
/// backend that enforces each mode; chmod alone is not a VM security boundary.
pub fn stage_declared_files(
    plan: &ValidatedRunPlan,
    trusted_host_root: &Path,
    destination: &Path,
) -> Result<Vec<StagedFile>, StagingError> {
    stage_declared_files_with_limits(
        plan,
        trusted_host_root,
        destination,
        DEFAULT_PER_FILE_LIMIT,
        DEFAULT_TOTAL_LIMIT,
    )
}

/// Testable variant with explicit byte bounds.
pub fn stage_declared_files_with_limits(
    plan: &ValidatedRunPlan,
    trusted_host_root: &Path,
    destination: &Path,
    per_file_limit: u64,
    total_limit: u64,
) -> Result<Vec<StagedFile>, StagingError> {
    let host_root =
        fs::canonicalize(trusted_host_root).map_err(|_| StagingError::InvalidWorkspace)?;
    if !host_root.is_dir() || !destination.is_absolute() {
        return Err(StagingError::InvalidWorkspace);
    }

    let root_fd = open(
        &host_root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| StagingError::InvalidWorkspace)?;

    if let Err(error) = mkdir(destination, Mode::from_bits_truncate(0o700)) {
        return Err(if error == rustix::io::Errno::EXIST {
            StagingError::DestinationAlreadyExists
        } else {
            StagingError::Io
        });
    }
    let mut cleanup = RemoveWorkspace(destination.to_path_buf());

    let mut total = 0u64;
    let mut staged = Vec::with_capacity(plan.file_access.len());
    for access in &plan.file_access {
        // Match against the trusted root spelling because /tmp and /private/tmp
        // are distinct lexical paths on macOS. The resulting relative path is
        // opened beneath the already-pinned canonical root descriptor below.
        let relative = Path::new(&access.host_path)
            .strip_prefix(trusted_host_root)
            .map_err(|_| StagingError::SourceOutsideWorkspace)?;
        if relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(StagingError::SourceOutsideWorkspace);
        }

        let mut source = open_regular_file_beneath(&root_fd, relative)?;
        let before = source.metadata().map_err(|_| StagingError::Io)?;
        if !before.is_file() || before.nlink() != 1 || before.len() > per_file_limit {
            return Err(if before.len() > per_file_limit {
                StagingError::FileTooLarge
            } else {
                StagingError::UnsafeSource
            });
        }
        let total_with_snapshot = total
            .checked_add(before.len())
            .filter(|size| *size <= total_limit)
            .ok_or(StagingError::TotalTooLarge)?;

        let guest_relative = Path::new(access.guest_path.as_str())
            .strip_prefix("/workspace")
            .map_err(|_| StagingError::UnsafeSource)?;
        if guest_relative.as_os_str().is_empty()
            || guest_relative
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(StagingError::UnsafeSource);
        }
        let output = destination.join(guest_relative);
        let parent = output.parent().ok_or(StagingError::UnsafeSource)?;
        fs::create_dir_all(parent).map_err(|_| StagingError::Io)?;

        let mut target = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&output)
            .map_err(|_| StagingError::Io)?;
        let copied = {
            let mut bounded_source = (&mut source).take(per_file_limit.saturating_add(1));
            io::copy(&mut bounded_source, &mut target).map_err(|_| StagingError::Io)?
        };
        if copied != before.len() || copied > per_file_limit {
            return Err(StagingError::FileTooLarge);
        }
        total = total_with_snapshot - before.len() + copied;
        if total > total_limit {
            return Err(StagingError::TotalTooLarge);
        }
        target.flush().map_err(|_| StagingError::Io)?;
        target
            .set_permissions(fs::Permissions::from_mode(match access.mode {
                FileMode::ReadOnly => 0o400,
                FileMode::ReadWrite => 0o600,
            }))
            .map_err(|_| StagingError::Io)?;

        let after = source.metadata().map_err(|_| StagingError::Io)?;
        if !same_open_file(&before, &after) {
            return Err(StagingError::UnsafeSource);
        }
        staged.push(StagedFile {
            guest_path: access.guest_path.as_str().to_owned(),
            mode: access.mode,
            byte_length: copied,
        });
    }

    cleanup.0 = PathBuf::new();
    Ok(staged)
}

fn open_regular_file_beneath(root: &OwnedFd, relative: &Path) -> Result<File, StagingError> {
    let root_device = fstat(root).map_err(|_| StagingError::UnsafeSource)?.st_dev;
    let components: Vec<_> = relative.components().collect();
    let Some((last, parents)) = components.split_last() else {
        return Err(StagingError::UnsafeSource);
    };
    let mut opened_directories: Vec<OwnedFd> = Vec::with_capacity(parents.len());
    for component in parents {
        let Component::Normal(name) = component else {
            return Err(StagingError::UnsafeSource);
        };
        let parent = opened_directories
            .last()
            .map(AsFd::as_fd)
            .unwrap_or_else(|| root.as_fd());
        let fd = openat(
            parent,
            *name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| StagingError::UnsafeSource)?;
        if fstat(&fd).map_err(|_| StagingError::UnsafeSource)?.st_dev != root_device {
            return Err(StagingError::UnsafeSource);
        }
        opened_directories.push(fd);
    }
    let Component::Normal(name) = last else {
        return Err(StagingError::UnsafeSource);
    };
    let parent = opened_directories
        .last()
        .map(AsFd::as_fd)
        .unwrap_or_else(|| root.as_fd());
    let fd = openat(
        parent,
        *name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| StagingError::UnsafeSource)?;
    if fstat(&fd).map_err(|_| StagingError::UnsafeSource)?.st_dev != root_device {
        return Err(StagingError::UnsafeSource);
    }
    Ok(File::from(fd))
}

fn same_open_file(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.nlink() == 1
        && after.nlink() == 1
        && before.len() == after.len()
        && before.modified().ok() == after.modified().ok()
}

struct RemoveWorkspace(PathBuf);

impl Drop for RemoveWorkspace {
    fn drop(&mut self) {
        if !self.0.as_os_str().is_empty() {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_run_request;
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("agentsecret-stage-{}-{id}", std::process::id()));
            fs::create_dir(&path).expect("create isolated test directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn plan(host_path: &Path, guest_path: &str, mode: &str) -> ValidatedRunPlan {
        let request = json!({
            "version": 1,
            "executable": "/usr/bin/cat",
            "argv": [],
            "working_directory": "/workspace",
            "file_access": [{
                "host_path": host_path,
                "guest_path": guest_path,
                "mode": mode
            }]
        });
        parse_run_request(request.to_string().as_bytes()).expect("valid run request")
    }

    #[test]
    fn stages_only_the_declared_file_with_restricted_permissions() {
        let temp = TestDir::new();
        let root = temp.path().join("project");
        fs::create_dir(&root).unwrap();
        let source = root.join("config.json");
        fs::write(&source, b"synthetic-config").unwrap();
        let destination = temp.path().join("guest-workspace");
        let run = plan(&source, "/workspace/project/config.json", "read_only");

        let files = stage_declared_files(&run, &root, &destination).unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].byte_length, 16);
        assert_eq!(files[0].mode, FileMode::ReadOnly);
        assert_eq!(
            fs::read(destination.join("project/config.json")).unwrap(),
            b"synthetic-config"
        );
        assert_eq!(
            fs::metadata(destination.join("project/config.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o400
        );
    }

    #[test]
    fn rejects_symlink_components_and_cleans_partial_workspace() {
        let temp = TestDir::new();
        let root = temp.path().join("project");
        let outside = temp.path().join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("credential.txt"), b"synthetic-secret").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("linked-dir")).unwrap();
        std::os::unix::fs::symlink(outside.join("credential.txt"), root.join("linked-file.txt"))
            .unwrap();

        for (index, relative) in ["linked-dir/credential.txt", "linked-file.txt"]
            .into_iter()
            .enumerate()
        {
            let destination = temp.path().join(format!("guest-workspace-{index}"));
            let run = plan(
                &root.join(relative),
                "/workspace/credential.txt",
                "read_only",
            );
            assert_eq!(
                stage_declared_files(&run, &root, &destination),
                Err(StagingError::UnsafeSource)
            );
            assert!(!destination.exists());
        }
    }

    #[test]
    fn refuses_sources_outside_root_hardlinks_and_existing_destinations() {
        let temp = TestDir::new();
        let root = temp.path().join("project");
        fs::create_dir(&root).unwrap();
        let outside = temp.path().join("outside.txt");
        fs::write(&outside, b"synthetic-secret").unwrap();
        let outside_plan = plan(&outside, "/workspace/file", "read_only");
        let destination = temp.path().join("outside-stage");
        assert_eq!(
            stage_declared_files(&outside_plan, &root, &destination),
            Err(StagingError::SourceOutsideWorkspace)
        );

        let source = root.join("source.txt");
        fs::write(&source, b"synthetic").unwrap();
        fs::hard_link(&source, root.join("alias.txt")).unwrap();
        let hardlink_plan = plan(&source, "/workspace/file", "read_only");
        assert_eq!(
            stage_declared_files(&hardlink_plan, &root, &temp.path().join("hardlink-stage")),
            Err(StagingError::UnsafeSource)
        );

        let existing = temp.path().join("existing");
        fs::create_dir(&existing).unwrap();
        assert_eq!(
            stage_declared_files(
                &plan(&source, "/workspace/file", "read_only"),
                &root,
                &existing
            ),
            Err(StagingError::DestinationAlreadyExists)
        );
    }

    #[test]
    fn enforces_per_file_and_total_byte_limits() {
        let temp = TestDir::new();
        let root = temp.path().join("project");
        fs::create_dir(&root).unwrap();
        let source = root.join("large.txt");
        fs::write(&source, b"0123456789").unwrap();
        let run = plan(&source, "/workspace/file", "read_write");

        assert_eq!(
            stage_declared_files_with_limits(
                &run,
                &root,
                &temp.path().join("per-file-limit"),
                9,
                20
            ),
            Err(StagingError::FileTooLarge)
        );
        assert_eq!(
            stage_declared_files_with_limits(&run, &root, &temp.path().join("total-limit"), 20, 9),
            Err(StagingError::TotalTooLarge)
        );
    }
}
