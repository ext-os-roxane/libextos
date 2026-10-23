//! Per-container rootfs assembly (PLAN 4.4.7).
//!
//! # Reuse, and where it stops
//!
//! The rootfs is built from the **weaver's own plan types**: [`CasRef`],
//! [`VfsPlan`], [`PlanEntry`](crate::weaver::plan::PlanEntry) and
//! [`PlanOp`], produced by the pure planner
//! [`plan_from_refs_with`]. That gives containers the same dependency
//! resolution, collision escalation and Tier-3 wrappers as the host weave — the
//! container is simply a *different target root*.
//!
//! What this module deliberately does **not** do is call
//! [`crate::weaver::execute_plan`]. Two reasons, both honesty-driven:
//!
//! 1. `execute_plan` materialises regular files with the planned link strategy.
//!    `Reflink`/`Hardlink` would share inodes with the CAS, so a writable
//!    container (levels 3/4) could corrupt the read-only store. Containers
//!    therefore get **copies** with the source mode preserved.
//! 2. A container root needs things a host weave does not (`/proc`, `/sys`,
//!    `/dev`, `/tmp`, a seeded `/etc`), and needs them *inside* the staged tree
//!    before the child mounts anything.
//!
//! The gap is recorded for the audit: if `execute_plan` grows a
//! "copy + system skeleton" mode, this module should collapse into a thin
//! adapter. Until then it is a scoped, ~150-line writer over the same
//! [`PlanOp`] vocabulary.
//!
//! # Scope
//!
//! One container profile = one set of refs (its package plus whatever the
//! resolver pulls in through `requires`). No multi-system VFS, no `/runlevel/1`
//! tree, no writes outside [`RootfsRequest::stage`].

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

use crate::cas::CasRepository;
use crate::container::ContainerError;
use crate::weaver::{
    plan_from_refs_with, CasRef, LinkStrategy, OriginPriority, PlanOp, VfsPlan,
};

/// Directories every container root gets before the package tree is copied.
///
/// `/proc`, `/sys` stay empty at every level (sysfs is not mountable from an
/// unprivileged user namespace, and a host procfs inside a container leaks host
/// PIDs); `/dev`, `/tmp`, `/run` are replaced with tmpfs by the child.
pub const SYSTEM_DIRS: [&str; 10] = [
    "etc", "proc", "sys", "dev", "tmp", "run", "var", "root", "home", "usr",
];

/// A request to assemble one container rootfs.
pub struct RootfsRequest<'a> {
    /// CAS the refs live in.
    pub repo: &'a CasRepository,
    /// Packages to weave (the profile package plus any explicit additions).
    pub refs: &'a [CasRef],
    /// Directory that becomes the container root. Created if absent; must be
    /// empty or non-existent so a stale root can never leak into a new
    /// container.
    pub stage: &'a Path,
    /// Hostname written to `/etc/hostname` inside the root.
    pub hostname: &'a str,
}

/// Result of a successful assembly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rootfs {
    /// Where the tree was materialised.
    pub stage: PathBuf,
    /// Top-level entries of the tree, sorted — this is exactly the list the
    /// child bind-mounts into its tmpfs root.
    pub top_level: Vec<String>,
    /// Counts, for diagnostics and tests.
    pub directories: usize,
    /// Regular files copied from the CAS.
    pub files: usize,
    /// Symlinks recreated verbatim.
    pub symlinks: usize,
    /// Tier-3 dispatch wrappers written.
    pub wrappers: usize,
    /// Files that received their declared file capabilities (PLAN 6.1.2);
    /// refusals land in [`Rootfs::warnings`] instead.
    pub file_caps: usize,
    /// Non-fatal notes from the planner and the writer.
    pub warnings: Vec<String>,
}

impl Rootfs {
    /// Whether `program` (an absolute in-container path) exists and is
    /// executable.
    pub fn has_program(&self, program: &str) -> bool {
        let rel = program.trim_start_matches('/');
        if rel.is_empty() {
            return false;
        }
        let path = self.stage.join(rel);
        path.metadata()
            .map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }

    /// Typed check used by the launcher before spawning anything.
    pub fn require_program(&self, program: &str) -> Result<(), ContainerError> {
        if self.has_program(program) {
            return Ok(());
        }
        Err(ContainerError::ProgramNotFound(program.to_string()))
    }
}

/// Assemble the container rootfs described by `request`.
pub fn assemble_rootfs(request: &RootfsRequest<'_>) -> Result<Rootfs, ContainerError> {
    if request.refs.is_empty() {
        return Err(ContainerError::Rootfs(
            "a container profile needs at least one package ref".into(),
        ));
    }

    let plan = plan_from_refs_with(
        request.repo,
        request.refs,
        LinkStrategy::Symlink,
        &OriginPriority::new(),
    )
    .map_err(|err| ContainerError::Rootfs(err.to_string()))?;

    prepare_stage(request.stage)?;

    let mut rootfs = Rootfs {
        stage: request.stage.to_path_buf(),
        top_level: Vec::new(),
        directories: 0,
        files: 0,
        symlinks: 0,
        wrappers: 0,
        file_caps: 0,
        warnings: plan.warnings().to_vec(),
    };

    for dir in SYSTEM_DIRS {
        ensure_dir(&request.stage.join(dir))?;
        rootfs.directories += 1;
    }
    seed_etc(request.stage, request.hostname)?;

    write_plan(&plan, request.stage, &mut rootfs)?;

    rootfs.top_level = list_top_level(request.stage)?;
    Ok(rootfs)
}

/// Create the staging directory, refusing to reuse a non-empty one.
fn prepare_stage(stage: &Path) -> Result<(), ContainerError> {
    if stage.exists() {
        let mut entries = fs::read_dir(stage).map_err(|err| {
            ContainerError::Rootfs(format!("cannot read {}: {err}", stage.display()))
        })?;
        if entries.next().is_some() {
            return Err(ContainerError::Rootfs(format!(
                "staging directory {} is not empty; refusing to weave over an existing root",
                stage.display()
            )));
        }
    } else {
        fs::create_dir_all(stage).map_err(|err| {
            ContainerError::Rootfs(format!("cannot create {}: {err}", stage.display()))
        })?;
    }
    Ok(())
}

/// Minimal `/etc`: identity of the container and a root account so tools that
/// call `getpwuid` do not fail.
fn seed_etc(stage: &Path, hostname: &str) -> Result<(), ContainerError> {
    let etc = stage.join("etc");
    ensure_dir(&etc)?;
    let hostname = if hostname.is_empty() { "extos" } else { hostname };
    write_if_absent(&etc.join("hostname"), &format!("{hostname}\n"))?;
    write_if_absent(&etc.join("passwd"), "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/false\n")?;
    write_if_absent(&etc.join("group"), "root:x:0:\nnogroup:x:65534:\n")?;
    write_if_absent(&etc.join("nsswitch.conf"), "passwd: files\ngroup: files\nhosts: files dns\n")?;
    Ok(())
}

fn write_if_absent(path: &Path, contents: &str) -> Result<(), ContainerError> {
    if path.exists() {
        return Ok(());
    }
    fs::write(path, contents).map_err(|err| {
        ContainerError::Rootfs(format!("cannot seed {}: {err}", path.display()))
    })
}

fn ensure_dir(path: &Path) -> Result<(), ContainerError> {
    fs::create_dir_all(path)
        .map_err(|err| ContainerError::Rootfs(format!("cannot create {}: {err}", path.display())))
}

/// Apply the plan to `stage`, copying payloads.
fn write_plan(plan: &VfsPlan, stage: &Path, rootfs: &mut Rootfs) -> Result<(), ContainerError> {
    for entry in plan.entries() {
        let rel = entry.rel_path();
        validate_rel_path(rel)?;
        let target = stage.join(rel);
        match &entry.op {
            PlanOp::Directory { .. } => {
                ensure_dir(&target)?;
                rootfs.directories += 1;
            }
            PlanOp::Symlink { target: link_to, .. } => {
                if let Some(parent) = target.parent() {
                    ensure_dir(parent)?;
                }
                remove_existing(&target)?;
                std::os::unix::fs::symlink(link_to, &target).map_err(|err| {
                    ContainerError::Rootfs(format!(
                        "cannot symlink {} -> {}: {err}",
                        target.display(),
                        link_to.display()
                    ))
                })?;
                rootfs.symlinks += 1;
            }
            PlanOp::Link { source, .. } => {
                if !source.exists() {
                    rootfs.warnings.push(format!(
                        "payload for {} is missing from the CAS ({}); entry skipped",
                        rel.display(),
                        source.display()
                    ));
                    continue;
                }
                if let Some(parent) = target.parent() {
                    ensure_dir(parent)?;
                }
                remove_existing(&target)?;
                // Copy, never link: a container must not be able to mutate the
                // read-only CAS through a shared inode (see the module docs).
                fs::copy(source, &target).map_err(|err| {
                    ContainerError::Rootfs(format!(
                        "cannot copy {} -> {}: {err}",
                        source.display(),
                        target.display()
                    ))
                })?;
                let mode = source
                    .metadata()
                    .map(|meta| meta.permissions().mode() & 0o7777)
                    .unwrap_or(0o644);
                fs::set_permissions(&target, fs::Permissions::from_mode(mode)).map_err(|err| {
                    ContainerError::Rootfs(format!(
                        "cannot set mode on {}: {err}",
                        target.display()
                    ))
                })?;
                rootfs.files += 1;
            }
            PlanOp::Wrapper { script, .. } => {
                if let Some(parent) = target.parent() {
                    ensure_dir(parent)?;
                }
                remove_existing(&target)?;
                fs::write(&target, script).map_err(|err| {
                    ContainerError::Rootfs(format!("cannot write {}: {err}", target.display()))
                })?;
                fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).map_err(|err| {
                    ContainerError::Rootfs(format!(
                        "cannot mark {} executable: {err}",
                        target.display()
                    ))
                })?;
                rootfs.wrappers += 1;
            }
            PlanOp::FileCaps { capabilities, .. } => {
                // The scoped rootfs copies payloads, so capabilities are
                // re-applied on the copy. A refusal (unprivileged assembly)
                // is recorded, never fatal and never silent.
                match crate::security::filecaps::apply_file_caps(&target, capabilities) {
                    Ok(()) => rootfs.file_caps += 1,
                    Err(err) => rootfs.warnings.push(format!(
                        "file capabilities skipped for {}: {err}",
                        rel.display()
                    )),
                }
            }
        }
    }
    Ok(())
}

fn remove_existing(path: &Path) -> Result<(), ContainerError> {
    match path.symlink_metadata() {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(path).map_err(|err| {
            ContainerError::Rootfs(format!("cannot clear {}: {err}", path.display()))
        }),
        Ok(_) => fs::remove_file(path).map_err(|err| {
            ContainerError::Rootfs(format!("cannot clear {}: {err}", path.display()))
        }),
        Err(_) => Ok(()),
    }
}

/// Reject absolute paths, `..` and empty components: a plan entry must never be
/// able to escape the staging root.
pub fn validate_rel_path(path: &Path) -> Result<(), ContainerError> {
    if path.as_os_str().is_empty() {
        return Err(ContainerError::Rootfs("empty plan path".into()));
    }
    for component in path.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir => {
                return Err(ContainerError::Rootfs(format!(
                    "plan path escapes the rootfs: {}",
                    path.display()
                )));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(ContainerError::Rootfs(format!(
                    "plan path is absolute: {}",
                    path.display()
                )));
            }
        }
    }
    Ok(())
}

fn list_top_level(stage: &Path) -> Result<Vec<String>, ContainerError> {
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(stage).map_err(|err| {
        ContainerError::Rootfs(format!("cannot list {}: {err}", stage.display()))
    })? {
        let entry = entry.map_err(|err| ContainerError::Rootfs(err.to_string()))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(ContainerError::Rootfs(format!(
                "non-UTF-8 top-level entry in {}",
                stage.display()
            )));
        };
        names.insert(name.to_string());
    }
    Ok(names.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::HashAlgorithm;

    #[test]
    fn empty_refs_are_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = CasRepository::open(tmp.path().join("repo"), HashAlgorithm::Blake3).unwrap();
        let err = assemble_rootfs(&RootfsRequest {
            repo: &repo,
            refs: &[],
            stage: &tmp.path().join("root"),
            hostname: "extos",
        })
        .unwrap_err();
        assert!(matches!(err, ContainerError::Rootfs(_)));
    }

    #[test]
    fn non_empty_stage_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let stage = tmp.path().join("root");
        fs::create_dir_all(&stage).unwrap();
        fs::write(stage.join("stale"), b"x").unwrap();
        let err = prepare_stage(&stage).unwrap_err();
        assert!(err.to_string().contains("not empty"));
    }

    #[test]
    fn system_dirs_and_etc_skeleton_are_created() {
        let tmp = tempfile::tempdir().unwrap();
        let stage = tmp.path().join("root");
        prepare_stage(&stage).unwrap();
        for dir in SYSTEM_DIRS {
            ensure_dir(&stage.join(dir)).unwrap();
        }
        seed_etc(&stage, "extos-test").unwrap();
        for dir in SYSTEM_DIRS {
            assert!(stage.join(dir).is_dir(), "{dir} missing");
        }
        let passwd = fs::read_to_string(stage.join("etc/passwd")).unwrap();
        assert!(passwd.contains("root:x:0:0"));
        assert_eq!(
            fs::read_to_string(stage.join("etc/hostname")).unwrap(),
            "extos-test\n"
        );
        // Seeding never overwrites a package-provided file.
        fs::write(stage.join("etc/hostname"), "package\n").unwrap();
        seed_etc(&stage, "other").unwrap();
        assert_eq!(
            fs::read_to_string(stage.join("etc/hostname")).unwrap(),
            "package\n"
        );
    }

    #[test]
    fn rel_path_validation_rejects_escapes() {
        assert!(validate_rel_path(Path::new("usr/bin/sh")).is_ok());
        assert!(validate_rel_path(Path::new("")).is_err());
        assert!(validate_rel_path(Path::new("/etc/passwd")).is_err());
        assert!(validate_rel_path(Path::new("../escape")).is_err());
        assert!(validate_rel_path(Path::new("usr/../../escape")).is_err());
    }

    #[test]
    fn top_level_listing_is_sorted() {
        let tmp = tempfile::tempdir().unwrap();
        for name in ["usr", "etc", "bin"] {
            fs::create_dir_all(tmp.path().join(name)).unwrap();
        }
        let names = list_top_level(tmp.path()).unwrap();
        assert_eq!(names, vec!["bin", "etc", "usr"]);
    }
}
