//! Forge mount plan: tmpfs root plus bind mounts of CAS objects (PLAN 4.2.2).
//!
//! A [`MountPlan`] is a *description* plus a *prepared program*:
//!
//! * [`MountPlan::describe`] renders the human-readable op list used in logs
//!   and tests;
//! * [`MountPlan::mount_script`] renders the same program as a `mount(8)` shell
//!   script for the `unshare` CLI strategy;
//! * [`MountPlan::apply_in_child`] executes it with raw syscalls and is meant to
//!   run inside a `pre_exec` closure — see the safety contract below.
//!
//! # Layout inside the forge
//!
//! ```text
//! <scratch>/forge/                  tmpfs (size-limited, nosuid, nodev)
//! ├── usr, bin, lib …               optional read-only host runtime binds
//! ├── opt/extos/tools/<name>/       read-only CAS object contents
//! ├── etc/initcpio/install/<hook>   read-only hook scripts from CAS
//! ├── etc/initcpio/hooks/<hook>     runtime hooks
//! ├── <blueprint binds…>            caller-declared host paths
//! └── out/                          read-write bind of the byte output dir
//! ```
//!
//! `<forge>/out` is the only write-through mount: an artifact written there
//! survives the namespace, everything else is thrown away with it. The forge is
//! **not** a chroot — paths keep their host meaning and isolation comes from the
//! private mount namespace, which only overlays `<scratch>/forge`; unbound host
//! paths stay visible but read-only usage is all the forge needs.
//!
//! # Syscall order (identical for both strategies)
//!
//! 1. `unshare(CLONE_NEWUSER | CLONE_NEWNS)` (or just `CLONE_NEWNS` as root);
//! 2. write `uid_map` / `gid_map` when unprivileged;
//! 3. `mount("/", MS_REC|MS_PRIVATE)` so nothing propagates to the host;
//! 4. mount the tmpfs root;
//! 5. `mkdir` every directory target **inside** the tmpfs;
//! 6. create empty file targets, write inline files;
//! 7. bind each source over its target (plus a read-only remount for `ro`).
//!
//! Steps 5–7 must run after step 4, otherwise the tmpfs would hide the created
//! directories. [`MountPlan::mount_script`] emits the same order.
//!
//! # Async-signal-safe `pre_exec` contract
//!
//! After `fork(2)` the child may only call async-signal-safe functions: no
//! allocation, no locks, no Rust formatting. [`MountPlan::apply_in_child`]
//! therefore touches **only** resources prepared before the fork:
//!
//! * every path is a pre-built [`CString`] stored in the plan;
//! * the uid/gid map text and all mount data strings are pre-rendered;
//! * inline file contents are pre-serialised `Vec<u8>` buffers;
//! * errors are returned as `io::Error::from_raw_os_error(errno)`, which is a
//!   plain integer wrapper (no allocation).
//!
//! The only syscalls used are `unshare`, `open`, `write`, `close`, `mkdir` and
//! `mount`, all of which are async-signal-safe.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString, OsStr};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use crate::cas::CasRepository;

use super::blueprint::{ForgeBlueprint, HookKind};
use super::{ForgeError, ForgeResult};

/// Forge-relative directory holding one subdirectory per blueprint tool.
pub const FORGE_TOOLS_DIR: &str = "opt/extos/tools";

/// Forge-relative directory for mkinitcpio *install* hooks.
pub const FORGE_INSTALL_HOOKS_DIR: &str = "etc/initcpio/install";

/// Forge-relative directory for mkinitcpio *runtime* hooks.
pub const FORGE_RUNTIME_HOOKS_DIR: &str = "etc/initcpio/hooks";

/// Forge-relative directory where the write-through output bind is mounted.
pub const FORGE_OUTPUT_DIR: &str = "out";

/// Directory name created for the forge inside the caller's scratch root.
pub const FORGE_ROOT_DIR: &str = "forge";

/// Default tmpfs size for the forge root (512 MiB).
pub const DEFAULT_TMPFS_SIZE: u64 = 512 * 1024 * 1024;

/// Default permissions for the tmpfs root.
pub const DEFAULT_TMPFS_MODE: u32 = 0o755;

/// Host directories bound read-only by [`MountPlanOptions::default`].
///
/// These are FHS runtime locations, not ExtOS layout: a forge that has to run a
/// real generator needs the host toolchain (`sh`, `bash`, `mount`, …). They are
/// only read-only binds, overridable with `EXTOS_FORGE_HOST_DIRS`
/// (`:`-separated) and absent from [`MountPlanOptions::minimal`].
pub const DEFAULT_HOST_RUNTIME_DIRS: &[&str] = &["/usr", "/bin", "/sbin", "/lib", "/lib64"];

/// Knobs for [`MountPlan::build_with`].
#[derive(Debug, Clone)]
pub struct MountPlanOptions {
    /// Host directories to bind read-only into the forge (missing ones skipped).
    pub host_runtime_dirs: Vec<PathBuf>,
    /// Size in bytes of the forge tmpfs.
    pub tmpfs_size: u64,
    /// Mode of the forge tmpfs root.
    pub tmpfs_mode: u32,
}

impl Default for MountPlanOptions {
    fn default() -> Self {
        Self {
            host_runtime_dirs: default_host_runtime_dirs(),
            tmpfs_size: DEFAULT_TMPFS_SIZE,
            tmpfs_mode: DEFAULT_TMPFS_MODE,
        }
    }
}

impl MountPlanOptions {
    /// Options with no host runtime binds — only blueprint-declared mounts.
    pub fn minimal() -> Self {
        Self {
            host_runtime_dirs: Vec::new(),
            tmpfs_size: DEFAULT_TMPFS_SIZE,
            tmpfs_mode: DEFAULT_TMPFS_MODE,
        }
    }

    /// Options from the environment: `EXTOS_FORGE_HOST_DIRS` (`:`-separated)
    /// replaces the default host runtime bind list, `EXTOS_FORGE_TMPFS_SIZE`
    /// (bytes) replaces the tmpfs size.
    pub fn from_env() -> Self {
        let mut options = Self::default();
        if let Ok(value) = std::env::var("EXTOS_FORGE_HOST_DIRS") {
            options.host_runtime_dirs = value
                .split(':')
                .filter(|part| !part.is_empty())
                .map(PathBuf::from)
                .collect();
        }
        if let Ok(value) = std::env::var("EXTOS_FORGE_TMPFS_SIZE")
            && let Ok(size) = value.trim().parse::<u64>()
        {
            options.tmpfs_size = size;
        }
        options
    }
}

/// The default host runtime bind list, filtered to paths that exist.
pub fn default_host_runtime_dirs() -> Vec<PathBuf> {
    DEFAULT_HOST_RUNTIME_DIRS
        .iter()
        .map(PathBuf::from)
        .filter(|path| path.is_dir())
        .collect()
}

/// What kind of mount an op performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountKind {
    /// A size-limited `tmpfs`.
    Tmpfs {
        /// Size in bytes.
        size: u64,
        /// Root mode.
        mode: u32,
    },
    /// A recursive bind mount, optionally remounted read-only.
    Bind {
        /// Remount the bind read-only.
        readonly: bool,
    },
}

/// One mount in the forge program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgeMount {
    /// Mount flavour.
    pub kind: MountKind,
    /// Host source path (`None` for tmpfs).
    pub source: Option<PathBuf>,
    /// Absolute target path; equal to the in-forge path.
    pub target: PathBuf,
}

impl ForgeMount {
    /// Human-readable one-line description.
    pub fn describe(&self) -> String {
        match self.kind {
            MountKind::Tmpfs { size, mode } => {
                format!("tmpfs {} size={size} mode={mode:o}", self.target.display())
            }
            MountKind::Bind { readonly } => format!(
                "bind {} {} -> {}",
                if readonly { "ro" } else { "rw" },
                self.source
                    .as_deref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_default(),
                self.target.display()
            ),
        }
    }
}

/// A resolved forge: mount program plus derived in-forge paths.
#[derive(Debug)]
pub struct MountPlan {
    /// Host directory that becomes the tmpfs root.
    root: PathBuf,
    /// Working directory for the tool (the forge root by default).
    workdir: PathBuf,
    /// `workdir` as a `CString`, for the post-mount `chdir(2)`.
    workdir_c: CString,
    /// Ordered mount program.
    mounts: Vec<ForgeMount>,
    /// Host directory mounted read-write at `<root>/out`.
    output_host: PathBuf,
    /// Tool name → in-forge executable path.
    tool_programs: BTreeMap<String, PathBuf>,
    /// Hook names in blueprint order.
    hooks: Vec<String>,
    /// Directories to create inside the tmpfs, shallowest first.
    dirs: Vec<CString>,
    /// Empty file targets to create inside the tmpfs (file bind targets).
    file_targets: Vec<CString>,
    /// Files written into the tmpfs from memory (e.g. generated configs).
    inline: Vec<PreparedFile>,
    /// The tmpfs root mount, executed before everything else.
    root_mount: Option<PreparedMount>,
    /// Syscall-ready mounts executed after the directories exist.
    prepared: Vec<PreparedMount>,
    /// Pre-rendered `0 <uid> 1` mapping.
    mapping_uid: CString,
    /// Pre-rendered `0 <gid> 1` mapping.
    mapping_gid: CString,
}

impl std::fmt::Debug for PreparedMount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedMount")
            .field("target", &self.target)
            .field("flags", &self.flags)
            .finish()
    }
}

struct PreparedMount {
    source: Option<CString>,
    target: CString,
    fstype: Option<CString>,
    data: Option<CString>,
    flags: libc::c_ulong,
}

#[derive(Debug)]
struct PreparedFile {
    path: CString,
    data: Vec<u8>,
}

impl MountPlan {
    /// Build the default forge for `blueprint` out of `cas`.
    ///
    /// Uses [`MountPlanOptions::default`] (host FHS runtime binds enabled). The
    /// forge root is created at `<scratch_root>/forge`; `blueprint.output.dir`
    /// must already exist because it is bind-mounted — a missing directory is a
    /// typed [`ForgeError::SourceMissing`].
    ///
    /// This pre-existence requirement is intentionally asymmetric with
    /// [`BlsPlan::write`](crate::forge::bls::BlsPlan::write), which
    /// `create_dir_all`s its own `loader/entries` below the boot root: the
    /// forge only *reads* an existing output tree, while the BLS writer is the
    /// tool that populates a fresh boot root.
    pub fn build(
        blueprint: &ForgeBlueprint,
        cas: &CasRepository,
        scratch_root: &Path,
    ) -> ForgeResult<Self> {
        Self::build_with(blueprint, cas, scratch_root, &MountPlanOptions::default())
    }

    /// Build a forge with explicit options.
    pub fn build_with(
        blueprint: &ForgeBlueprint,
        cas: &CasRepository,
        scratch_root: &Path,
        options: &MountPlanOptions,
    ) -> ForgeResult<Self> {
        let root = scratch_root.join(FORGE_ROOT_DIR);
        fs::create_dir_all(&root)?;

        let output_host = blueprint.output.dir.clone();
        if !output_host.is_dir() {
            return Err(ForgeError::SourceMissing {
                path: output_host.display().to_string(),
            });
        }

        let mut mounts = vec![ForgeMount {
            kind: MountKind::Tmpfs {
                size: options.tmpfs_size,
                mode: options.tmpfs_mode,
            },
            source: None,
            target: root.clone(),
        }];

        for host_dir in &options.host_runtime_dirs {
            if !host_dir.is_dir() {
                continue;
            }
            let Some(relative) = strip_root(host_dir) else {
                continue;
            };
            mounts.push(ForgeMount {
                kind: MountKind::Bind { readonly: true },
                source: Some(host_dir.clone()),
                target: root.join(relative),
            });
        }

        let mut tool_programs = BTreeMap::new();
        for tool in &blueprint.tools {
            let object_dir = cas.object_path(&tool.object);
            if !object_dir.is_dir() {
                return Err(ForgeError::ObjectNotFound {
                    object: tool.object.clone(),
                });
            }
            let content = object_dir.join("content");
            if !content.is_dir() {
                return Err(ForgeError::ToolMissing {
                    tool: tool.name.clone(),
                    path: "content".into(),
                    object: tool.object.clone(),
                });
            }
            let target = root.join(FORGE_TOOLS_DIR).join(&tool.name);
            mounts.push(ForgeMount {
                kind: MountKind::Bind { readonly: true },
                source: Some(content.clone()),
                target: target.clone(),
            });
            if let Some(exec) = &tool.exec {
                let host_exec = content.join(exec);
                if !host_exec.is_file() {
                    return Err(ForgeError::ToolMissing {
                        tool: tool.name.clone(),
                        path: exec.display().to_string(),
                        object: tool.object.clone(),
                    });
                }
                tool_programs.insert(tool.name.clone(), target.join(exec));
            }
        }

        for hook in &blueprint.hooks {
            let (Some(object), Some(path)) = (&hook.object, &hook.path) else {
                continue;
            };
            let object_dir = cas.object_path(object);
            if !object_dir.is_dir() {
                return Err(ForgeError::ObjectNotFound {
                    object: object.clone(),
                });
            }
            let host_script = object_dir.join("content").join(path);
            if !host_script.is_file() {
                return Err(ForgeError::ToolMissing {
                    tool: hook.name.clone(),
                    path: path.display().to_string(),
                    object: object.clone(),
                });
            }
            let dir = match hook.kind {
                HookKind::Install => FORGE_INSTALL_HOOKS_DIR,
                HookKind::Runtime => FORGE_RUNTIME_HOOKS_DIR,
            };
            mounts.push(ForgeMount {
                kind: MountKind::Bind { readonly: true },
                source: Some(host_script),
                target: root.join(dir).join(&hook.name),
            });
        }

        for bind in &blueprint.binds {
            if !bind.source.exists() {
                return Err(ForgeError::SourceMissing {
                    path: bind.source.display().to_string(),
                });
            }
            mounts.push(ForgeMount {
                kind: MountKind::Bind {
                    readonly: bind.readonly,
                },
                source: Some(bind.source.clone()),
                target: root.join(&bind.target),
            });
        }

        mounts.push(ForgeMount {
            kind: MountKind::Bind { readonly: false },
            source: Some(output_host.clone()),
            target: root.join(FORGE_OUTPUT_DIR),
        });

        let mut plan = Self {
            root: root.clone(),
            workdir: PathBuf::new(),
            workdir_c: cstring(root.as_os_str(), "forge root")?,
            mounts,
            output_host,
            tool_programs,
            hooks: blueprint
                .hooks
                .iter()
                .map(|hook| hook.name.clone())
                .collect(),
            dirs: Vec::new(),
            file_targets: Vec::new(),
            inline: Vec::new(),
            root_mount: None,
            prepared: Vec::new(),
            mapping_uid: mapping_cstring(unsafe { libc::getuid() }),
            mapping_gid: mapping_cstring(unsafe { libc::getgid() }),
        };
        plan.workdir = plan.root.clone();
        plan.validate_layout()?;
        plan.rebuild()?;
        Ok(plan)
    }

    /// Host path of the forge root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Working directory the tool starts in (the forge root).
    pub fn workdir(&self) -> &Path {
        &self.workdir
    }

    /// Ordered mount program.
    pub fn mounts(&self) -> &[ForgeMount] {
        &self.mounts
    }

    /// Host directory the artifact is written into (`<root>/out` in-forge).
    pub fn output_host(&self) -> &Path {
        &self.output_host
    }

    /// In-forge path of `name` inside the output bind.
    pub fn output_in_forge(&self, name: &str) -> PathBuf {
        self.root.join(FORGE_OUTPUT_DIR).join(name)
    }

    /// Path of the read-write output bind inside the forge.
    pub fn output_dir_in_forge(&self) -> PathBuf {
        self.root.join(FORGE_OUTPUT_DIR)
    }

    /// In-forge executable path for a blueprint tool, if it declared `exec`.
    pub fn tool_program(&self, name: &str) -> Option<&Path> {
        self.tool_programs.get(name).map(PathBuf::as_path)
    }

    /// Tool name → in-forge executable path.
    pub fn tool_programs(&self) -> &BTreeMap<String, PathBuf> {
        &self.tool_programs
    }

    /// Hook names in blueprint order.
    pub fn hooks(&self) -> &[String] {
        &self.hooks
    }

    /// In-forge path of a staged file or directory (helper for callers).
    pub fn in_forge(&self, relative: impl AsRef<Path>) -> PathBuf {
        self.root.join(relative.as_ref())
    }

    /// Change the working directory used inside the forge.
    pub fn set_workdir(&mut self, workdir: PathBuf) -> ForgeResult<()> {
        self.workdir_c = cstring(workdir.as_os_str(), "workdir")?;
        self.workdir = workdir;
        Ok(())
    }

    /// Stage `content` at the absolute in-forge path `path` before the tool runs.
    ///
    /// The file is written by the `pre_exec` child directly into the tmpfs, so
    /// generated configuration (e.g. `mkinitcpio.conf`) never touches the host.
    pub fn stage_inline_file(&mut self, path: &Path, content: &str) -> ForgeResult<()> {
        if !path.is_absolute() {
            return Err(ForgeError::MountFailed {
                target: path.display().to_string(),
                message: "inline file path must be absolute (inside the forge)".into(),
            });
        }
        if !path.starts_with(&self.root) || path == self.root {
            return Err(ForgeError::MountFailed {
                target: path.display().to_string(),
                message: format!(
                    "inline file must live under the forge root '{}'",
                    self.root.display()
                ),
            });
        }
        self.inline.push(PreparedFile {
            path: cstring(path.as_os_str(), "inline file path")?,
            data: content.as_bytes().to_vec(),
        });
        self.rebuild()
    }

    /// Human-readable program, one line per operation, in execution order.
    pub fn describe(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if let Some(root) = &self.root_mount {
            lines.push(format!("tmpfs {}", root.target.to_string_lossy()));
        }
        for dir in &self.dirs {
            lines.push(format!("mkdir {}", dir.to_string_lossy()));
        }
        for file in &self.file_targets {
            lines.push(format!("touch {}", file.to_string_lossy()));
        }
        for file in &self.inline {
            lines.push(format!(
                "write {} ({} bytes)",
                file.path.to_string_lossy(),
                file.data.len()
            ));
        }
        for mount in &self.mounts {
            if mount.target == self.root {
                continue; // reported above as the tmpfs root
            }
            lines.push(mount.describe());
        }
        lines
    }

    /// Render the program as a `sh` script for the `unshare` CLI strategy.
    ///
    /// The script assumes it already runs inside a user+mount namespace and
    /// that `mount(8)` and a POSIX shell are available (host runtime binds).
    pub fn mount_script(&self) -> String {
        let mut script = String::from("set -e\n");
        if let Some(root) = &self.root_mount
            && let Some(data) = &root.data
        {
            script.push_str(&format!(
                "mount -t tmpfs -o {} tmpfs {}\n",
                data.to_string_lossy(),
                shell_quote(&root.target.to_string_lossy())
            ));
        }
        for dir in &self.dirs {
            script.push_str(&format!(
                "mkdir -p {}\n",
                shell_quote(&dir.to_string_lossy())
            ));
        }
        for file in &self.file_targets {
            script.push_str(&format!(": > {}\n", shell_quote(&file.to_string_lossy())));
        }
        for file in &self.inline {
            script.push_str(&format!(
                "printf '%s' {} > {}\n",
                shell_quote(&String::from_utf8_lossy(&file.data)),
                shell_quote(&file.path.to_string_lossy())
            ));
        }
        for mount in &self.mounts {
            if mount.source.is_none() && mount.target == self.root {
                continue; // tmpfs root, already emitted
            }
            let target = shell_quote(&mount.target.to_string_lossy());
            let source = mount
                .source
                .as_deref()
                .map(|path| shell_quote(&path.to_string_lossy()))
                .unwrap_or_else(|| "''".to_string());
            script.push_str(&format!("mount --bind {source} {target}\n"));
            if let MountKind::Bind { readonly: true } = mount.kind {
                script.push_str(&format!("mount -o remount,ro,bind {target}\n"));
            }
        }
        script
    }

    /// Execute the plan in the current process.
    ///
    /// # Safety contract
    ///
    /// This function is meant to be called from `CommandExt::pre_exec`, i.e. in
    /// the child between `fork(2)` and `execve(2)`. It allocates nothing and
    /// only uses async-signal-safe syscalls (see the module docs). Calling it
    /// from a normal thread is *not* safe: it replaces mounts for the whole
    /// calling process.
    pub fn apply_in_child(&self) -> io::Result<()> {
        self.apply_in_child_in(None)
    }

    /// Like [`MountPlan::apply_in_child`], but changing into `workdir` (a
    /// pre-built `CString`) after the mounts. `None` uses
    /// [`MountPlan::workdir`].
    ///
    /// The `chdir` happens after the tmpfs is mounted, so relative paths inside
    /// the tool resolve in the forge rather than in the (now covered) host
    /// directory.
    ///
    /// # Safety contract
    ///
    /// Same as [`MountPlan::apply_in_child`].
    pub fn apply_in_child_in(&self, workdir: Option<&CStr>) -> io::Result<()> {
        // SAFETY: the caller guarantees post-fork, pre-exec context (see above).
        // Every pointer comes from a CString/Vec owned by `self`, so it stays
        // valid for the duration of the call, and nothing here allocates.
        unsafe {
            let euid = libc::geteuid();
            let unshare_flags = if euid == 0 {
                libc::CLONE_NEWNS
            } else {
                libc::CLONE_NEWUSER | libc::CLONE_NEWNS
            };
            if libc::unshare(unshare_flags) != 0 {
                return Err(io::Error::last_os_error());
            }

            if euid != 0 {
                // Unprivileged user namespaces start without a mapping: install
                // it before any mount, which needs CAP_SYS_ADMIN in the new
                // namespace. `setgroups` must be denied before `gid_map`.
                ignore_missing(write_small_file(c"/proc/self/setgroups", b"deny"))?;
                write_small_file(c"/proc/self/uid_map", self.mapping_uid.as_bytes())?;
                write_small_file(c"/proc/self/gid_map", self.mapping_gid.as_bytes())?;
            }

            // Make the new mount namespace private so nothing propagates back to
            // the host mount namespace.
            if libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }

            if let Some(root) = &self.root_mount {
                mount_one(root)?;
            }

            for dir in &self.dirs {
                if libc::mkdir(dir.as_ptr(), 0o755) != 0 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::EEXIST) {
                        return Err(error);
                    }
                }
            }

            for path in &self.file_targets {
                let fd = libc::open(
                    path.as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC,
                    0o644,
                );
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                libc::close(fd);
            }

            for file in &self.inline {
                let fd = libc::open(
                    file.path.as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC,
                    0o644,
                );
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                if let Err(error) = write_all_fd(fd, &file.data) {
                    libc::close(fd);
                    return Err(error);
                }
                libc::close(fd);
            }

            for mount in &self.prepared {
                mount_one(mount)?;
            }

            let dir = workdir.unwrap_or(&self.workdir_c);
            if libc::chdir(dir.as_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// Reject mount layouts whose targets nest, which would make the mount
    /// order decide the visible result.
    fn validate_layout(&self) -> ForgeResult<()> {
        for (index, mount) in self.mounts.iter().enumerate() {
            if mount.target == self.root {
                continue;
            }
            for other in &self.mounts[index + 1..] {
                if other.target == self.root {
                    continue;
                }
                if mount.target.starts_with(&other.target)
                    || other.target.starts_with(&mount.target)
                {
                    return Err(ForgeError::MountFailed {
                        target: format!("{} / {}", mount.target.display(), other.target.display()),
                        message: "nested forge mount targets are not supported; bind the parent \
                                  directory instead"
                            .into(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Recompute the prepared dirs, file targets and syscall program.
    fn rebuild(&mut self) -> ForgeResult<()> {
        let mut dir_targets: BTreeSet<PathBuf> = BTreeSet::new();
        let mut file_paths: Vec<PathBuf> = Vec::new();

        for mount in &self.mounts {
            let Some(source) = mount.source.as_deref() else {
                continue; // the tmpfs root itself
            };
            if source.is_dir() {
                dir_targets.insert(mount.target.clone());
            } else {
                file_paths.push(mount.target.clone());
            }
        }
        for file in &self.inline {
            file_paths.push(PathBuf::from(OsStr::from_bytes(file.path.as_bytes())));
        }

        // Every directory the program touches, plus all of their ancestors
        // below the forge root, shallowest first so `mkdir` never needs `-p`.
        let mut needed: BTreeSet<PathBuf> = BTreeSet::new();
        for path in dir_targets.iter() {
            needed.insert(path.clone());
        }
        for path in needed.clone().iter().chain(file_paths.iter()) {
            let mut current = path.parent();
            while let Some(parent) = current {
                if !parent.starts_with(&self.root) || parent == self.root {
                    break;
                }
                needed.insert(parent.to_path_buf());
                current = parent.parent();
            }
        }

        let mut ordered: Vec<PathBuf> = needed.into_iter().collect();
        ordered.sort_by(|a, b| {
            component_count(a)
                .cmp(&component_count(b))
                .then_with(|| a.cmp(b))
        });

        self.dirs = ordered
            .iter()
            .map(|path| cstring(path.as_os_str(), "mount directory"))
            .collect::<ForgeResult<_>>()?;
        self.file_targets = file_paths
            .iter()
            .map(|path| cstring(path.as_os_str(), "mount file target"))
            .collect::<ForgeResult<_>>()?;

        let mut root_mount = None;
        let mut prepared = Vec::new();
        for mount in &self.mounts {
            let ops = self.prepare(mount)?;
            if mount.target == self.root {
                root_mount = ops.into_iter().next();
            } else {
                prepared.extend(ops);
            }
        }
        self.root_mount = root_mount;
        self.prepared = prepared;
        Ok(())
    }

    /// Expand one [`ForgeMount`] into its syscall operations.
    fn prepare(&self, mount: &ForgeMount) -> ForgeResult<Vec<PreparedMount>> {
        let target = cstring(mount.target.as_os_str(), "mount target")?;
        match mount.kind {
            MountKind::Tmpfs { size, mode } => Ok(vec![PreparedMount {
                source: None,
                target,
                fstype: Some(cstring(OsStr::new("tmpfs"), "fstype")?),
                data: Some(cstring(
                    OsStr::new(&format!("size={size},mode={mode:o}")),
                    "tmpfs options",
                )?),
                flags: libc::MS_NOSUID | libc::MS_NODEV,
            }]),
            MountKind::Bind { readonly } => {
                let source = mount
                    .source
                    .as_ref()
                    .ok_or_else(|| ForgeError::MountFailed {
                        target: mount.target.display().to_string(),
                        message: "bind mount without a source".into(),
                    })?;
                let mut ops = vec![PreparedMount {
                    source: Some(cstring(source.as_os_str(), "bind source")?),
                    target: target.clone(),
                    fstype: None,
                    data: None,
                    flags: libc::MS_BIND | libc::MS_REC,
                }];
                if readonly {
                    ops.push(PreparedMount {
                        source: None,
                        target,
                        fstype: None,
                        data: None,
                        flags: libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
                    });
                }
                Ok(ops)
            }
        }
    }
}

/// # Safety
///
/// Must run in the post-fork child with a live mount namespace; uses a raw
/// `mount(2)` on pre-built C strings.
unsafe fn mount_one(mount: &PreparedMount) -> io::Result<()> {
    let source = mount
        .source
        .as_ref()
        .map_or(std::ptr::null(), |source| source.as_ptr());
    let fstype = mount
        .fstype
        .as_ref()
        .map_or(std::ptr::null(), |fstype| fstype.as_ptr());
    let data = mount
        .data
        .as_ref()
        .map_or(std::ptr::null(), |data| data.as_ptr());
    let result = unsafe {
        libc::mount(
            source,
            mount.target.as_ptr(),
            fstype,
            mount.flags,
            data as *const libc::c_void,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `CString` from an `OsStr`, reporting interior NULs as a typed error.
fn cstring(value: &OsStr, what: &str) -> ForgeResult<CString> {
    CString::new(value.as_bytes().to_vec()).map_err(|_| ForgeError::MountFailed {
        target: value.to_string_lossy().to_string(),
        message: format!("{what} contains a NUL byte"),
    })
}

fn mapping_cstring(id: u32) -> CString {
    CString::new(format!("0 {id} 1\n")).unwrap_or_default()
}

/// Strip the leading `/` of an absolute host path to get a forge-relative path.
fn strip_root(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let mut relative = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(part) => relative.push(part),
            _ => return None,
        }
    }
    if relative.as_os_str().is_empty() {
        None
    } else {
        Some(relative)
    }
}

fn component_count(path: &Path) -> usize {
    path.components().count()
}

/// Quote a string for safe interpolation into a POSIX shell script.
pub fn shell_quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

fn ignore_missing(result: io::Result<()>) -> io::Result<()> {
    match result {
        Ok(()) => Ok(()),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
        Err(error) => Err(error),
    }
}

/// # Safety
///
/// Only safe in the post-fork, pre-exec child: uses `open`/`write`/`close` on a
/// static path and a caller-owned buffer.
unsafe fn write_small_file(path: &CStr, data: &[u8]) -> io::Result<()> {
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        match write_all_fd(fd, data) {
            Ok(()) => {
                libc::close(fd);
                Ok(())
            }
            Err(error) => {
                libc::close(fd);
                Err(error)
            }
        }
    }
}

/// # Safety
///
/// Writes `data` to an open file descriptor; async-signal-safe by construction.
unsafe fn write_all_fd(fd: libc::c_int, data: &[u8]) -> io::Result<()> {
    let mut written = 0usize;
    while written < data.len() {
        let result = unsafe {
            libc::write(
                fd,
                data[written..].as_ptr() as *const libc::c_void,
                data.len() - written,
            )
        };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(error);
        }
        if result == 0 {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        written += result as usize;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::HashAlgorithm;
    use std::os::unix::fs::PermissionsExt;

    fn blueprint_with_output(boot: &Path) -> ForgeBlueprint {
        ForgeBlueprint {
            tools: Vec::new(),
            hooks: Vec::new(),
            binds: Vec::new(),
            output: super::super::blueprint::ForgeOutput {
                dir: boot.to_path_buf(),
                name: "initramfs.img".into(),
                preset: None,
                kernel: None,
            },
        }
    }

    fn fixture() -> (tempfile::TempDir, CasRepository, ForgeBlueprint) {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cas = CasRepository::open(dir.path().join("repo"), HashAlgorithm::Blake3).expect("cas");
        let payload = dir.path().join("payload");
        fs::create_dir_all(payload.join("usr/bin")).expect("payload dirs");
        fs::write(payload.join("usr/bin/mkinitcpio"), "#!/bin/sh\n").expect("payload file");
        fs::set_permissions(
            payload.join("usr/bin/mkinitcpio"),
            fs::Permissions::from_mode(0o755),
        )
        .expect("chmod");
        let hash = cas.store_directory(&payload).expect("store");

        let boot = dir.path().join("boot");
        fs::create_dir_all(&boot).expect("boot dir");
        let mut blueprint = blueprint_with_output(&boot);
        blueprint.tools.push(super::super::blueprint::ForgeTool {
            name: "mkinitcpio".into(),
            object: hash,
            exec: Some(PathBuf::from("usr/bin/mkinitcpio")),
        });
        (dir, cas, blueprint)
    }

    fn plan_for(
        dir: &Path,
        cas: &CasRepository,
        blueprint: &ForgeBlueprint,
        options: &MountPlanOptions,
    ) -> MountPlan {
        let scratch = dir.join("scratch");
        fs::create_dir_all(&scratch).expect("scratch");
        MountPlan::build_with(blueprint, cas, &scratch, options).expect("plan")
    }

    #[test]
    fn test_build_layout_and_tool_program() {
        let (dir, cas, blueprint) = fixture();
        let plan = plan_for(dir.path(), &cas, &blueprint, &MountPlanOptions::minimal());

        assert_eq!(plan.root(), dir.path().join("scratch/forge"));
        // tmpfs + tool bind + output bind
        assert_eq!(plan.mounts().len(), 3);
        assert!(matches!(plan.mounts()[0].kind, MountKind::Tmpfs { .. }));

        let tool = plan.tool_program("mkinitcpio").expect("tool program");
        assert_eq!(
            tool,
            plan.root()
                .join("opt/extos/tools/mkinitcpio/usr/bin/mkinitcpio")
        );
        assert_eq!(plan.output_dir_in_forge(), plan.root().join("out"));
        assert_eq!(
            plan.output_in_forge("initramfs.img"),
            plan.root().join("out/initramfs.img")
        );
        assert_eq!(
            plan.in_forge("etc/mkinitcpio.conf"),
            plan.root().join("etc/mkinitcpio.conf")
        );
    }

    #[test]
    fn test_describe_order_puts_tmpfs_first_then_dirs_then_binds() {
        let (dir, cas, blueprint) = fixture();
        let plan = plan_for(dir.path(), &cas, &blueprint, &MountPlanOptions::minimal());
        let lines = plan.describe();
        assert!(lines[0].starts_with("tmpfs "), "{lines:?}");
        let first_mkdir = lines
            .iter()
            .position(|line| line.starts_with("mkdir "))
            .expect("mkdir");
        let first_bind = lines
            .iter()
            .position(|line| line.starts_with("bind "))
            .expect("bind");
        assert!(first_mkdir < first_bind, "{lines:?}");
        assert!(
            lines[first_bind].contains("opt/extos/tools/mkinitcpio"),
            "{lines:?}"
        );
        let rw = lines
            .iter()
            .find(|line| line.starts_with("bind rw "))
            .expect("rw output bind");
        assert!(rw.ends_with("/out"), "{rw}");
    }

    #[test]
    fn test_script_creates_directories_after_tmpfs_before_binds() {
        let (dir, cas, blueprint) = fixture();
        let plan = plan_for(dir.path(), &cas, &blueprint, &MountPlanOptions::minimal());
        let script = plan.mount_script();
        let tmpfs_at = script.find("mount -t tmpfs").expect("tmpfs");
        let mkdir_at = script.find("mkdir -p ").expect("mkdir");
        let bind_at = script.find("mount --bind ").expect("bind");
        assert!(tmpfs_at < mkdir_at, "{script}");
        assert!(mkdir_at < bind_at, "{script}");
        assert!(script.contains("mount -o remount,ro,bind "), "{script}");
        assert!(script.contains("size=536870912"), "{script}");
    }

    #[test]
    fn test_missing_object_is_typed() {
        let (dir, cas, mut blueprint) = fixture();
        blueprint.tools.push(super::super::blueprint::ForgeTool {
            name: "ghost".into(),
            object: "BLAKE3-deadbeef".into(),
            exec: None,
        });
        let scratch = dir.path().join("scratch");
        fs::create_dir_all(&scratch).expect("scratch");
        match MountPlan::build_with(&blueprint, &cas, &scratch, &MountPlanOptions::minimal()) {
            Err(ForgeError::ObjectNotFound { object }) => assert_eq!(object, "BLAKE3-deadbeef"),
            other => panic!("expected ObjectNotFound, got {other:?}"),
        }
    }

    #[test]
    fn test_missing_exec_payload_is_typed() {
        let (dir, cas, mut blueprint) = fixture();
        blueprint.tools[0].exec = Some(PathBuf::from("usr/bin/nope"));
        let scratch = dir.path().join("scratch");
        fs::create_dir_all(&scratch).expect("scratch");
        match MountPlan::build_with(&blueprint, &cas, &scratch, &MountPlanOptions::minimal()) {
            Err(ForgeError::ToolMissing { tool, path, .. }) => {
                assert_eq!(tool, "mkinitcpio");
                assert_eq!(path, "usr/bin/nope");
            }
            other => panic!("expected ToolMissing, got {other:?}"),
        }
    }

    #[test]
    fn test_missing_output_dir_is_typed() {
        let (dir, cas, mut blueprint) = fixture();
        blueprint.output.dir = dir.path().join("no-such-boot");
        let scratch = dir.path().join("scratch");
        fs::create_dir_all(&scratch).expect("scratch");
        match MountPlan::build_with(&blueprint, &cas, &scratch, &MountPlanOptions::minimal()) {
            Err(ForgeError::SourceMissing { path }) => {
                assert!(path.contains("no-such-boot"), "{path}")
            }
            other => panic!("expected SourceMissing, got {other:?}"),
        }
    }

    #[test]
    fn test_host_runtime_dirs_are_stripped_and_mounted_ro() {
        let options = MountPlanOptions {
            host_runtime_dirs: vec![PathBuf::from("/usr")],
            ..MountPlanOptions::minimal()
        };
        let (dir, cas, blueprint) = fixture();
        let plan = plan_for(dir.path(), &cas, &blueprint, &options);
        let usr = plan
            .mounts()
            .iter()
            .find(|mount| mount.target == plan.root().join("usr"))
            .expect("usr bind");
        assert_eq!(usr.source.as_deref(), Some(Path::new("/usr")));
        assert_eq!(usr.kind, MountKind::Bind { readonly: true });
    }

    #[test]
    fn test_nested_mount_targets_rejected() {
        let (dir, cas, mut blueprint) = fixture();
        blueprint.binds.push(super::super::blueprint::ForgeBind {
            source: PathBuf::from("/usr"),
            target: PathBuf::from("opt"),
            readonly: true,
        });
        let scratch = dir.path().join("scratch");
        fs::create_dir_all(&scratch).expect("scratch");
        match MountPlan::build_with(&blueprint, &cas, &scratch, &MountPlanOptions::minimal()) {
            Err(ForgeError::MountFailed { message, .. }) => {
                assert!(message.contains("nested"), "{message}")
            }
            other => panic!("expected nested-mount rejection, got {other:?}"),
        }
    }

    #[test]
    fn test_hook_script_is_bound_into_initcpio_tree() {
        let (dir, cas, mut blueprint) = fixture();
        let hook_payload = dir.path().join("hook");
        fs::create_dir_all(hook_payload.join("usr/lib/initcpio/install")).expect("hook dirs");
        fs::write(
            hook_payload.join("usr/lib/initcpio/install/base"),
            "#!/bin/sh\n",
        )
        .expect("hook file");
        let hook_hash = cas.store_directory(&hook_payload).expect("store hook");
        blueprint.hooks.push(super::super::blueprint::ForgeHook {
            name: "base".into(),
            kind: HookKind::Install,
            object: Some(hook_hash),
            path: Some(PathBuf::from("usr/lib/initcpio/install/base")),
        });
        blueprint.hooks.push(super::super::blueprint::ForgeHook {
            name: "udev".into(),
            kind: HookKind::Install,
            object: None,
            path: None,
        });

        let plan = plan_for(dir.path(), &cas, &blueprint, &MountPlanOptions::minimal());
        assert_eq!(plan.hooks(), ["base", "udev"]);
        let hook_mount = plan
            .mounts()
            .iter()
            .find(|mount| mount.target.ends_with("etc/initcpio/install/base"))
            .expect("hook mount");
        assert_eq!(hook_mount.kind, MountKind::Bind { readonly: true });
        // The hook is a file, so it must be created as an empty file target.
        assert!(
            plan.describe()
                .iter()
                .any(|line| line.starts_with("touch ") && line.contains("install/base")),
            "{:?}",
            plan.describe()
        );
    }

    #[test]
    fn test_inline_file_staging_and_script() {
        let (dir, cas, blueprint) = fixture();
        let mut plan = plan_for(dir.path(), &cas, &blueprint, &MountPlanOptions::minimal());
        let conf = plan.in_forge("etc/mkinitcpio.conf");
        plan.stage_inline_file(&conf, "HOOKS=(base)\n")
            .expect("stage");

        let lines = plan.describe();
        assert!(
            lines.iter().any(|line| line.contains("write ")),
            "{lines:?}"
        );
        let script = plan.mount_script();
        assert!(script.starts_with("set -e\n"), "{script}");
        assert!(script.contains("HOOKS=(base)"), "{script}");
        let mkdir_at = script.find("mkdir -p ").expect("mkdir");
        let write_at = script.find("printf '%s'").expect("write");
        assert!(mkdir_at < write_at, "{script}");
    }

    #[test]
    fn test_inline_file_outside_root_rejected() {
        let (dir, cas, blueprint) = fixture();
        let mut plan = plan_for(dir.path(), &cas, &blueprint, &MountPlanOptions::minimal());
        match plan.stage_inline_file(Path::new("/etc/passwd"), "x") {
            Err(ForgeError::MountFailed { message, .. }) => {
                assert!(message.contains("forge root"), "{message}")
            }
            other => panic!("expected rejection, got {other:?}"),
        }
        match plan.stage_inline_file(Path::new("relative.conf"), "x") {
            Err(ForgeError::MountFailed { .. }) => {}
            other => panic!("expected rejection, got {other:?}"),
        }
    }

    #[test]
    fn test_shell_quote_escapes_single_quotes() {
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
        assert_eq!(shell_quote("$HOME `x`"), "'$HOME `x`'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn test_mount_describe_forms() {
        let bind = ForgeMount {
            kind: MountKind::Bind { readonly: true },
            source: Some(PathBuf::from("/usr")),
            target: PathBuf::from("/forge/usr"),
        };
        assert_eq!(bind.describe(), "bind ro /usr -> /forge/usr");
        let tmpfs = ForgeMount {
            kind: MountKind::Tmpfs {
                size: 1024,
                mode: 0o755,
            },
            source: None,
            target: PathBuf::from("/forge"),
        };
        assert_eq!(tmpfs.describe(), "tmpfs /forge size=1024 mode=755");
    }

    #[test]
    fn test_strip_root() {
        assert_eq!(strip_root(Path::new("/usr")), Some(PathBuf::from("usr")));
        assert_eq!(strip_root(Path::new("/a/b")), Some(PathBuf::from("a/b")));
        assert_eq!(strip_root(Path::new("/")), None);
        assert_eq!(strip_root(Path::new("relative")), None);
    }

    #[test]
    fn test_minimal_options_have_no_host_binds() {
        let options = MountPlanOptions::minimal();
        assert!(options.host_runtime_dirs.is_empty());
        assert_eq!(options.tmpfs_size, DEFAULT_TMPFS_SIZE);
        assert!(
            default_host_runtime_dirs().iter().all(|path| path.is_dir()),
            "default host dirs must be filtered to existing paths"
        );
    }

    #[test]
    fn test_build_is_deterministic() {
        let (dir, cas, blueprint) = fixture();
        let first = plan_for(dir.path(), &cas, &blueprint, &MountPlanOptions::minimal());
        let second = plan_for(dir.path(), &cas, &blueprint, &MountPlanOptions::minimal());
        assert_eq!(first.describe(), second.describe());
        assert_eq!(first.mount_script(), second.mount_script());
    }

    #[test]
    fn test_read_only_bind_expands_to_two_syscalls() {
        let (dir, cas, blueprint) = fixture();
        let mut plan = plan_for(dir.path(), &cas, &blueprint, &MountPlanOptions::minimal());
        // Rebuild through a stage call to make sure expansion is stable.
        let conf = plan.in_forge("etc/x.conf");
        plan.stage_inline_file(&conf, "x").expect("stage");
        let ro = plan
            .describe()
            .iter()
            .filter(|line| line.starts_with("bind ro "))
            .count();
        let rw = plan
            .describe()
            .iter()
            .filter(|line| line.starts_with("bind rw "))
            .count();
        assert_eq!(ro, 1, "tool bind");
        assert_eq!(rw, 1, "output bind");
    }
}
