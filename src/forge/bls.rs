//! Boot Loader Specification entries for the forge output (PLAN 4.2.4/4.2.5).
//!
//! [`BlsPlan`] turns *systems × kernels* metadata into an ordered set of
//! `loader/entries/<id>.conf` files and closes the Phase-2 residual recorded in
//! `PLAN.md`: **a fresh boot root gets a `loader.conf` whose `default` points at
//! the freshly written entry**. An existing `loader.conf` is never touched
//! unless the caller explicitly asks for it, so user edits survive.
//!
//! # Schema
//!
//! Rendering reuses [`crate::snapshot::generation::BlsEntry`], i.e. the same
//! `key value` serialiser the snapshot engine already uses:
//!
//! ```text
//! title ExtOS workstation 6.11.0-arch1-1
//! version 6.11.0-arch1-1
//! sort-key extos-workstation
//! linux /vmlinuz-linux
//! initrd /initramfs-linux.img
//! options root=UUID=… rw
//! ```
//!
//! Values are folded to one line by the shared renderer, so nothing in a title
//! or command line can inject extra fields.
//!
//! # Ids and naming (4.2.5)
//!
//! ```text
//! id        = extos-<system>-g<generation>-<kernel>   (sanitised, lower-bound 1 char)
//! file name = <id>.conf
//! ```
//!
//! Ids are derived only from blueprint metadata — no timestamps, no counters —
//! so a rerun of the same inputs produces byte-identical files. All characters
//! outside `[A-Za-z0-9._+-]` become `-`; two inputs that sanitise to the same id
//! are a hard [`ForgeError::BlsIdCollision`] error instead of a silent
//! overwrite.
//!
//! # Deterministic order
//!
//! Entries are ordered by generation **descending**, then system name
//! **ascending**, then kernel **declaration order** within the system (no
//! version parsing: `6.6.1-lts` listed first stays first). The first entry is
//! the newest one and is what `loader.conf` defaults to. The order is stable
//! across runs, independent of `read_dir` order, and driven purely by blueprint
//! metadata.
//!
//! # `loader.conf` policy
//!
//! | [`LoaderDefaultPolicy`] | Behaviour |
//! |-------------------------|-----------|
//! | `CreateIfMissing` (default) | create `loader.conf` with `default <newest>` only when absent |
//! | `Always` | rewrite just the `default` line, preserving `timeout`/`editor`/comments |
//! | `Never` | never touch `loader.conf` |

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::snapshot::generation::BlsEntry;

use super::{ForgeError, ForgeResult};

/// Subdirectory of the boot root that holds the BLS entries.
pub const ENTRIES_SUBDIR: &str = "loader/entries";

/// File name of the bootloader configuration inside the boot root.
pub const LOADER_CONF: &str = "loader/loader.conf";

/// Default BLS `title` prefix.
pub const DEFAULT_TITLE_PREFIX: &str = "ExtOS";

/// Default BLS `sort-key` prefix.
pub const DEFAULT_SORT_KEY_PREFIX: &str = "extos";

/// Maximum length of a system name in a BLS id.
pub const MAX_SYSTEM_NAME_LEN: usize = 64;

/// One kernel a system can boot.
#[derive(Debug, Clone)]
pub struct BootKernel {
    /// Kernel version, used as the BLS `version` field.
    pub kernel: String,
    /// Kernel image path, emitted verbatim (boot-relative like `/vmlinuz-linux`
    /// or absolute — nothing here resolves a rootfs layout).
    pub linux: PathBuf,
    /// Initramfs images; repeatable `initrd` lines.
    pub initrd: Vec<PathBuf>,
    /// Kernel command line for this kernel.
    pub options: Option<String>,
}

impl BootKernel {
    /// A kernel with `linux` and no initrd/options.
    pub fn new(kernel: impl Into<String>, linux: impl Into<PathBuf>) -> Self {
        Self {
            kernel: kernel.into(),
            linux: linux.into(),
            initrd: Vec::new(),
            options: None,
        }
    }
}

/// One ExtOS system (a `/runlevel/1/<system>` tree) and its kernels.
#[derive(Debug, Clone)]
pub struct BlsSystem {
    /// System name (also used in the entry id and `sort-key`).
    pub system: String,
    /// Generation number; higher is newer and sorts first.
    pub generation: u64,
    /// Kernels this system boots, in declaration order.
    pub kernels: Vec<BootKernel>,
}

/// Knobs applied to every generated entry.
#[derive(Debug, Clone)]
pub struct BlsPlanOptions {
    /// Title prefix (`"ExtOS"` → `"ExtOS workstation 6.11…"`).
    pub title_prefix: String,
    /// `sort-key` prefix.
    pub sort_key_prefix: String,
    /// Extra kernel arguments appended to every entry.
    pub extra_options: Option<String>,
}

impl Default for BlsPlanOptions {
    fn default() -> Self {
        Self {
            title_prefix: DEFAULT_TITLE_PREFIX.into(),
            sort_key_prefix: DEFAULT_SORT_KEY_PREFIX.into(),
            extra_options: None,
        }
    }
}

/// One rendered matrix cell.
#[derive(Debug, Clone)]
pub struct BlsEntryPlan {
    /// Stable id (file stem).
    pub id: String,
    /// File name (`<id>.conf`).
    pub file_name: String,
    /// System name this entry boots.
    pub system: String,
    /// Kernel version.
    pub kernel: String,
    /// Generation number.
    pub generation: u64,
    /// Position of the kernel in its system's declaration list.
    pub kernel_index: usize,
    /// Rendered BLS content.
    pub entry: BlsEntry,
}

impl BlsEntryPlan {
    /// Rendered file content.
    pub fn render(&self) -> String {
        self.entry.render()
    }

    /// Human-readable identity used in collision messages.
    fn describe(&self) -> String {
        format!(
            "{} gen {} kernel {}",
            self.system, self.generation, self.kernel
        )
    }
}

/// An ordered, collision-free set of entries for one boot root.
#[derive(Debug, Clone)]
pub struct BlsPlan {
    entries: Vec<BlsEntryPlan>,
}

impl BlsPlan {
    /// Expand `systems` × their kernels into an ordered entry set (PLAN 4.2.5).
    pub fn from_systems(systems: &[BlsSystem], options: &BlsPlanOptions) -> ForgeResult<Self> {
        if systems.is_empty() {
            return Err(ForgeError::Bls {
                message: "at least one system is required to generate BLS entries".into(),
            });
        }

        let mut entries: Vec<BlsEntryPlan> = Vec::new();
        let mut seen: BTreeMap<String, String> = BTreeMap::new();

        for system in systems {
            if system.system.trim().is_empty() {
                return Err(ForgeError::Bls {
                    message: "system name must not be empty".into(),
                });
            }
            if system.system.len() > MAX_SYSTEM_NAME_LEN {
                return Err(ForgeError::Bls {
                    message: format!(
                        "system name '{}' exceeds {MAX_SYSTEM_NAME_LEN} characters",
                        system.system
                    ),
                });
            }
            if system.kernels.is_empty() {
                return Err(ForgeError::Bls {
                    message: format!("system '{}' declares no kernels", system.system),
                });
            }

            for (kernel_index, kernel) in system.kernels.iter().enumerate() {
                if kernel.kernel.trim().is_empty() {
                    return Err(ForgeError::Bls {
                        message: format!(
                            "system '{}' has a kernel without a version",
                            system.system
                        ),
                    });
                }
                if kernel.linux.as_os_str().is_empty() {
                    return Err(ForgeError::Bls {
                        message: format!(
                            "kernel '{}' of system '{}' has no linux image path",
                            kernel.kernel, system.system
                        ),
                    });
                }

                let id = entry_id(&system.system, system.generation, &kernel.kernel);
                let entry = BlsEntry {
                    title: format!(
                        "{} {} {}",
                        options.title_prefix, system.system, kernel.kernel
                    ),
                    version: kernel.kernel.clone(),
                    machine_id: None,
                    sort_key: Some(format!(
                        "{}-{}",
                        options.sort_key_prefix,
                        sanitize(&system.system)
                    )),
                    linux: kernel.linux.clone(),
                    initrd: kernel.initrd.clone(),
                    options: merge_options(
                        kernel.options.as_deref(),
                        options.extra_options.as_deref(),
                    ),
                };

                let plan = BlsEntryPlan {
                    file_name: format!("{id}.conf"),
                    id: id.clone(),
                    system: system.system.clone(),
                    kernel: kernel.kernel.clone(),
                    generation: system.generation,
                    kernel_index,
                    entry,
                };

                if let Some(first) = seen.insert(id.clone(), plan.describe()) {
                    return Err(ForgeError::BlsIdCollision {
                        id,
                        first,
                        second: plan.describe(),
                    });
                }
                entries.push(plan);
            }
        }

        entries.sort_by(|a, b| {
            b.generation
                .cmp(&a.generation)
                .then_with(|| a.system.cmp(&b.system))
                .then_with(|| a.kernel_index.cmp(&b.kernel_index))
                .then_with(|| a.id.cmp(&b.id))
        });

        Ok(Self { entries })
    }

    /// Ordered entries (newest first).
    pub fn entries(&self) -> &[BlsEntryPlan] {
        &self.entries
    }

    /// Id of the entry `loader.conf` should default to (the newest one).
    pub fn default_id(&self) -> Option<&str> {
        self.entries.first().map(|entry| entry.id.as_str())
    }

    /// Write every entry and apply the `loader.conf` policy.
    pub fn write(&self, boot_root: &Path, options: &BlsWriteOptions) -> ForgeResult<BlsReport> {
        let entries_dir = entries_dir(boot_root);
        fs::create_dir_all(&entries_dir)?;

        let mut written = Vec::new();
        let mut unchanged = Vec::new();
        for entry in &self.entries {
            let path = entries_dir.join(&entry.file_name);
            let content = entry.render();
            let already_identical = match fs::read_to_string(&path) {
                Ok(existing) => existing == content,
                Err(_) => false,
            };
            if already_identical {
                unchanged.push(path);
                continue;
            }
            write_atomic(&path, content.as_bytes())?;
            written.push(path);
        }

        let default = self.default_id().map(str::to_string);
        let loader_conf = match options.loader_default {
            LoaderDefaultPolicy::Never => LoaderConfAction::Disabled,
            LoaderDefaultPolicy::CreateIfMissing => {
                let path = loader_conf_path(boot_root);
                if path.exists() {
                    LoaderConfAction::Preserved {
                        current_default: read_loader_default(boot_root)?,
                        path,
                    }
                } else if let Some(id) = &default {
                    write_atomic(
                        &path,
                        format!(
                            "# Generated once by the ExtOS forge (PLAN 4.2.4).\n\
                             # Edits are preserved; `extos` never rewrites this file unless asked.\n\
                             default {id}\n"
                        )
                        .as_bytes(),
                    )?;
                    LoaderConfAction::Created(path)
                } else {
                    LoaderConfAction::Disabled
                }
            }
            LoaderDefaultPolicy::Always => match &default {
                Some(id) => {
                    let path = set_loader_default(boot_root, id)?;
                    LoaderConfAction::Created(path)
                }
                None => LoaderConfAction::Disabled,
            },
        };

        Ok(BlsReport {
            written,
            unchanged,
            default,
            loader_conf,
        })
    }
}

/// What to do with `<boot>/loader/loader.conf`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoaderDefaultPolicy {
    /// Create the file with `default <newest>` only when it does not exist.
    CreateIfMissing,
    /// Rewrite only the `default` line, preserving everything else.
    Always,
    /// Never touch the file.
    Never,
}

impl Default for LoaderDefaultPolicy {
    fn default() -> Self {
        Self::CreateIfMissing
    }
}

/// Write options for [`BlsPlan::write`].
#[derive(Debug, Clone, Default)]
pub struct BlsWriteOptions {
    /// `loader.conf` policy.
    pub loader_default: LoaderDefaultPolicy,
}

impl BlsWriteOptions {
    /// Options creating `loader.conf` only when missing (the default rule).
    pub fn create_if_missing() -> Self {
        Self::default()
    }

    /// Options that force `loader.conf` to point at the newest entry.
    pub fn always() -> Self {
        Self {
            loader_default: LoaderDefaultPolicy::Always,
        }
    }

    /// Options that leave `loader.conf` alone.
    pub fn never() -> Self {
        Self {
            loader_default: LoaderDefaultPolicy::Never,
        }
    }
}

/// What happened to `loader.conf`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoaderConfAction {
    /// The file was created or its `default` line rewritten.
    Created(PathBuf),
    /// An existing file was left untouched.
    Preserved {
        /// Path of the preserved file.
        path: PathBuf,
        /// Its current `default` value, if any.
        current_default: Option<String>,
    },
    /// The policy (or the absence of entries) left the file alone.
    Disabled,
}

/// Result of [`BlsPlan::write`].
#[derive(Debug, Clone)]
pub struct BlsReport {
    /// Entry files created or updated.
    pub written: Vec<PathBuf>,
    /// Entry files whose content was already identical.
    pub unchanged: Vec<PathBuf>,
    /// Id `loader.conf` points at (the newest entry), if any.
    pub default: Option<String>,
    /// What happened to `loader.conf`.
    pub loader_conf: LoaderConfAction,
}

impl BlsReport {
    /// Total number of entry files after the write.
    pub fn total(&self) -> usize {
        self.written.len() + self.unchanged.len()
    }
}

/// `<boot>/loader/entries`.
pub fn entries_dir(boot_root: &Path) -> PathBuf {
    boot_root.join(ENTRIES_SUBDIR)
}

/// `<boot>/loader/loader.conf`.
pub fn loader_conf_path(boot_root: &Path) -> PathBuf {
    boot_root.join(LOADER_CONF)
}

/// Read the `default` value from `<boot>/loader/loader.conf`, if present.
///
/// Comments (`#…`) and blank lines are ignored; `default` may be followed by
/// anything the bootloader accepts (an id or a glob).
pub fn read_loader_default(boot_root: &Path) -> ForgeResult<Option<String>> {
    let path = loader_conf_path(boot_root);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    Ok(text.lines().find_map(|line| {
        let line = line.trim();
        if line.starts_with('#') {
            return None;
        }
        let rest = line.strip_prefix("default")?;
        if !rest.starts_with(char::is_whitespace) {
            return None;
        }
        let value = rest.trim();
        (!value.is_empty()).then(|| value.to_string())
    }))
}

/// Explicitly point `<boot>/loader/loader.conf` at `id`.
///
/// Only the `default` line is replaced; every other line (comments, `timeout`,
/// `editor`, …) is preserved. A missing file is created.
pub fn set_loader_default(boot_root: &Path, id: &str) -> ForgeResult<PathBuf> {
    let path = loader_conf_path(boot_root);
    let existing = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error.into()),
    };

    let mut lines: Vec<String> = Vec::new();
    let mut replaced = false;
    for line in existing.lines() {
        let trimmed = line.trim_start();
        let is_default = !trimmed.starts_with('#')
            && trimmed
                .strip_prefix("default")
                .is_some_and(|rest| rest.starts_with(char::is_whitespace));
        if is_default {
            if !replaced {
                lines.push(format!("default {id}"));
                replaced = true;
            }
            continue;
        }
        lines.push(line.to_string());
    }
    if !replaced {
        lines.push(format!("default {id}"));
    }
    let mut body = lines.join("\n");
    body.push('\n');

    fs::create_dir_all(boot_root.join("loader"))?;
    write_atomic(&path, body.as_bytes())?;
    Ok(path)
}

/// Stable id for one matrix cell.
pub fn entry_id(system: &str, generation: u64, kernel: &str) -> String {
    format!(
        "extos-{}-g{generation}-{}",
        sanitize(system),
        sanitize(kernel)
    )
}

/// Fold anything outside `[A-Za-z0-9._+-]` to `-`, collapsing runs and trimming
/// the edges so ids stay portable file names.
///
/// Note that trimming is byte-wise at the edges of the folded result: leading
/// and trailing multibyte characters fold to `-` and are then folded away, so
/// `"ümlaut"` becomes `"mlaut"` — and two distinct inputs can therefore
/// sanitise to the same id. Such a collision is not silently merged; the
/// caller receives a typed [`ForgeError::BlsIdCollision`].
pub fn sanitize(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        let mapped = if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '+' | '-') {
            ch
        } else {
            '-'
        };
        if mapped == '-' && out.ends_with('-') {
            continue;
        }
        out.push(mapped);
    }
    out.trim_matches('-').to_string()
}

fn merge_options(kernel: Option<&str>, extra: Option<&str>) -> Option<String> {
    match (kernel, extra) {
        (Some(kernel), Some(extra)) => Some(format!("{kernel} {extra}")),
        (Some(kernel), None) => Some(kernel.to_string()),
        (None, Some(extra)) => Some(extra.to_string()),
        (None, None) => None,
    }
}

fn write_atomic(path: &Path, content: &[u8]) -> ForgeResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "entry".into());
    let tmp = path.with_file_name(format!(".{file_name}.tmp-{}", std::process::id()));
    {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(content)?;
        file.sync_all()?;
    }
    if let Err(error) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(error.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn systems() -> Vec<BlsSystem> {
        vec![
            BlsSystem {
                system: "workstation".into(),
                generation: 7,
                kernels: vec![
                    {
                        let mut kernel = BootKernel::new("6.11.0", "/vmlinuz-linux");
                        kernel.initrd.push(PathBuf::from("/initramfs-linux.img"));
                        kernel.options = Some("root=UUID=abc rw".into());
                        kernel
                    },
                    BootKernel::new("6.10.0", "/vmlinuz-linux-lts"),
                ],
            },
            BlsSystem {
                system: "server".into(),
                generation: 7,
                kernels: vec![BootKernel::new("6.11.0", "/vmlinuz-server")],
            },
            BlsSystem {
                system: "workstation".into(),
                generation: 8,
                kernels: vec![BootKernel::new("6.11.0", "/vmlinuz-linux")],
            },
        ]
    }

    #[test]
    fn test_matrix_ids_and_ordering() {
        let plan = BlsPlan::from_systems(&systems(), &BlsPlanOptions::default()).expect("plan");
        let ids: Vec<&str> = plan.entries().iter().map(|e| e.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "extos-workstation-g8-6.11.0", // newest generation first
                "extos-server-g7-6.11.0",      // then system name ascending
                "extos-workstation-g7-6.11.0",
                "extos-workstation-g7-6.10.0", // then kernel declaration order
            ]
        );
        assert_eq!(plan.default_id(), Some("extos-workstation-g8-6.11.0"));
    }

    #[test]
    fn test_kernel_order_follows_declaration_not_version_string() {
        let systems = vec![BlsSystem {
            system: "edge".into(),
            generation: 1,
            // "6.6.1" sorts *after* "6.11.0" lexicographically; declaration
            // order must win so the blueprint author stays in control.
            kernels: vec![
                BootKernel::new("6.6.1-lts", "/vmlinuz-lts"),
                BootKernel::new("6.11.0-arch1-1", "/vmlinuz"),
            ],
        }];
        let plan = BlsPlan::from_systems(&systems, &BlsPlanOptions::default()).expect("plan");
        let ids: Vec<&str> = plan
            .entries()
            .iter()
            .map(|entry| entry.id.as_str())
            .collect();
        assert_eq!(
            ids,
            vec!["extos-edge-g1-6.6.1-lts", "extos-edge-g1-6.11.0-arch1-1"]
        );
        assert_eq!(plan.default_id(), Some("extos-edge-g1-6.6.1-lts"));
    }

    #[test]
    fn test_rendered_entry_schema() {
        let plan = BlsPlan::from_systems(&systems(), &BlsPlanOptions::default()).expect("plan");
        let entry = plan
            .entries()
            .iter()
            .find(|entry| entry.id == "extos-workstation-g7-6.11.0")
            .expect("entry");
        let text = entry.render();
        assert_eq!(
            text,
            "title ExtOS workstation 6.11.0\n\
             version 6.11.0\n\
             sort-key extos-workstation\n\
             linux /vmlinuz-linux\n\
             initrd /initramfs-linux.img\n\
             options root=UUID=abc rw\n"
        );
        assert_eq!(entry.file_name, "extos-workstation-g7-6.11.0.conf");
    }

    #[test]
    fn test_extra_options_are_appended() {
        let options = BlsPlanOptions {
            extra_options: Some("quiet".into()),
            ..BlsPlanOptions::default()
        };
        let plan = BlsPlan::from_systems(&systems(), &options).expect("plan");
        let text = plan
            .entries()
            .iter()
            .find(|entry| entry.id == "extos-workstation-g7-6.11.0")
            .expect("entry")
            .render();
        assert!(text.contains("options root=UUID=abc rw quiet"), "{text}");

        let bare = plan
            .entries()
            .iter()
            .find(|entry| entry.id == "extos-server-g7-6.11.0")
            .expect("entry")
            .render();
        assert!(bare.contains("options quiet"), "{bare}");
    }

    #[test]
    fn test_ids_are_stable_and_sanitised() {
        assert_eq!(
            entry_id("work station", 3, "6.11.0-arch1-1"),
            "extos-work-station-g3-6.11.0-arch1-1"
        );
        assert_eq!(sanitize("a//b"), "a-b");
        assert_eq!(sanitize("--a--b--"), "a-b");
        // Non-portable characters fold to '-' and leading/trailing dashes are trimmed.
        assert_eq!(sanitize("ümlaut"), "mlaut");
        assert_eq!(sanitize("6.11.0_1+2"), "6.11.0_1+2");
        // Same inputs, same id — no time or counter component.
        assert_eq!(entry_id("s", 1, "k"), entry_id("s", 1, "k"));
    }

    #[test]
    fn test_collision_is_typed() {
        let systems = vec![BlsSystem {
            system: "s".into(),
            generation: 1,
            kernels: vec![BootKernel::new("6.1", "/a"), BootKernel::new("6.1", "/b")],
        }];
        match BlsPlan::from_systems(&systems, &BlsPlanOptions::default()) {
            Err(ForgeError::BlsIdCollision { id, first, second }) => {
                assert_eq!(id, "extos-s-g1-6.1");
                assert!(first.contains("6.1"), "{first}");
                assert!(second.contains("6.1"), "{second}");
            }
            other => panic!("expected collision, got {other:?}"),
        }
    }

    #[test]
    fn test_sanitised_collision_is_typed() {
        let systems = vec![BlsSystem {
            system: "s".into(),
            generation: 1,
            kernels: vec![
                BootKernel::new("6.1/x", "/a"),
                BootKernel::new("6.1:x", "/b"),
            ],
        }];
        assert!(matches!(
            BlsPlan::from_systems(&systems, &BlsPlanOptions::default()),
            Err(ForgeError::BlsIdCollision { .. })
        ));
    }

    #[test]
    fn test_empty_inputs_are_typed() {
        assert!(matches!(
            BlsPlan::from_systems(&[], &BlsPlanOptions::default()),
            Err(ForgeError::Bls { .. })
        ));
        let no_kernels = vec![BlsSystem {
            system: "s".into(),
            generation: 1,
            kernels: Vec::new(),
        }];
        assert!(matches!(
            BlsPlan::from_systems(&no_kernels, &BlsPlanOptions::default()),
            Err(ForgeError::Bls { .. })
        ));
        let empty_name = vec![BlsSystem {
            system: "  ".into(),
            generation: 1,
            kernels: vec![BootKernel::new("k", "/x")],
        }];
        assert!(matches!(
            BlsPlan::from_systems(&empty_name, &BlsPlanOptions::default()),
            Err(ForgeError::Bls { .. })
        ));
    }

    #[test]
    fn test_write_creates_entries_and_loader_conf() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let boot = dir.path().join("boot");
        let plan = BlsPlan::from_systems(&systems(), &BlsPlanOptions::default()).expect("plan");
        let report = plan
            .write(&boot, &BlsWriteOptions::create_if_missing())
            .expect("write");

        assert_eq!(report.written.len(), 4);
        assert!(report.unchanged.is_empty());
        assert_eq!(
            report.default.as_deref(),
            Some("extos-workstation-g8-6.11.0")
        );

        let entries = entries_dir(&boot);
        assert!(entries.join("extos-workstation-g8-6.11.0.conf").is_file());
        assert!(entries.join("extos-workstation-g7-6.10.0.conf").is_file());
        assert_eq!(
            read_loader_default(&boot).expect("read"),
            Some("extos-workstation-g8-6.11.0".into())
        );
        assert!(matches!(report.loader_conf, LoaderConfAction::Created(_)));
    }

    #[test]
    fn test_rerun_is_idempotent() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let boot = dir.path().join("boot");
        let plan = BlsPlan::from_systems(&systems(), &BlsPlanOptions::default()).expect("plan");
        plan.write(&boot, &BlsWriteOptions::create_if_missing())
            .expect("first");

        let entry = entries_dir(&boot).join("extos-workstation-g7-6.11.0.conf");
        let before = fs::metadata(&entry).expect("metadata").modified().ok();
        let loader_before = fs::read_to_string(loader_conf_path(&boot)).expect("loader");

        let report = plan
            .write(&boot, &BlsWriteOptions::create_if_missing())
            .expect("second");
        assert!(report.written.is_empty(), "{report:?}");
        assert_eq!(report.unchanged.len(), 4);
        assert!(matches!(
            report.loader_conf,
            LoaderConfAction::Preserved { .. }
        ));
        assert_eq!(
            fs::read_to_string(loader_conf_path(&boot)).expect("loader"),
            loader_before
        );
        let after = fs::metadata(&entry).expect("metadata").modified().ok();
        assert_eq!(before, after, "unchanged entries must not be rewritten");
    }

    #[test]
    fn test_existing_loader_conf_is_preserved() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let boot = dir.path().join("boot");
        fs::create_dir_all(boot.join("loader")).expect("loader dir");
        let custom = "default other\n# hand written\ntimeout 5\n";
        fs::write(loader_conf_path(&boot), custom).expect("loader.conf");

        let plan = BlsPlan::from_systems(&systems(), &BlsPlanOptions::default()).expect("plan");
        let report = plan
            .write(&boot, &BlsWriteOptions::create_if_missing())
            .expect("write");

        assert_eq!(
            report.loader_conf,
            LoaderConfAction::Preserved {
                path: loader_conf_path(&boot),
                current_default: Some("other".into()),
            }
        );
        assert_eq!(
            fs::read_to_string(loader_conf_path(&boot)).expect("loader"),
            custom
        );
    }

    #[test]
    fn test_always_policy_rewrites_only_default() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let boot = dir.path().join("boot");
        fs::create_dir_all(boot.join("loader")).expect("loader dir");
        fs::write(
            loader_conf_path(&boot),
            "default stale\ntimeout 5\neditor 1\n",
        )
        .expect("loader.conf");

        let plan = BlsPlan::from_systems(&systems(), &BlsPlanOptions::default()).expect("plan");
        plan.write(&boot, &BlsWriteOptions::always())
            .expect("write");

        let text = fs::read_to_string(loader_conf_path(&boot)).expect("loader");
        assert_eq!(
            text,
            "default extos-workstation-g8-6.11.0\ntimeout 5\neditor 1\n"
        );
    }

    #[test]
    fn test_never_policy_leaves_loader_conf_absent() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let boot = dir.path().join("boot");
        let plan = BlsPlan::from_systems(&systems(), &BlsPlanOptions::default()).expect("plan");
        let report = plan.write(&boot, &BlsWriteOptions::never()).expect("write");
        assert_eq!(report.loader_conf, LoaderConfAction::Disabled);
        assert!(!loader_conf_path(&boot).exists());
        assert_eq!(report.written.len(), 4);
    }

    #[test]
    fn test_set_loader_default_appends_and_creates() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let boot = dir.path().join("boot");
        let path = set_loader_default(&boot, "extos-a").expect("set");
        assert_eq!(
            fs::read_to_string(&path).expect("read"),
            "default extos-a\n"
        );

        set_loader_default(&boot, "extos-b").expect("set");
        assert_eq!(
            fs::read_to_string(&path).expect("read"),
            "default extos-b\n"
        );
    }

    #[test]
    fn test_read_loader_default_ignores_comments_and_globs() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let boot = dir.path().join("boot");
        fs::create_dir_all(boot.join("loader")).expect("dir");
        fs::write(
            loader_conf_path(&boot),
            "# default nope\ndefaults x\ndefault extos-*\n",
        )
        .expect("write");
        assert_eq!(
            read_loader_default(&boot).expect("read"),
            Some("extos-*".into())
        );

        fs::write(loader_conf_path(&boot), "timeout 3\n").expect("write");
        assert_eq!(read_loader_default(&boot).expect("read"), None);
    }

    #[test]
    fn test_missing_loader_conf_reads_none() {
        let dir = tempfile::tempdir().expect("tmpdir");
        assert_eq!(read_loader_default(dir.path()).expect("read"), None);
    }

    #[test]
    fn test_report_total() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let plan = BlsPlan::from_systems(&systems(), &BlsPlanOptions::default()).expect("plan");
        let report = plan
            .write(
                &dir.path().join("boot"),
                &BlsWriteOptions::create_if_missing(),
            )
            .expect("write");
        assert_eq!(report.total(), 4);
    }
}
