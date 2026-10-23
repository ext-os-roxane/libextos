//! Selectable container backends (PLAN 4.4.9).
//!
//! ExtOS never hard-requires a container manager: the same
//! [`crate::container::launcher::LaunchSpec`] can be executed by
//!
//! | Backend | Mechanism | Levels | Notes |
//! |---------|-----------|--------|-------|
//! | [`Backend::Native`] | in-process `unshare`/`mount`/`chroot` via `pre_exec` | 0–4 | default; needs unprivileged user namespaces |
//! | [`Backend::Nspawn`] | `systemd-nspawn` (PATH) | 0–2 | cannot express host-network (3) or privileged (4); rootless needs `systemd-nsresourced` |
//! | [`Backend::Runc`] | `runc` (PATH) + generated OCI bundle | 0–3 | level 4 refused: an OCI bundle always keeps a mount namespace |
//! | [`Backend::Crun`] | `crun` (PATH) | — | auto-detected; reported **absent** on hosts without it |
//! | [`Backend::Chroot`] | `chroot(1)` (PATH) | 4 | filesystem isolation only — no namespaces at all |
//!
//! # Command-line templates
//!
//! *Native* (implemented in [`crate::container::namespace`], documented here for
//! completeness):
//!
//! ```text
//! unshare(CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWIPC|CLONE_NEWUTS[|CLONE_NEWNET])
//! write /proc/self/{setgroups,uid_map,gid_map}
//! mount --make-rprivate / ; mount -t tmpfs tmpfs <root> ; mount --bind <root>/<entry>
//! chroot <root> ; mount -t tmpfs /dev /tmp /run ; mount --bind sockets
//! fork → mount -t proc /proc ; setsid ; execve
//! ```
//!
//! *nspawn*:
//!
//! ```text
//! systemd-nspawn --quiet --machine=extos-<pid> --directory=<root>
//!                [--private-network] [--private-users=pick] [--resolv-conf=off]
//!                [--bind-ro=<socket>:<target>]… [--setenv=K=V]…
//!                --chdir=/ -- <program> <args>
//! ```
//!
//! *runc*: a bundle directory is generated (`config.json` + an absolute
//! `root.path`), then
//!
//! ```text
//! runc --root <state-dir> run --bundle <bundle> extos-<pid>
//! ```
//!
//! *chroot*:
//!
//! ```text
//! chroot <root> <program> <args>
//! ```
//!
//! # Probing
//!
//! [`BackendProbe::discover`] reports, on this host: unprivileged user namespace
//! support (probed by forking and calling `unshare(CLONE_NEWUSER)` in the child —
//! never in the calling process), plus the resolved paths of `systemd-nspawn`,
//! `runc`, `crun` and `chroot`, and which of those are absent.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::container::{ContainerError, IsolationLevel};
use crate::manifest::NamespaceToggles;

/// Which runtime executes the container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Backend {
    /// In-process namespaces (PLAN 4.4.2). Default and the only backend that
    /// works unprivileged on every kernel with user namespaces enabled.
    Native,
    /// `systemd-nspawn`, resolved from `PATH`.
    Nspawn(String),
    /// `runc`, resolved from `PATH`, driven through a generated OCI bundle.
    Runc(String),
    /// `crun` placeholder: auto-detected, and reported as absent on hosts that
    /// do not ship it (its command-line surface mirrors `runc`'s, so the bundle
    /// generator is shared).
    Crun(String),
    /// `chroot(1)`: filesystem isolation only, no namespaces. Level 4 only.
    Chroot(String),
}

/// The value `Backend::Native` uses for "no binary".
const NATIVE: &str = "native";

impl Backend {
    /// Canonical name used by [`Backend::from_env`] and diagnostics.
    pub fn as_str(&self) -> &'static str {
        match self {
            Backend::Native => NATIVE,
            Backend::Nspawn(_) => "nspawn",
            Backend::Runc(_) => "runc",
            Backend::Crun(_) => "crun",
            Backend::Chroot(_) => "chroot",
        }
    }

    /// The executable this backend drives, if any.
    pub fn binary(&self) -> Option<&str> {
        match self {
            Backend::Native => None,
            Backend::Nspawn(bin) | Backend::Runc(bin) | Backend::Crun(bin) | Backend::Chroot(bin) => {
                Some(bin.as_str())
            }
        }
    }

    /// Select a backend from `EXTOS_CONTAINER_BACKEND`
    /// (`native|nspawn|runc|crun|chroot`), resolving binaries through `PATH`.
    ///
    /// Unset or empty means [`Backend::Native`].
    pub fn from_env() -> Result<Self, ContainerError> {
        let raw = std::env::var("EXTOS_CONTAINER_BACKEND").unwrap_or_default();
        Self::from_name(raw.trim())
    }

    /// Resolve a backend by name, probing `PATH` for the external ones.
    pub fn from_name(name: &str) -> Result<Self, ContainerError> {
        match name {
            "" | NATIVE => Ok(Backend::Native),
            "nspawn" | "systemd-nspawn" => Ok(Backend::Nspawn(which("systemd-nspawn").ok_or_else(
                || ContainerError::BackendUnavailable("systemd-nspawn not found in PATH".into()),
            )?)),
            "runc" => Ok(Backend::Runc(which("runc").ok_or_else(|| {
                ContainerError::BackendUnavailable("runc not found in PATH".into())
            })?)),
            "crun" => Ok(Backend::Crun(which("crun").ok_or_else(|| {
                ContainerError::BackendUnavailable("crun not found in PATH".into())
            })?)),
            "chroot" => Ok(Backend::Chroot(which("chroot").ok_or_else(|| {
                ContainerError::BackendUnavailable("chroot not found in PATH".into())
            })?)),
            other => Err(ContainerError::BackendUnavailable(format!(
                "unknown container backend {other:?} (expected native, nspawn, runc, crun or chroot)"
            ))),
        }
    }

    /// Whether this backend can honour `level`, with the reason when it cannot.
    ///
    /// These are honest limits of the *templates* implemented here, not of the
    /// underlying tools in general.
    pub fn supports(&self, level: IsolationLevel) -> Result<(), ContainerError> {
        let refuse = |reason: &str| {
            Err(ContainerError::UnsupportedLevel {
                backend: self.as_str(),
                level: level.as_str(),
                reason: reason.to_string(),
            })
        };
        match self {
            Backend::Native => Ok(()),
            Backend::Nspawn(_) => match level {
                IsolationLevel::Isolated | IsolationLevel::Cli | IsolationLevel::Gui => Ok(()),
                IsolationLevel::Networked => refuse(
                    "the nspawn template cannot join the host network namespace without \
                     --network-namespace-path (root-only); use a native backend",
                ),
                IsolationLevel::Privileged => refuse(
                    "systemd-nspawn always creates namespaces; it cannot express level 4",
                ),
            },
            Backend::Runc(_) | Backend::Crun(_) => match level {
                IsolationLevel::Isolated
                | IsolationLevel::Cli
                | IsolationLevel::Gui
                | IsolationLevel::Networked => Ok(()),
                IsolationLevel::Privileged => refuse(
                    "an OCI bundle keeps at least a mount namespace; level 4 is refused",
                ),
            },
            Backend::Chroot(_) => match level {
                IsolationLevel::Privileged => Ok(()),
                _ => refuse(
                    "chroot(1) provides filesystem isolation only; it cannot create the \
                     namespaces levels 0–3 promise",
                ),
            },
        }
    }

    /// Probe this specific backend on the host.
    ///
    /// The full [`BackendProbe`] is returned (it describes every backend, not
    /// just this one) so a caller can print one coherent report.
    pub fn probe(&self) -> BackendProbe {
        BackendProbe::discover()
    }

    /// Whether a real run needs privileges the caller may not have.
    pub fn requires_root(&self) -> bool {
        matches!(self, Backend::Chroot(_))
    }
}

/// Locate `name` on `PATH` (first hit wins), returning the full path.
pub fn which(name: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let candidate = dir.join(name);
        if is_executable(&candidate) {
            return Some(candidate.display().to_string());
        }
    }
    None
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Varlink socket of `systemd-nsresourced`, systemd's user-namespace allocator.
///
/// Rootless `systemd-nspawn --user` acquires its UID range from this service and
/// fails with "User-scoped operation requires managed user namespaces" when the
/// socket is absent.
pub const NSRESOURCED_SOCKET: &str = "/run/systemd/io.systemd.NamespaceResource";

/// Whether `systemd-nsresourced` is reachable on this host.
pub fn nsresourced_available() -> bool {
    Path::new(NSRESOURCED_SOCKET).exists()
}

/// Result of probing the host for available backends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendProbe {
    /// Unprivileged user namespaces are usable (probed in a forked child).
    pub native_userns: bool,
    /// Resolved `systemd-nspawn`.
    pub nspawn: Option<String>,
    /// Resolved `runc`.
    pub runc: Option<String>,
    /// Resolved `crun`.
    pub crun: Option<String>,
    /// Resolved `chroot`.
    pub chroot: Option<String>,
    /// `systemd-nsresourced` is reachable (its varlink socket exists). Without
    /// it, rootless `systemd-nspawn --user` refuses to start because it cannot
    /// acquire a UID range.
    pub nsresourced: bool,
    /// Backends whose binary was not found.
    pub absent: Vec<&'static str>,
    /// Extra notes (kernel knobs that were read, probe failures, …).
    pub notes: Vec<String>,
}

impl BackendProbe {
    /// Probe the running host.
    pub fn discover() -> Self {
        let nspawn = which("systemd-nspawn");
        let runc = which("runc");
        let crun = which("crun");
        let chroot = which("chroot");

        let mut absent = Vec::new();
        if nspawn.is_none() {
            absent.push("nspawn");
        }
        if runc.is_none() {
            absent.push("runc");
        }
        if crun.is_none() {
            absent.push("crun");
        }
        if chroot.is_none() {
            absent.push("chroot");
        }

        let mut notes = Vec::new();
        for knob in [
            "/proc/sys/user/max_user_namespaces",
            "/proc/sys/kernel/unprivileged_userns_clone",
        ] {
            match std::fs::read_to_string(knob) {
                Ok(value) => notes.push(format!("{knob} = {}", value.trim())),
                Err(_) => notes.push(format!("{knob} not present")),
            }
        }

        let native_userns = probe_unprivileged_userns();
        if !native_userns {
            notes.push(
                "unprivileged user namespaces are unavailable; the native backend cannot run \
                 levels 0–3 on this host"
                    .to_string(),
            );
        }

        let nsresourced = nsresourced_available();
        if nspawn.is_some() && !nsresourced && unsafe { libc::geteuid() } != 0 {
            notes.push(format!(
                "systemd-nspawn is installed but {NSRESOURCED_SOCKET} is missing, so rootless \
                 nspawn (--user) cannot acquire a UID range on this host"
            ));
        }

        Self {
            native_userns,
            nspawn,
            runc,
            crun,
            chroot,
            nsresourced,
            absent,
            notes,
        }
    }

    /// The backend a request should default to on this host.
    pub fn preferred(&self) -> Backend {
        if self.native_userns {
            return Backend::Native;
        }
        if let Some(bin) = &self.runc {
            return Backend::Runc(bin.clone());
        }
        if let Some(bin) = &self.nspawn {
            if self.nsresourced || unsafe { libc::geteuid() } == 0 {
                return Backend::Nspawn(bin.clone());
            }
        }
        Backend::Native
    }

    /// A typed, human-readable report (printed by tests and `instanz --check`).
    pub fn report(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "native user namespaces: {}\n",
            if self.native_userns { "yes" } else { "no" }
        ));
        for (name, path) in [
            ("systemd-nspawn", &self.nspawn),
            ("runc", &self.runc),
            ("crun", &self.crun),
            ("chroot", &self.chroot),
        ] {
            out.push_str(&format!(
                "{name}: {}\n",
                path.clone().unwrap_or_else(|| "<absent>".to_string())
            ));
        }
        if !self.absent.is_empty() {
            out.push_str(&format!("absent: {}\n", self.absent.join(", ")));
        }
        out.push_str(&format!(
            "systemd-nsresourced: {}\n",
            if self.nsresourced { "yes" } else { "no" }
        ));
        for note in &self.notes {
            out.push_str(&format!("note: {note}\n"));
        }
        out
    }
}

/// Fork, call `unshare(CLONE_NEWUSER)` in the child, report whether it worked.
///
/// The calling process is never modified: `unshare` is irreversible, so the only
/// safe probe is a child that exits immediately.
pub fn probe_unprivileged_userns() -> bool {
    // SAFETY: fork/waitpid/exit only; the child performs two syscalls and exits
    // without touching the Rust runtime's allocator.
    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            return false;
        }
        if pid == 0 {
            let rc = libc::unshare(libc::CLONE_NEWUSER);
            libc::_exit(if rc == 0 { 0 } else { 1 });
        }
        let mut status: libc::c_int = 0;
        loop {
            let reaped = libc::waitpid(pid, &mut status, 0);
            if reaped == pid {
                break;
            }
            if reaped < 0 && *libc::__errno_location() != libc::EINTR {
                return false;
            }
        }
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    }
}

// ─── Command templates ─────────────────────────────────────────

/// A fully built command line for an external backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendTemplate {
    /// Executable to run.
    pub program: PathBuf,
    /// Arguments, in order.
    pub args: Vec<String>,
    /// OCI bundle directory, when the backend needs one.
    pub bundle: Option<PathBuf>,
    /// Bundle file written to disk (`config.json`).
    pub bundle_file: Option<(PathBuf, String)>,
    /// Notes worth surfacing to the caller.
    pub warnings: Vec<String>,
}

/// Inputs shared by every template.
pub struct TemplateRequest<'a> {
    /// Isolation level.
    pub level: IsolationLevel,
    /// Namespace toggles (already validated).
    pub namespaces: NamespaceToggles,
    /// Assembled rootfs.
    pub root: &'a Path,
    /// Program to run, absolute inside the container.
    pub program: &'a str,
    /// Program arguments.
    pub args: &'a [String],
    /// Container environment.
    pub env: &'a BTreeMap<String, String>,
    /// Container hostname.
    pub hostname: &'a str,
    /// Socket binds the GUI level assembled (`source` → `target`).
    pub socket_binds: &'a [(PathBuf, PathBuf)],
    /// Scratch directory for bundles and `runc` state.
    pub state_dir: &'a Path,
    /// Container identifier (used for bundle/state naming).
    pub id: &'a str,
}

/// Build the `systemd-nspawn` argument vector for `request`.
///
/// Split out as a pure function so the template can be asserted on any host,
/// including ones where rootless nspawn cannot actually start.
pub fn nspawn_args(request: &TemplateRequest<'_>, rootless: bool) -> Vec<String> {
    let mut args = vec![
        "--quiet".to_string(),
        format!("--machine=extos-{}", request.id),
        format!("--directory={}", request.root.display()),
        "--chdir=/".to_string(),
    ];
    if request.level != IsolationLevel::Networked {
        // `--private=network` was removed in systemd 262; the dedicated flag is
        // `--private-network`.
        args.push("--private-network".to_string());
    }
    if rootless {
        // Rootless nspawn refuses to start outside the per-user service manager
        // scope ("User-scoped operation requires managed user namespaces"):
        // `--user` opts into that scope and `--private-users=pick` allocates the
        // UID range from systemd-nsresourced.
        args.push("--user".to_string());
        args.push("--private-users=pick".to_string());
    }
    args.push("--resolv-conf=off".to_string());
    for (source, target) in request.socket_binds {
        args.push(format!("--bind-ro={}:{}", source.display(), target.display()));
    }
    for (key, value) in request.env {
        args.push(format!("--setenv={key}={value}"));
    }
    args.push("--".to_string());
    args.push(request.program.to_string());
    args.extend(request.args.iter().cloned());
    args
}

impl Backend {
    /// Build the command line for this backend.
    ///
    /// Returns a typed [`ContainerError::UnsupportedLevel`] when the template
    /// cannot express the request, so a bad combination fails before anything is
    /// spawned.
    pub fn template(&self, request: &TemplateRequest<'_>) -> Result<BackendTemplate, ContainerError> {
        self.supports(request.level)?;
        match self {
            Backend::Native => Ok(BackendTemplate {
                // The native backend never execs a manager; the launcher uses
                // `Command::new(program)` plus `pre_exec`. The template is kept
                // for documentation and diagnostics.
                program: PathBuf::from(request.program),
                args: request.args.to_vec(),
                bundle: None,
                bundle_file: None,
                warnings: vec![
                    "native backend executes the payload directly via pre_exec syscalls".into(),
                ],
            }),
            Backend::Nspawn(bin) => {
                // Rootless nspawn cannot acquire a UID range without
                // systemd-nsresourced, so fail with a typed error before
                // spawning anything rather than letting nspawn die on startup.
                let rootless = unsafe { libc::geteuid() } != 0;
                if rootless && !nsresourced_available() {
                    return Err(ContainerError::BackendUnavailable(format!(
                        "systemd-nspawn needs root, or systemd-nsresourced at \
                         {NSRESOURCED_SOCKET} for rootless operation; neither is available here"
                    )));
                }
                Ok(BackendTemplate {
                    program: PathBuf::from(bin),
                    args: nspawn_args(request, rootless),
                    bundle: None,
                    bundle_file: None,
                    warnings: vec![
                        "nspawn template cannot enforce cgroup limits and may require privileges \
                         to create user namespaces"
                            .into(),
                    ],
                })
            }
            Backend::Runc(bin) | Backend::Crun(bin) => {
                let bundle = request.state_dir.join("bundle");
                let config = oci_config(request);
                let config_path = bundle.join("config.json");
                let state = request.state_dir.join("runc-state");
                let args = vec![
                    "--root".to_string(),
                    state.display().to_string(),
                    "run".to_string(),
                    "--bundle".to_string(),
                    bundle.display().to_string(),
                    format!("extos-{}", request.id),
                ];
                Ok(BackendTemplate {
                    program: PathBuf::from(bin),
                    args,
                    bundle: Some(bundle),
                    bundle_file: Some((config_path, config)),
                    warnings: vec![
                        "OCI backends need a delegated cgroup hierarchy for resource limits; this \
                         template only declares namespaces"
                            .into(),
                    ],
                })
            }
            Backend::Chroot(bin) => {
                let mut args = vec![request.root.display().to_string()];
                args.push(request.program.to_string());
                args.extend(request.args.iter().cloned());
                Ok(BackendTemplate {
                    program: PathBuf::from(bin),
                    args,
                    bundle: None,
                    bundle_file: None,
                    warnings: vec![
                        "chroot(1) provides no namespace isolation; only filesystem confinement"
                            .into(),
                    ],
                })
            }
        }
    }
}

/// Render the OCI `config.json` for `request`.
///
/// Namespace set follows the level: level 3 drops the `network` namespace so the
/// container inherits the host's; levels 0–2 keep it. A user namespace with
/// identity mappings is always declared, which is what makes the bundle runnable
/// without root.
pub fn oci_config(request: &TemplateRequest<'_>) -> String {
    // Rootless `runc` hard-refuses a bundle whose `linux.namespaces` has no
    // user namespace ("rootless container requires user namespaces"), so the
    // user namespace is declared whenever we are not already root and is
    // mapped identity-wise onto our own euid/egid.
    let rootless = unsafe { libc::geteuid() } != 0;
    let mut namespaces: Vec<serde_json::Value> = Vec::new();
    if rootless {
        namespaces.push(serde_json::json!({ "type": "user" }));
    }
    namespaces.extend(
        [
            ("pid", request.namespaces.pid),
            ("mount", request.namespaces.mount),
            ("ipc", request.namespaces.ipc),
            ("uts", request.namespaces.uts),
            ("network", request.namespaces.net),
        ]
        .into_iter()
        .filter(|(_, on)| *on)
        .map(|(name, _)| serde_json::json!({ "type": name })),
    );

    let mut process_args = vec![request.program.to_string()];
    process_args.extend(request.args.iter().cloned());
    let env: Vec<String> = request
        .env
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect();

    let mut mounts = vec![
        serde_json::json!({
            "destination": "/proc",
            "type": "proc",
            "source": "proc"
        }),
        serde_json::json!({
            "destination": "/dev",
            "type": "tmpfs",
            "source": "tmpfs",
            "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]
        }),
        // A PTY needs a real devpts instance; without it runc fails with
        // "open /dev/pts/ptmx: no such file or directory" as soon as
        // `process.terminal` is true.
        serde_json::json!({
            "destination": "/dev/pts",
            "type": "devpts",
            "source": "devpts",
            "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"]
        }),
        serde_json::json!({
            "destination": "/dev/shm",
            "type": "tmpfs",
            "source": "shm",
            "options": ["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"]
        }),
        serde_json::json!({
            "destination": "/tmp",
            "type": "tmpfs",
            "source": "tmpfs",
            "options": ["nosuid", "nodev", "mode=1777", "size=65536k"]
        }),
    ];
    for (source, target) in request.socket_binds {
        mounts.push(serde_json::json!({
            "destination": target.display().to_string(),
            "type": "bind",
            "source": source.display().to_string(),
            "options": ["bind", "rw"]
        }));
    }

    let mut linux = serde_json::json!({ "namespaces": namespaces });
    // Standard character devices a /dev tmpfs would otherwise lack. libcontainer
    // creates them after mounting /dev and, because /dev/pts is mounted with
    // `newinstance`, also links /dev/ptmx to pts/ptmx.
    linux["devices"] = serde_json::json!([
        { "path": "/dev/null", "type": "c", "major": 1, "minor": 3, "fileMode": 438, "uid": 0, "gid": 0 },
        { "path": "/dev/zero", "type": "c", "major": 1, "minor": 5, "fileMode": 438, "uid": 0, "gid": 0 },
        { "path": "/dev/full", "type": "c", "major": 1, "minor": 7, "fileMode": 438, "uid": 0, "gid": 0 },
        { "path": "/dev/tty", "type": "c", "major": 5, "minor": 0, "fileMode": 438, "uid": 0, "gid": 0 },
        { "path": "/dev/random", "type": "c", "major": 1, "minor": 8, "fileMode": 438, "uid": 0, "gid": 0 },
        { "path": "/dev/urandom", "type": "c", "major": 1, "minor": 9, "fileMode": 438, "uid": 0, "gid": 0 }
    ]);
    if rootless {
        let euid = unsafe { libc::geteuid() };
        let egid = unsafe { libc::getegid() };
        linux["uidMappings"] = serde_json::json!([
            { "containerID": 0, "hostID": euid, "size": 1 }
        ]);
        linux["gidMappings"] = serde_json::json!([
            { "containerID": 0, "hostID": egid, "size": 1 }
        ]);
    }

    let config = serde_json::json!({
        "ociVersion": "1.0.2",
        "process": {
            "terminal": request.level.needs_pty(),
            "user": { "uid": 0, "gid": 0 },
            "args": process_args,
            "env": env,
            "cwd": "/",
        },
        "root": {
            "path": request.root.display().to_string(),
            "readonly": !matches!(
                request.level,
                IsolationLevel::Networked | IsolationLevel::Privileged
            ),
        },
        "hostname": request.hostname,
        "mounts": mounts,
        "linux": linux,
    });
    serde_json::to_string_pretty(&config).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request<'a>(
        level: IsolationLevel,
        root: &'a Path,
        state: &'a Path,
        program: &'a str,
        args: &'a [String],
        env: &'a BTreeMap<String, String>,
    ) -> TemplateRequest<'a> {
        TemplateRequest {
            level,
            namespaces: NamespaceToggles::for_level(level),
            root,
            program,
            args,
            env,
            hostname: "extos-test",
            socket_binds: &[],
            state_dir: state,
            id: "t1",
        }
    }

    #[test]
    fn level_support_matrix_is_honest() {
        assert!(Backend::Native.supports(IsolationLevel::Privileged).is_ok());

        let nspawn = Backend::Nspawn("/usr/bin/systemd-nspawn".into());
        assert!(nspawn.supports(IsolationLevel::Isolated).is_ok());
        assert!(nspawn.supports(IsolationLevel::Gui).is_ok());
        assert!(nspawn.supports(IsolationLevel::Networked).is_err());
        assert!(nspawn.supports(IsolationLevel::Privileged).is_err());

        let runc = Backend::Runc("/usr/bin/runc".into());
        assert!(runc.supports(IsolationLevel::Networked).is_ok());
        assert!(runc.supports(IsolationLevel::Privileged).is_err());

        let chroot = Backend::Chroot("/usr/bin/chroot".into());
        assert!(chroot.supports(IsolationLevel::Privileged).is_ok());
        assert!(chroot.supports(IsolationLevel::Cli).is_err());
        assert!(chroot.requires_root());
    }

    #[test]
    fn unsupported_level_error_names_both_sides() {
        let err = Backend::Nspawn("nspawn".into())
            .supports(IsolationLevel::Privileged)
            .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("nspawn"));
        assert!(text.contains("privileged"));
    }

    #[test]
    fn nspawn_template_contains_root_program_and_binds() {
        let root = Path::new("/tmp/rootfs");
        let state = Path::new("/tmp/state");
        let mut env = BTreeMap::new();
        env.insert("PATH".to_string(), "/usr/bin".to_string());
        let args = vec!["--version".to_string()];
        let mut req = request(
            IsolationLevel::Gui,
            root,
            state,
            "/usr/bin/tool",
            &args,
            &env,
        );
        let binds = vec![(
            PathBuf::from("/run/user/1000/wayland-1"),
            PathBuf::from("/run/user/0/wayland-1"),
        )];
        req.socket_binds = &binds;

        let template = Backend::Nspawn("/usr/bin/systemd-nspawn".into()).template(&req);
        let rootless = unsafe { libc::geteuid() } != 0;
        match template {
            Ok(template) => {
                assert_eq!(template.program, Path::new("/usr/bin/systemd-nspawn"));
                assert_eq!(template.args, nspawn_args(&req, rootless));
            }
            // Rootless hosts without systemd-nsresourced cannot start nspawn at
            // all; the template must say so with a typed error instead of
            // letting the manager fail at startup.
            Err(ContainerError::BackendUnavailable(message)) => {
                assert!(rootless);
                assert!(message.contains("nsresourced"));
            }
            Err(other) => panic!("unexpected template error: {other:?}"),
        }

        let args = nspawn_args(&req, false);
        assert!(args.iter().any(|a| a == "--machine=extos-t1"));
        assert!(args.iter().any(|a| a == "--directory=/tmp/rootfs"));
        assert!(args.iter().any(|a| a == "--private-network"));
        assert!(args.iter().any(|a| a.contains("--bind-ro=")));
        assert!(args.iter().any(|a| a == "--setenv=PATH=/usr/bin"));
        assert_eq!(args.last().unwrap(), "--version");
        assert!(args.contains(&"/usr/bin/tool".to_string()));
    }

    #[test]
    fn nspawn_rootless_args_opt_into_the_user_manager_scope() {
        let root = Path::new("/tmp/rootfs");
        let state = Path::new("/tmp/state");
        let env = BTreeMap::new();
        let args: Vec<String> = vec![];
        let req = request(
            IsolationLevel::Isolated,
            root,
            state,
            "/bin/sh",
            &args,
            &env,
        );

        let rootful = nspawn_args(&req, false);
        assert!(!rootful.iter().any(|a| a == "--user"));
        assert!(!rootful.iter().any(|a| a == "--private-users=pick"));

        let rootless = nspawn_args(&req, true);
        assert!(rootless.iter().any(|a| a == "--user"));
        assert!(rootless.iter().any(|a| a == "--private-users=pick"));
        // `--private=network` was removed in systemd 262.
        assert!(!rootless.iter().any(|a| a == "--private=network"));
        assert!(rootless.iter().any(|a| a == "--private-network"));
    }

    #[test]
    fn nspawn_template_refuses_networked_and_privileged() {
        let root = Path::new("/tmp/rootfs");
        let state = Path::new("/tmp/state");
        let env = BTreeMap::new();
        let args: Vec<String> = vec![];
        for level in [IsolationLevel::Networked, IsolationLevel::Privileged] {
            let req = request(level, root, state, "/bin/sh", &args, &env);
            assert!(Backend::Nspawn("/usr/bin/systemd-nspawn".into())
                .template(&req)
                .is_err());
        }
    }

    #[test]
    fn runc_template_generates_a_valid_oci_bundle() {
        let root = Path::new("/tmp/rootfs");
        let state = Path::new("/tmp/state");
        let mut env = BTreeMap::new();
        env.insert("PATH".to_string(), "/usr/bin".to_string());
        let args = vec!["-c".to_string(), "uname -a".to_string()];
        let req = request(
            IsolationLevel::Networked,
            root,
            state,
            "/bin/sh",
            &args,
            &env,
        );
        let template = Backend::Runc("/usr/bin/runc".into()).template(&req).unwrap();
        assert_eq!(template.bundle.as_deref(), Some(Path::new("/tmp/state/bundle")));
        let (path, json) = template.bundle_file.clone().unwrap();
        assert_eq!(path, Path::new("/tmp/state/bundle/config.json"));

        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["ociVersion"], "1.0.2");
        assert_eq!(parsed["root"]["path"], "/tmp/rootfs");
        assert_eq!(parsed["process"]["args"][0], "/bin/sh");
        let namespaces = parsed["linux"]["namespaces"].as_array().unwrap();
        // Level 3 inherits the host network namespace.
        assert!(!namespaces.iter().any(|ns| ns["type"] == "network"));
        assert!(namespaces.iter().any(|ns| ns["type"] == "pid"));

        let args = &template.args;
        assert_eq!(args[0], "--root");
        assert_eq!(args[2], "run");
        assert_eq!(args[3], "--bundle");
        assert_eq!(args[5], "extos-t1");
    }

    #[test]
    fn runc_config_keeps_network_namespace_below_level_three() {
        let root = Path::new("/r");
        let state = Path::new("/s");
        let env = BTreeMap::new();
        let args: Vec<String> = vec![];
        let json = oci_config(&request(
            IsolationLevel::Isolated,
            root,
            state,
            "/bin/sh",
            &args,
            &env,
        ));
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let namespaces = parsed["linux"]["namespaces"].as_array().unwrap();
        assert!(namespaces.iter().any(|ns| ns["type"] == "network"));
        assert_eq!(parsed["root"]["readonly"], true);
    }

    #[test]
    fn runc_config_declares_a_rootless_user_namespace_and_devpts() {
        let root = Path::new("/r");
        let state = Path::new("/s");
        let env = BTreeMap::new();
        let args: Vec<String> = vec![];
        let json = oci_config(&request(
            IsolationLevel::Cli,
            root,
            state,
            "/bin/sh",
            &args,
            &env,
        ));
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let namespaces = parsed["linux"]["namespaces"].as_array().unwrap();

        if unsafe { libc::geteuid() } != 0 {
            // Rootless `runc` refuses a bundle with no user namespace.
            assert!(namespaces.iter().any(|ns| ns["type"] == "user"));
            let uid_mappings = parsed["linux"]["uidMappings"].as_array().unwrap();
            assert_eq!(uid_mappings[0]["containerID"], 0);
            assert_eq!(uid_mappings[0]["hostID"], unsafe { libc::geteuid() });
            assert!(parsed["linux"]["gidMappings"].is_array());
        } else {
            assert!(!namespaces.iter().any(|ns| ns["type"] == "user"));
        }

        // A PTY level needs a real devpts instance, otherwise runc dies opening
        // /dev/pts/ptmx.
        let mounts = parsed["mounts"].as_array().unwrap();
        assert!(mounts.iter().any(|m| m["destination"] == "/dev/pts"));
        assert!(parsed["linux"]["devices"].as_array().unwrap().len() >= 6);
    }

    #[test]
    fn chroot_template_is_root_program_args() {
        let root = Path::new("/tmp/rootfs");
        let state = Path::new("/tmp/state");
        let env = BTreeMap::new();
        let args = vec!["--help".to_string()];
        let req = request(
            IsolationLevel::Privileged,
            root,
            state,
            "/bin/tool",
            &args,
            &env,
        );
        let template = Backend::Chroot("/usr/bin/chroot".into())
            .template(&req)
            .unwrap();
        assert_eq!(template.args, vec!["/tmp/rootfs", "/bin/tool", "--help"]);
        assert!(template.warnings.iter().any(|w| w.contains("no namespace")));
    }

    #[test]
    fn backend_from_name_validates() {
        assert_eq!(Backend::from_name("").unwrap(), Backend::Native);
        assert!(matches!(
            Backend::from_name("bogus"),
            Err(ContainerError::BackendUnavailable(_))
        ));
        // `chroot` is present on every host this project targets.
        if which("chroot").is_some() {
            assert!(Backend::from_name("chroot").is_ok());
        }
    }

    #[test]
    fn probe_reports_absent_backends_by_name() {
        let probe = BackendProbe::discover();
        let report = probe.report();
        assert!(report.contains("native user namespaces"));
        for name in &probe.absent {
            assert!(report.contains(name));
        }
        // `crun` is absent on the reference host; when it is present the name
        // must simply not appear in the absent list.
        if probe.crun.is_none() {
            assert!(probe.absent.contains(&"crun"));
        }
    }

    #[test]
    fn which_finds_a_real_binary() {
        if std::env::var_os("PATH").is_some() {
            // `sh` is guaranteed by POSIX on every target host.
            assert!(which("sh").is_some());
            assert!(which("definitely-not-a-real-binary-xyz").is_none());
        }
    }

    #[test]
    fn probe_never_modifies_the_calling_process() {
        // The probe forks; our own namespace set must be unchanged afterwards,
        // i.e. /proc/self/ns/user still matches the initial namespace inode.
        let before = std::fs::read_link("/proc/self/ns/user").ok();
        let _ = BackendProbe::discover();
        let after = std::fs::read_link("/proc/self/ns/user").ok();
        assert_eq!(before, after);
    }
}
