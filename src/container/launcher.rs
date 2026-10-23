//! The launcher: one function that ties spec → rootfs → namespaces → process.
//!
//! [`launch`] is the only entry point most callers need.
//!
//! # Levels at a glance
//!
//! * **Level 0 (Isolated)** — user/mount/pid/ipc/uts/net namespaces, tmpfs root,
//!   piped stdio, empty `/proc` until PID 1 mounts its own procfs.
//! * **Level 1 (CLI)** — Level 0 plus a controlling PTY (PLAN 4.4.3).
//! * **Level 2 (GUI)** — Level 1 plus the socket binds assembled by
//!   [`crate::container::gui`] (PLAN 4.4.4). Absent sockets are warnings by
//!   default; set [`LaunchSpec::require_gui_sockets`] for a hard failure.
//! * **Level 3 (Networked)** — Level 2 with the **host** network namespace
//!   (PLAN 4.4.5).
//! * **Level 4 (Privileged)** — no namespace restriction (PLAN 4.4.6). See the
//!   warning below.
//!
//! # Level 4 is explicit opt-in
//!
//! A manifest may *declare* `containerPermissions.level = "privileged"`, but the
//! launcher refuses to act on it until the caller sets
//! [`LaunchSpec::allow_privileged`]; the failure is the typed
//! [`ContainerError::PrivilegedNotAllowed`]. Level 4 exists for build toolchains
//! and system agents, not for ordinary packages.
//!
//! When the native backend runs level 4 it still creates a **user namespace** —
//! not for isolation, but because that is the only way an unprivileged caller
//! obtains `CAP_SYS_CHROOT`. No mount, PID, IPC, UTS or network namespaces are
//! created; the container sees the host's process table, network and IPC, and
//! differs from the host only by its root directory. This is documented
//! behaviour, not a leak.
//!
//! # What a failure looks like
//!
//! Every failure is a [`ContainerError`] variant. Child-side setup failures are
//! reported through [`crate::container::namespace::child_exit_error`]: the child
//! writes `extos-container: <step>` to fd 2 and exits with `120 + stage`, and the
//! parent converts that into `ContainerError::Namespace { op, … }` after the
//! output has been collected.

use std::collections::BTreeMap;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::container::backend::{BackendTemplate, TemplateRequest};
use crate::container::gui::{assemble_gui_spec, GuiEnv, GuiSpec};
use crate::container::mounts::{HostPaths, MountPlan};
use crate::container::namespace::{
    child_exit_error, namespace_failure, ChildProgram, ChildSpec, NamespacePlan, RootMode,
    TMPFS_ROOT_DIR,
};
use crate::container::pty::{read_to_end, PtyPair};
use crate::container::spec::RuntimePolicy;
use crate::container::{Backend, ContainerError, ContainerSocket, IsolationLevel};
use crate::manifest::{ContainerPermissions, NamespaceToggles};

/// Everything needed to launch one container.
#[derive(Debug, Clone)]
pub struct LaunchSpec {
    /// Isolation level.
    pub level: IsolationLevel,
    /// Namespace toggles (declared, not yet shimmed — see
    /// [`LaunchSpec::effective_namespaces`]).
    pub namespaces: NamespaceToggles,
    /// Assembled rootfs (from [`crate::container::rootfs::assemble_rootfs`]).
    pub rootfs: PathBuf,
    /// Program to run, absolute *inside* the container.
    pub program: String,
    /// Program arguments.
    pub args: Vec<String>,
    /// Environment for the container (merged with GUI and default variables).
    pub env: BTreeMap<String, String>,
    /// Container hostname (needs a UTS namespace to take effect).
    pub hostname: String,
    /// Root mount strategy for the native backend.
    pub root_mode: RootMode,
    /// Remount the package tree read-only inside the container.
    pub read_only_root: bool,
    /// Explicit authorisation for level 4.
    pub allow_privileged: bool,
    /// Backend to execute the container.
    pub backend: Backend,
    /// Pre-assembled GUI spec (levels ≥ 2). `None` assembles one from the
    /// process environment when the level has a display.
    pub gui: Option<GuiSpec>,
    /// Turn absent GUI sockets into hard errors.
    pub require_gui_sockets: bool,
    /// Size of every anonymous tmpfs, in KiB.
    pub tmpfs_size_kib: u64,
    /// Host paths the mount table borrows (dev nodes, resolver config).
    pub host_paths: HostPaths,
    /// Scratch directory for external backends (OCI bundles, `runc` state).
    /// `None` uses a per-launch directory under [`std::env::temp_dir`].
    pub state_dir: Option<PathBuf>,
}

impl LaunchSpec {
    /// A minimal spec: level defaults, read-only root, native backend.
    pub fn new(level: IsolationLevel, rootfs: impl Into<PathBuf>, program: impl Into<String>) -> Self {
        let profile = ContainerPermissions::new(level);
        Self {
            level,
            namespaces: profile.namespaces,
            rootfs: rootfs.into(),
            program: program.into(),
            args: Vec::new(),
            env: BTreeMap::new(),
            hostname: "extos".to_string(),
            root_mode: RootMode::TmpfsBind,
            read_only_root: !matches!(
                level,
                IsolationLevel::Networked | IsolationLevel::Privileged
            ),
            allow_privileged: false,
            backend: Backend::Native,
            gui: None,
            require_gui_sockets: false,
            tmpfs_size_kib: 64 * 1024,
            host_paths: HostPaths::from_env(),
            state_dir: None,
        }
    }

    /// Build a spec from a manifest-declared profile.
    ///
    /// The profile's `command` is used when `program` is `None`; a profile
    /// without a command and no explicit program is a typed error at launch
    /// time.
    pub fn from_profile(
        profile: &ContainerPermissions,
        rootfs: impl Into<PathBuf>,
        program: Option<&str>,
    ) -> Self {
        let mut spec = Self::new(profile.level, rootfs, program.unwrap_or(""));
        spec.namespaces = profile.namespaces;
        if program.is_none() {
            if let Some(first) = profile.command.first() {
                spec.program = first.clone();
                spec.args = profile.command[1..].to_vec();
            }
        }
        if !profile.sockets.is_empty() {
            let gui = assemble_gui_spec(&profile.sockets, &GuiEnv::from_env());
            spec.gui = Some(gui);
        }
        spec
    }

    /// Replace the program arguments.
    pub fn with_args(mut self, args: impl IntoIterator<Item = String>) -> Self {
        self.args = args.into_iter().collect();
        self
    }

    /// Add/override an environment variable.
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    /// Select the backend.
    pub fn with_backend(mut self, backend: Backend) -> Self {
        self.backend = backend;
        self
    }

    /// Allow a level-4 launch.
    pub fn with_privileged(mut self, allow: bool) -> Self {
        self.allow_privileged = allow;
        self
    }

    /// Pre-assembled GUI spec.
    pub fn with_gui(mut self, gui: GuiSpec) -> Self {
        self.gui = Some(gui);
        self
    }

    /// Requested sockets (from the level defaults plus the GUI spec).
    pub fn sockets(&self) -> Vec<ContainerSocket> {
        if self.level.as_u8() < 2 {
            return Vec::new();
        }
        self.gui
            .as_ref()
            .map(|gui| gui.mounts.iter().map(|mount| mount.kind).collect())
            .unwrap_or_else(|| ContainerSocket::defaults_for_level(self.level))
    }

    /// Namespace toggles the child will actually use.
    ///
    /// The only transformation: level 4 on the native backend gains a user
    /// namespace as a chroot capability shim (see the module docs).
    pub fn effective_namespaces(&self) -> NamespaceToggles {
        let mut toggles = self.namespaces;
        if self.level == IsolationLevel::Privileged
            && self.backend == Backend::Native
            && !toggles.user
        {
            toggles.user = true;
        }
        toggles
    }

    /// The mount strategy actually used (a tmpfs root needs a mount namespace).
    pub fn effective_root_mode(&self) -> RootMode {
        if self.effective_namespaces().mount {
            self.root_mode
        } else {
            RootMode::Direct
        }
    }

    /// Environment the container will see, after defaults and GUI rewrites.
    pub fn container_env(&self) -> BTreeMap<String, String> {
        let mut env = self.env.clone();
        let defaults = [
            ("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string()),
            ("HOME", "/root".to_string()),
            ("HOSTNAME", self.hostname.clone()),
            ("EXTOS_CONTAINER", "1".to_string()),
        ];
        for (key, value) in defaults {
            env.entry(key.to_string()).or_insert(value);
        }
        if self.level.needs_pty() {
            env.entry("TERM".to_string())
                .or_insert_with(|| "xterm-256color".to_string());
        }
        if let Some(gui) = &self.gui {
            for (key, value) in &gui.env {
                env.insert(key.clone(), value.clone());
            }
            for key in &gui.unset {
                env.remove(key);
            }
        }
        env
    }
}

/// What a launch produced.
#[derive(Debug, Clone)]
pub struct LaunchOutcome {
    /// Exit status of the container payload.
    pub status: ExitStatus,
    /// Everything the container wrote to its stdout/stderr (PTY-merged for
    /// levels ≥ 1, concatenated for level 0).
    pub output: Vec<u8>,
    /// Backend that ran it.
    pub backend: Backend,
    /// Non-fatal notes (absent sockets, dropped devices, honest limits).
    pub warnings: Vec<String>,
    /// Whether stdio was a PTY.
    pub pty: bool,
}

impl LaunchOutcome {
    /// Whether the payload exited successfully.
    pub fn success(&self) -> bool {
        self.status.success()
    }

    /// The captured output as lossy UTF-8 (PTY output contains CR/LF pairs).
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.output).to_string()
    }
}

/// Launch one container.
pub fn launch(spec: &LaunchSpec) -> Result<LaunchOutcome, ContainerError> {
    let policy = RuntimePolicy {
        level: spec.level,
        namespaces: spec.namespaces,
        pty: spec.level.needs_pty(),
        sockets: spec.sockets(),
        tmpfs_root: true,
        read_only_root: spec.read_only_root,
    };
    policy.validate()?;

    if spec.level == IsolationLevel::Privileged && !spec.allow_privileged {
        return Err(ContainerError::PrivilegedNotAllowed);
    }
    spec.backend.supports(spec.level)?;

    if spec.program.is_empty() {
        return Err(ContainerError::Spec(
            "no container program: the profile declares no command and the caller passed none"
                .into(),
        ));
    }
    if !spec.rootfs.is_dir() {
        return Err(ContainerError::Rootfs(format!(
            "rootfs {} is not a directory",
            spec.rootfs.display()
        )));
    }
    require_program(&spec.rootfs, &spec.program)?;

    // Validate required sockets only when the caller opted in: a desktop
    // without PipeWire must not break every GUI container.
    let mut warnings = Vec::new();
    if let Some(gui) = &spec.gui {
        gui.validate(spec.require_gui_sockets)?;
        warnings.extend(gui.warnings.iter().cloned());
    }

    let env = spec.container_env();
    match &spec.backend {
        Backend::Native => launch_native(spec, &env, warnings),
        backend => launch_external(spec, backend, &env, warnings),
    }
}

/// Ensure `program` exists (and is executable) as `<rootfs>/<program>`.
fn require_program(rootfs: &Path, program: &str) -> Result<(), ContainerError> {
    let rel = program.trim_start_matches('/');
    if rel.is_empty() {
        return Err(ContainerError::ProgramNotFound(program.to_string()));
    }
    let path = rootfs.join(rel);
    let meta = path.metadata().map_err(|_| {
        ContainerError::ProgramNotFound(format!(
            "{program} ({} is missing from the rootfs)",
            path.display()
        ))
    })?;
    if !meta.is_file() {
        return Err(ContainerError::ProgramNotFound(format!(
            "{program} is not a regular file"
        )));
    }
    Ok(())
}

/// Native backend: `Command` + `pre_exec` + the child program.
fn launch_native(
    spec: &LaunchSpec,
    env: &BTreeMap<String, String>,
    warnings: Vec<String>,
) -> Result<LaunchOutcome, ContainerError> {
    let namespaces = spec.effective_namespaces();
    let plan = NamespacePlan::new(namespaces);
    let mounts = MountPlan::for_level(spec.level, &spec.host_paths, spec.tmpfs_size_kib);
    let mut warnings = warnings;
    warnings.extend(mounts.warnings.iter().cloned());

    let root_mode = spec.effective_root_mode();
    if root_mode == RootMode::TmpfsBind {
        // `mount(2)` needs an existing mountpoint; it lives inside the staged
        // tree so the bind sources stay reachable (see TMPFS_ROOT_DIR).
        std::fs::create_dir_all(spec.rootfs.join(TMPFS_ROOT_DIR))?;
    }
    let top_level = list_top_level(&spec.rootfs)?;
    if root_mode == RootMode::TmpfsBind && top_level.is_empty() {
        return Err(ContainerError::Rootfs(
            "rootfs has no top-level entries to bind into the tmpfs root".into(),
        ));
    }

    let child = ChildProgram::build(&ChildSpec {
        plan: &plan,
        root: &spec.rootfs,
        root_mode,
        top_level: &top_level,
        read_only_root: spec.read_only_root,
        mounts: &mounts,
        gui: spec.gui.as_ref(),
        hostname: &spec.hostname,
        program: &spec.program,
        args: &spec.args,
        env,
        claim_tty: spec.level.needs_pty(),
        tmpfs_size_kib: spec.tmpfs_size_kib,
    })?;

    let mut command = Command::new(&spec.program);
    // argv is built by the child program; std's own argv is never used because
    // the `pre_exec` closure never returns.

    let pty = if spec.level.needs_pty() {
        Some(PtyPair::open()?)
    } else {
        None
    };
    if let Some(pair) = &pty {
        // stdin/stdout/stderr all point at the PTY slave.
        command
            .stdin(Stdio::from(pair.slave.try_clone()?))
            .stdout(Stdio::from(pair.slave.try_clone()?))
            .stderr(Stdio::from(pair.slave.try_clone()?));
    } else {
        command.stdin(Stdio::null());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
    }

    // SAFETY: the closure moves only pre-allocated `CString`/`Vec` data into the
    // child and calls async-signal-safe libc functions; see
    // `container::namespace` for the full contract. `run_for_closure` never
    // returns, so std never reaches its own `exec`.
    unsafe {
        command.pre_exec(move || ChildProgram::run_for_closure(&child));
    }

    let mut child_process = command.spawn()?;
    drop_parent_stdio(&mut command);

    let outcome = if let Some(pair) = pty {
        // Drop our send side first: the parent must not keep the slave open, or
        // the master never sees EOF.
        let PtyPair { master, slave } = pair;
        drop(slave);
        let mut master = master;
        let output = read_to_end(&mut master)?;
        let status = child_process.wait()?;
        LaunchOutcome {
            status,
            output,
            backend: Backend::Native,
            warnings,
            pty: true,
        }
    } else {
        let output = child_process.wait_with_output()?;
        let mut combined = output.stdout;
        combined.extend_from_slice(&output.stderr);
        LaunchOutcome {
            status: output.status,
            output: combined,
            backend: Backend::Native,
            warnings,
            pty: false,
        }
    };

    interpret_child_exit(outcome)
}

/// External backend (nspawn/runc/crun/chroot): build the template and run it.
fn launch_external(
    spec: &LaunchSpec,
    backend: &Backend,
    env: &BTreeMap<String, String>,
    warnings: Vec<String>,
) -> Result<LaunchOutcome, ContainerError> {
    let mut warnings = warnings;
    if backend.requires_root() {
        warnings.push(format!(
            "backend {} needs CAP_SYS_CHROOT; unprivileged hosts will get EPERM",
            backend.as_str()
        ));
    }
    let state_dir = match &spec.state_dir {
        Some(dir) => {
            std::fs::create_dir_all(dir)?;
            dir.clone()
        }
        None => scratch_dir()?,
    };
    let socket_binds: Vec<(PathBuf, PathBuf)> = spec
        .gui
        .as_ref()
        .map(|gui| {
            gui.mounts
                .iter()
                .filter_map(|mount| {
                    mount
                        .source
                        .as_ref()
                        .filter(|source| source.exists())
                        .map(|source| (source.clone(), mount.target.clone()))
                })
                .collect()
        })
        .unwrap_or_default();

    let request = TemplateRequest {
        level: spec.level,
        namespaces: spec.namespaces,
        root: &spec.rootfs,
        program: &spec.program,
        args: &spec.args,
        env,
        hostname: &spec.hostname,
        socket_binds: &socket_binds,
        state_dir: &state_dir,
        id: &format!("{}-{}", std::process::id(), unique_suffix()),
    };
    let BackendTemplate {
        program,
        args,
        bundle,
        bundle_file,
        warnings: template_warnings,
    } = backend.template(&request)?;
    warnings.extend(template_warnings);

    if let Some(dir) = &bundle {
        std::fs::create_dir_all(dir)?;
    }
    if let Some((path, contents)) = &bundle_file {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, contents)?;
    }

    let pty = if spec.level.needs_pty() {
        Some(PtyPair::open()?)
    } else {
        None
    };
    let mut command = Command::new(&program);
    command.args(&args);
    if let Some(pair) = &pty {
        command
            .stdin(Stdio::from(pair.slave.try_clone()?))
            .stdout(Stdio::from(pair.slave.try_clone()?))
            .stderr(Stdio::from(pair.slave.try_clone()?));
    } else {
        command.stdin(Stdio::null());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
    }

    let spawn_result = command.spawn();
    let mut child = match spawn_result {
        Ok(child) => child,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(ContainerError::BackendUnavailable(format!(
                "{} could not be executed: {err}",
                program.display()
            )));
        }
        Err(err) => return Err(err.into()),
    };
    drop_parent_stdio(&mut command);

    if let Some(pair) = pty {
        let PtyPair { mut master, slave } = pair;
        drop(slave);
        let output = read_to_end(&mut master)?;
        let status = child.wait()?;
        Ok(LaunchOutcome {
            status,
            output,
            backend: backend.clone(),
            warnings,
            pty: true,
        })
    } else {
        let output = child.wait_with_output()?;
        let mut combined = output.stdout;
        combined.extend_from_slice(&output.stderr);
        Ok(LaunchOutcome {
            status: output.status,
            output: combined,
            backend: backend.clone(),
            warnings,
            pty: false,
        })
    }
}

/// Release the stdio handles the parent still owns.
///
/// `std::process::Command` keeps its `Stdio` values (and therefore any file
/// descriptors we handed it) alive after `spawn`. Holding the PTY slave in the
/// parent would keep the master open forever, so the read would never see EOF;
/// the same applies to a piped write end. Replacing the fields drops them.
fn drop_parent_stdio(command: &mut Command) {
    command.stdin(Stdio::null());
    command.stdout(Stdio::null());
    command.stderr(Stdio::null());
}

/// Convert an `extos-container: …` + `120 + stage` exit into a typed error.
fn interpret_child_exit(outcome: LaunchOutcome) -> Result<LaunchOutcome, ContainerError> {
    let Some(code) = outcome.status.code() else {
        return Ok(outcome);
    };
    if code < crate::container::namespace::CHILD_EXIT_SETUP_BASE {
        return Ok(outcome);
    }
    if !outcome
        .output
        .windows(b"extos-container:".len())
        .any(|window| window == b"extos-container:")
    {
        // The payload legitimately exited with a high code.
        return Ok(outcome);
    }
    match child_exit_error(code) {
        Some(err) => Err(err),
        None => Err(namespace_failure("setup", libc::EPERM)),
    }
}

fn list_top_level(rootfs: &Path) -> Result<Vec<String>, ContainerError> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(rootfs)? {
        let entry = entry?;
        let name = entry.file_name();
        if let Some(name) = name.to_str() {
            if name == TMPFS_ROOT_DIR {
                continue;
            }
            names.push(name.to_string());
        }
    }
    names.sort();
    Ok(names)
}

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("{nanos}")
}

/// Per-launch scratch directory for external backends.
fn scratch_dir() -> Result<PathBuf, ContainerError> {
    let dir = std::env::temp_dir().join(format!(
        "extos-container-{}-{}",
        std::process::id(),
        unique_suffix()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_follow_the_level() {
        let cli = LaunchSpec::new(IsolationLevel::Cli, "/tmp/root", "/bin/sh");
        assert!(cli.level.needs_pty());
        assert_eq!(cli.backend, Backend::Native);
        assert!(!cli.allow_privileged);
        assert!(cli.read_only_root);
        assert_eq!(cli.effective_namespaces().net, true);

        let net = LaunchSpec::new(IsolationLevel::Networked, "/tmp/root", "/bin/sh");
        assert_eq!(net.effective_namespaces().net, false);
        assert!(!net.read_only_root);
    }

    #[test]
    fn level_four_gains_a_userns_shim_but_no_other_namespace() {
        let priv_spec = LaunchSpec::new(IsolationLevel::Privileged, "/tmp/root", "/bin/sh");
        let effective = priv_spec.effective_namespaces();
        assert!(effective.user, "chroot shim requires a user namespace");
        assert!(!effective.mount);
        assert!(!effective.pid);
        assert!(!effective.net);
        assert_eq!(priv_spec.effective_root_mode(), RootMode::Direct);
    }

    #[test]
    fn level_four_without_opt_in_is_refused() {
        let spec = LaunchSpec::new(IsolationLevel::Privileged, "/tmp/root", "/bin/sh");
        let err = launch(&spec).unwrap_err();
        assert!(matches!(err, ContainerError::PrivilegedNotAllowed));
    }

    #[test]
    fn unsupported_backend_combination_is_refused_before_spawn() {
        let spec = LaunchSpec::new(IsolationLevel::Privileged, "/tmp/root", "/bin/sh")
            .with_privileged(true)
            .with_backend(Backend::Nspawn("systemd-nspawn".into()));
        let err = launch(&spec).unwrap_err();
        assert!(matches!(err, ContainerError::UnsupportedLevel { .. }));
    }

    #[test]
    fn missing_program_is_a_typed_error() {
        let tmp = tempfile::tempdir().unwrap();
        let spec = LaunchSpec::new(IsolationLevel::Cli, tmp.path(), "/bin/definitely-missing");
        let err = launch(&spec).unwrap_err();
        match err {
            ContainerError::ProgramNotFound(name) => assert!(name.contains("definitely-missing")),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn missing_rootfs_is_a_typed_error() {
        let spec = LaunchSpec::new(IsolationLevel::Cli, "/definitely/not/a/rootfs", "/bin/sh");
        let err = launch(&spec).unwrap_err();
        assert!(matches!(err, ContainerError::Rootfs(_)));
    }

    #[test]
    fn env_merges_defaults_and_gui_rewrites() {
        let tmp = tempfile::tempdir().unwrap();
        let gui_env = GuiEnv {
            xdg_runtime_dir: Some(tmp.path().to_path_buf()),
            wayland_display: Some("wayland-0".into()),
            xauthority: Some(PathBuf::from("/home/u/.Xauthority")),
            ..Default::default()
        };
        let gui = assemble_gui_spec(&[ContainerSocket::Wayland], &gui_env);
        let mut spec = LaunchSpec::new(IsolationLevel::Gui, "/tmp/root", "/bin/sh");
        spec.gui = Some(gui);
        spec.env.insert("XAUTHORITY".into(), "/home/u/.Xauthority".into());
        let env = spec.container_env();
        assert_eq!(env.get("XDG_RUNTIME_DIR").map(String::as_str), Some("/run/user/0"));
        assert_eq!(env.get("WAYLAND_DISPLAY").map(String::as_str), Some("wayland-0"));
        assert_eq!(env.get("PATH").map(String::as_str).unwrap().contains("/usr/bin"), true);
        assert_eq!(env.get("TERM").map(String::as_str), Some("xterm-256color"));
        assert_eq!(env.get("EXTOS_CONTAINER").map(String::as_str), Some("1"));
        assert!(!env.contains_key("XAUTHORITY"));
    }

    #[test]
    fn level_zero_has_no_terminal_env_or_pty() {
        let spec = LaunchSpec::new(IsolationLevel::Isolated, "/tmp/root", "/bin/sh");
        let env = spec.container_env();
        assert!(!env.contains_key("TERM"));
        assert!(!spec.level.needs_pty());
        assert!(spec.sockets().is_empty());
    }

    #[test]
    fn from_profile_carries_the_declared_command() {
        let profile = ContainerPermissions::new(IsolationLevel::Cli)
            .with_command(["/usr/bin/app".to_string(), "--flag".to_string()]);
        let spec = LaunchSpec::from_profile(&profile, "/tmp/root", None);
        assert_eq!(spec.program, "/usr/bin/app");
        assert_eq!(spec.args, vec!["--flag"]);
        assert_eq!(spec.level, IsolationLevel::Cli);
    }

    #[test]
    fn from_profile_without_command_leaves_program_empty() {
        let profile = ContainerPermissions::new(IsolationLevel::Isolated);
        let spec = LaunchSpec::from_profile(&profile, "/tmp/root", None);
        assert!(spec.program.is_empty());
        assert_eq!(spec.sockets(), Vec::<ContainerSocket>::new());
    }
}
