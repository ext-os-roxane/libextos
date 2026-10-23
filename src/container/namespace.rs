//! The child-side syscall program and its safety contract (PLAN 4.4.2, 4.4.5,
//! 4.4.6).
//!
//! Everything in this module runs **between `fork` and `exec`** and therefore
//! obeys the async-signal-safety contract documented below. The parent builds a
//! `ChildProgram` — every path, every option string, every argument is an
//! already-allocated `CString` — and the child only walks that structure issuing
//! raw libc calls. No allocation, no locks, no Rust runtime services, no
//! `unwrap`, no panicking formatting.
//!
//! # The fork/exec safety contract
//!
//! After `fork(2)` the child may only call async-signal-safe functions. In
//! practice that means:
//!
//! * **Allowed:** `unshare`, `mount`, `chroot`, `chdir`, `mkdirat`, `open`,
//!   `write`, `close`, `sethostname`, `fork`, `setsid`, `ioctl`, `waitpid`,
//!   `execve`, `_exit`.
//! * **Forbidden:** `malloc`/`free` and everything built on them (`String`,
//!   `Vec`, `format!`, `CString::new`), `std::io`, `tracing`, mutexes, atfork
//!   handlers, `std::process::Command` internals.
//! * Every byte string the child touches was allocated by the parent *before*
//!   the fork, so the child's address space contains no partially-initialised
//!   heap object. `argv`/`envp` pointer arrays are built on the child's stack
//!   from those pre-allocated `CString`s (no allocation).
//! * `fork` itself is issued as a raw `SYS_fork` syscall so glibc's
//!   `pthread_atfork` handlers (which may take locks) never run in a process
//!   that is about to `exec`.
//! * Failures are reported by writing a fixed byte string to fd 2 and calling
//!   `_exit(CHILD_EXIT_SETUP_BASE + stage)`. The parent maps that exit code back
//!   to a typed [`crate::container::ContainerError::Namespace`], so no error
//!   object ever crosses the fork boundary.
//!
//! # Why the launch forks twice
//!
//! `unshare(CLONE_NEWPID)` only affects *children created afterwards*: the
//! calling process stays in the old PID namespace, so a plain
//! `pre_exec → execve` would leave the container without PID isolation. Exactly
//! like `unshare --pid --fork`, the supervisor therefore forks once after
//! unsharing; the grandchild — PID 1 of the new namespace — mounts `/proc`,
//! claims the PTY and `execve`s the payload, while the supervisor `waitpid`s and
//! propagates the exit status so `std::process::Child` still reports the real
//! result.
//!
//! # Sequence
//!
//! ```text
//! unshare(user,mount,pid,ipc,uts[,net])
//!   → write /proc/self/{setgroups,uid_map,gid_map}
//!   → mount --make-rprivate /
//!   → mount -t tmpfs tmpfs <stage>/.extos-root           (tmpfs root)
//!   → for each top-level entry: mkdir + mount --bind <stage>/<e> → <root>/<e>
//!                                                        (+ remount ro)
//!   → chroot(<root>); chdir("/")
//!   → mount -t tmpfs /dev /tmp /run
//!   → mkdir parents; mount --bind device nodes and GUI sockets
//!   → sethostname
//!   → fork
//!       child : mount -t proc /proc; setsid; TIOCSCTTY; execve
//!       parent: waitpid → _exit(status)
//! ```

use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::path::Path;

use crate::container::{ns_err, ContainerError, GuiSpec, IsolationLevel, MountPlan, MountSource};
use crate::manifest::NamespaceToggles;

/// Exit code offset for child setup failures (`120 + stage index`).
pub const CHILD_EXIT_SETUP_BASE: i32 = 120;

/// Human names of the child stages, indexed by `exit_code - CHILD_EXIT_SETUP_BASE`.
pub const CHILD_STAGES: [&str; 18] = [
    "unshare",
    "setgroups",
    "uid_map",
    "gid_map",
    "mount-private",
    "tmpfs-root",
    "bind-root-entry",
    "chroot",
    "chdir",
    "mount-tmpfs",
    "mkdir",
    "mount-bind",
    "sethostname",
    "fork",
    "mount-proc",
    "setsid",
    "claim-tty",
    "execve",
];

/// Map a child exit code back to its stage name, if it is a setup failure.
pub fn stage_for_exit_code(code: i32) -> Option<&'static str> {
    let index = code.checked_sub(CHILD_EXIT_SETUP_BASE)?;
    usize::try_from(index)
        .ok()
        .and_then(|i| CHILD_STAGES.get(i).copied())
}

/// Turn a child setup exit code into a typed error (parent side).
pub fn child_exit_error(code: i32) -> Option<ContainerError> {
    let stage = stage_for_exit_code(code)?;
    Some(ContainerError::Namespace {
        op: stage,
        message: format!("child setup failed and exited with code {code}"),
    })
}

// ─── Namespace plan ────────────────────────────────────────────

/// Where the container root comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootMode {
    /// The assembled tree is staged somewhere; the child mounts a fresh tmpfs at
    /// `root` and bind-mounts each top-level entry of the staged tree into it.
    /// The root inode is genuinely tmpfs, and only the declared entries come
    /// from the host filesystem (PLAN 4.4.2, "tmpfs root").
    TmpfsBind,
    /// The staged directory *is* the root (`chroot` only). Useful for debugging
    /// and for hosts where mounting a tmpfs is not permitted.
    Direct,
}

/// Which namespaces a launch creates, resolved from [`NamespaceToggles`].
///
/// The `libc` flags are derived once, here, so both the child program and the
/// backend command-line templates agree on the same numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespacePlan {
    /// Toggles this plan was built from.
    pub toggles: NamespaceToggles,
}

impl NamespacePlan {
    /// Wrap a toggle set.
    pub fn new(toggles: NamespaceToggles) -> Self {
        Self { toggles }
    }

    /// The plan implied by an isolation level's default toggles.
    pub fn for_level(level: IsolationLevel) -> Self {
        Self::new(NamespaceToggles::for_level(level))
    }

    /// `CLONE_*` bits for `unshare(2)`.
    pub fn unshare_flags(&self) -> libc::c_int {
        let mut flags = 0;
        if self.toggles.user {
            flags |= libc::CLONE_NEWUSER;
        }
        if self.toggles.mount {
            flags |= libc::CLONE_NEWNS;
        }
        if self.toggles.pid {
            flags |= libc::CLONE_NEWPID;
        }
        if self.toggles.ipc {
            flags |= libc::CLONE_NEWIPC;
        }
        if self.toggles.uts {
            flags |= libc::CLONE_NEWUTS;
        }
        if self.toggles.net {
            flags |= libc::CLONE_NEWNET;
        }
        if self.toggles.cgroup {
            flags |= libc::CLONE_NEWCGROUP;
        }
        flags
    }

    /// Whether a user namespace is created (required for any mount work).
    pub fn uses_user_namespace(&self) -> bool {
        self.toggles.user
    }

    /// Whether the launched payload becomes PID 1 of a fresh PID namespace.
    pub fn creates_pid_namespace(&self) -> bool {
        self.toggles.pid
    }

    /// The syscalls this plan will issue in the child, in order.
    pub fn syscall_sequence(&self) -> Vec<&'static str> {
        let mut steps = vec!["unshare"];
        if self.toggles.user {
            steps.extend(["setgroups", "uid_map", "gid_map"]);
        }
        if self.toggles.mount {
            steps.extend([
                "mount-private",
                "tmpfs-root",
                "bind-root-entry",
                "chroot",
                "chdir",
                "mount-tmpfs",
                "mkdir",
                "mount-bind",
            ]);
        }
        if self.toggles.uts {
            steps.push("sethostname");
        }
        steps.extend(["fork", "setsid", "execve"]);
        steps
    }
}

// ─── Child program (parent-built, child-walked) ────────────────

/// Directory (inside the staged rootfs) that hosts the tmpfs root.
///
/// The tmpfs must be mounted on a path that does *not* hide the staged tree,
/// otherwise the bind sources (`<stage>/usr`, …) would resolve inside the fresh
/// tmpfs and bind empty directories onto themselves. Mounting it one level
/// deeper keeps `<stage>/usr` reachable, and the container is then chrooted into
/// `<stage>/.extos-root`.
pub const TMPFS_ROOT_DIR: &str = ".extos-root";

/// Maximum argv/envp entries: the child fills fixed-size stack arrays, so the
/// limit is enforced in the parent with a typed error instead of failing in the
/// child.
pub const MAX_EXEC_VECTORS: usize = 64;

/// Slots in the child's on-stack pointer arrays: [`MAX_EXEC_VECTORS`] entries
/// plus the trailing `NULL` pointer `execve(2)` requires (G-L15 fix).
///
/// The two spaces are deliberately distinct: [`MAX_EXEC_VECTORS`] bounds what a
/// caller may pass, while `MAX_EXEC_PTRS` bounds the array that carries those
/// entries *and* its terminator. Conflating them (`MAX_EXEC_VECTORS` slots for
/// both) silently truncated the 64th argument, which is the off-by-one this
/// constant exists to prevent.
const MAX_EXEC_PTRS: usize = MAX_EXEC_VECTORS + 1;

/// One bind-mount to apply inside the container.
#[derive(Debug, Clone)]
struct ChildBind {
    source: CString,
    target: CString,
    read_only: bool,
}

/// Everything the child needs, fully materialised.
///
/// Contains only `CString`/`Vec` (already allocated) and no raw pointers, so it
/// stays `Send` and can be moved into a `pre_exec` closure.
#[derive(Debug)]
pub(crate) struct ChildProgram {
    unshare_flags: libc::c_int,
    uid_map: Option<CString>,
    gid_map: Option<CString>,
    root: CString,
    root_mode: RootMode,
    root_tmpfs_opts: CString,
    /// `(source, target)` pairs for the tmpfs root: host path in the staged
    /// tree, and its path inside the fresh tmpfs root.
    root_binds: Vec<(CString, CString)>,
    read_only_root: bool,
    tmpfs_mounts: Vec<(CString, CString)>,
    mkdirs: Vec<CString>,
    binds: Vec<ChildBind>,
    proc_target: Option<CString>,
    hostname: Option<CString>,
    claim_tty: bool,
    program: CString,
    argv: Vec<CString>,
    envp: Vec<CString>,
}

/// Inputs for [`ChildProgram::build`].
pub(crate) struct ChildSpec<'a> {
    pub plan: &'a NamespacePlan,
    pub root: &'a Path,
    pub root_mode: RootMode,
    pub top_level: &'a [String],
    pub read_only_root: bool,
    pub mounts: &'a MountPlan,
    pub gui: Option<&'a GuiSpec>,
    pub hostname: &'a str,
    pub program: &'a str,
    pub args: &'a [String],
    pub env: &'a BTreeMap<String, String>,
    pub claim_tty: bool,
    pub tmpfs_size_kib: u64,
}

/// Directories that must exist inside the container before binds land on them.
fn mount_directories(mounts: &MountPlan, gui: Option<&GuiSpec>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |path: &str| {
        if !path.is_empty() && path != "/" && !out.iter().any(|existing| existing == path) {
            out.push(path.to_string());
        }
    };
    for mount in &mounts.mounts {
        if let Some(parent) = mount.target.parent() {
            push(&parent.display().to_string());
        }
    }
    if let Some(gui) = gui {
        for mount in &gui.mounts {
            if let Some(parent) = mount.target.parent() {
                push(&parent.display().to_string());
            }
        }
    }
    // Parent-first order so a single `mkdir` pass suffices.
    out.sort_by_key(|path| path.matches('/').count());
    out
}

impl ChildProgram {
    /// Materialise the child program. All allocation happens here.
    pub(crate) fn build(spec: &ChildSpec<'_>) -> Result<Self, ContainerError> {
        // `argv[0]` is the program, so `args.len() + 1` entries are produced.
        // Exactly `MAX_EXEC_VECTORS` entries are legal; the child's pointer
        // array has one extra `NULL` slot (see `MAX_EXEC_PTRS`), so the 64th
        // argument reaches the payload instead of being truncated (G-L15).
        if spec.args.len() + 1 > MAX_EXEC_VECTORS {
            return Err(ContainerError::Spec(format!(
                "too many container arguments ({} + program); the limit is {MAX_EXEC_VECTORS}",
                spec.args.len()
            )));
        }
        if spec.env.len() >= MAX_EXEC_VECTORS {
            return Err(ContainerError::Spec(format!(
                "too many container environment variables ({}); the limit is {MAX_EXEC_VECTORS}",
                spec.env.len()
            )));
        }
        if !spec.program.starts_with('/') {
            return Err(ContainerError::Spec(format!(
                "container program must be an absolute in-container path, got {:?}",
                spec.program
            )));
        }
        if spec.hostname.is_empty() || spec.hostname.len() > 64 {
            return Err(ContainerError::Spec(format!(
                "invalid container hostname: {:?}",
                spec.hostname
            )));
        }

        let plan = spec.plan;
        let cstring = |text: &str, what: &str| -> Result<CString, ContainerError> {
            CString::new(text).map_err(|_| {
                ContainerError::Spec(format!("{what} contains an interior NUL byte: {text:?}"))
            })
        };

        // UID/GID maps: map the caller's real ids to 0 inside the container.
        // SAFETY: geteuid/getegid are always safe to call.
        let (uid_map, gid_map) = if plan.uses_user_namespace() {
            let uid = unsafe { libc::geteuid() };
            let gid = unsafe { libc::getegid() };
            (
                Some(cstring(&format!("0 {uid} 1"), "uid map")?),
                Some(cstring(&format!("0 {gid} 1"), "gid map")?),
            )
        } else {
            (None, None)
        };

        let stage_text = spec.root.display().to_string();
        let root_text = if spec.root_mode == RootMode::TmpfsBind {
            format!("{stage_text}/{TMPFS_ROOT_DIR}")
        } else {
            stage_text.clone()
        };
        let root = cstring(&root_text, "root path")?;
        let size_kib = spec.tmpfs_size_kib.max(1024);
        let root_tmpfs_opts =
            cstring(&format!("size={size_kib},mode=0755"), "tmpfs options")?;

        let mut root_binds = Vec::with_capacity(spec.top_level.len());
        for entry in spec.top_level {
            if entry.is_empty() || entry.contains('/') || entry == "." || entry == ".." {
                return Err(ContainerError::Spec(format!(
                    "invalid rootfs top-level entry name: {entry:?}"
                )));
            }
            if entry == TMPFS_ROOT_DIR {
                continue;
            }
            root_binds.push((
                cstring(&format!("{stage_text}/{entry}"), "rootfs entry source")?,
                cstring(&format!("{root_text}/{entry}"), "rootfs entry target")?,
            ));
        }

        let mut tmpfs_mounts = Vec::new();
        let mut binds = Vec::new();
        let mut proc_target = None;
        for mount in &spec.mounts.mounts {
            let target = cstring(&mount.target.display().to_string(), "mount target")?;
            match &mount.source {
                MountSource::Tmpfs { size_kib } => tmpfs_mounts.push((
                    target,
                    cstring(
                        &format!("size={},mode=0755", (*size_kib).max(1024)),
                        "tmpfs options",
                    )?,
                )),
                MountSource::Bind { source, read_only } => binds.push(ChildBind {
                    source: cstring(&source.display().to_string(), "bind source")?,
                    target,
                    read_only: *read_only,
                }),
                MountSource::Proc => proc_target = Some(target),
            }
        }
        if let Some(gui) = spec.gui {
            for mount in &gui.mounts {
                let Some(source) = mount.source.as_ref() else {
                    continue;
                };
                if !source.exists() {
                    // Absent sockets are warnings from `gui::assemble_gui_spec`;
                    // they must never make the child fail.
                    continue;
                }
                binds.push(ChildBind {
                    source: cstring(&source.display().to_string(), "socket source")?,
                    target: cstring(&mount.target.display().to_string(), "socket target")?,
                    // A socket bind stays writable: `connect(2)` is refused on a
                    // read-only mount for some filesystems.
                    read_only: false,
                });
            }
        }

        let mut mkdirs = Vec::new();
        for dir in mount_directories(spec.mounts, spec.gui) {
            mkdirs.push(cstring(&dir, "mkdir path")?);
        }

        let hostname = if plan.toggles.uts {
            Some(cstring(spec.hostname, "hostname")?)
        } else {
            None
        };

        let program = cstring(spec.program, "program")?;
        let mut argv = Vec::with_capacity(spec.args.len() + 1);
        argv.push(cstring(spec.program, "argv[0]")?);
        for arg in spec.args {
            argv.push(cstring(arg, "argument")?);
        }
        let mut envp = Vec::with_capacity(spec.env.len());
        for (key, value) in spec.env {
            if key.is_empty() || key.contains('=') {
                return Err(ContainerError::Spec(format!(
                    "invalid environment variable name: {key:?}"
                )));
            }
            envp.push(cstring(&format!("{key}={value}"), "environment entry")?);
        }

        Ok(Self {
            unshare_flags: plan.unshare_flags(),
            uid_map,
            gid_map,
            root,
            root_mode: spec.root_mode,
            root_tmpfs_opts,
            root_binds,
            read_only_root: spec.read_only_root,
            tmpfs_mounts,
            mkdirs,
            binds,
            proc_target,
            hostname,
            claim_tty: spec.claim_tty,
            program,
            argv,
            envp,
        })
    }

    /// Stages this program will touch, for diagnostics and tests.
    #[cfg(test)]
    pub fn stages(&self) -> Vec<&'static str> {
        let mut stages = Vec::new();
        if self.unshare_flags != 0 {
            stages.push("unshare");
        }
        if self.uid_map.is_some() {
            stages.extend(["setgroups", "uid_map", "gid_map"]);
        }
        if self.unshare_flags & libc::CLONE_NEWNS != 0 {
            stages.extend([
                "mount-private",
                "tmpfs-root",
                "bind-root-entry",
                "chroot",
                "chdir",
                "mount-tmpfs",
                "mkdir",
                "mount-bind",
            ]);
        }
        if self.hostname.is_some() {
            stages.push("sethostname");
        }
        stages.extend(["fork", "setsid", "execve"]);
        stages
    }

    /// Entry point for the `pre_exec` closure. **Never returns.**
    pub(crate) fn run_for_closure(&self) -> ! {
        run_child(self)
    }
}

// ─── The child ─────────────────────────────────────────────────

/// Run the child program. **Never returns.**
///
/// Must only be called in a forked child that will either `execve` or `_exit`,
/// never return to Rust code that allocates.
pub(crate) fn run_child(program: &ChildProgram) -> ! {
    let mount_ns = program.unshare_flags & libc::CLONE_NEWNS != 0;

    if program.unshare_flags != 0 && unsafe { libc::unshare(program.unshare_flags) } != 0 {
        child_fail(0, b"unshare");
    }
    if let Some(map) = &program.uid_map {
        // Best-effort: /proc/self/setgroups is absent before Linux 3.19.
        write_path(c"/proc/self/setgroups", b"deny");
        if !write_path(c"/proc/self/uid_map", map.as_bytes()) {
            child_fail(2, b"uid_map");
        }
    }
    if let Some(map) = &program.gid_map {
        if !write_path(c"/proc/self/gid_map", map.as_bytes()) {
            child_fail(3, b"gid_map");
        }
    }

    if mount_ns {
        if !make_private_root() {
            child_fail(4, b"make-rprivate");
        }
        if program.root_mode == RootMode::TmpfsBind {
            let mounted = unsafe {
                libc::mount(
                    c"tmpfs".as_ptr(),
                    program.root.as_ptr(),
                    c"tmpfs".as_ptr(),
                    (libc::MS_NOSUID | libc::MS_NODEV) as libc::c_ulong,
                    program.root_tmpfs_opts.as_ptr().cast(),
                )
            };
            if mounted != 0 {
                child_fail(5, b"tmpfs-root");
            }
            for (source, target) in &program.root_binds {
                // mkdirat is best-effort: the entry may already exist.
                unsafe {
                    libc::mkdirat(libc::AT_FDCWD, target.as_ptr(), 0o755);
                }
                if !bind_path(source, target) || !maybe_remount_ro(target, program.read_only_root)
                {
                    child_fail(6, b"bind-root-entry");
                }
            }
        }
    }

    // chroot is independent of the mount namespace: even a privileged (level 4)
    // container is confined to its root directory.
    if unsafe { libc::chroot(program.root.as_ptr()) } != 0 {
        child_fail(7, b"chroot");
    }
    if unsafe { libc::chdir(c"/".as_ptr()) } != 0 {
        child_fail(8, b"chdir");
    }

    if mount_ns {
        for (target, opts) in &program.tmpfs_mounts {
            let mounted = unsafe {
                libc::mount(
                    c"tmpfs".as_ptr(),
                    target.as_ptr(),
                    c"tmpfs".as_ptr(),
                    (libc::MS_NOSUID | libc::MS_NODEV) as libc::c_ulong,
                    opts.as_ptr().cast(),
                )
            };
            if mounted != 0 {
                child_fail(9, b"mount-tmpfs");
            }
        }
        for dir in &program.mkdirs {
            let made = unsafe { libc::mkdirat(libc::AT_FDCWD, dir.as_ptr(), 0o755) };
            if made != 0 && last_errno() != libc::EEXIST {
                child_fail(10, b"mkdir");
            }
        }
        for bind in &program.binds {
            // The mount target must exist; an empty file is enough for both
            // device nodes and sockets.
            let fd = unsafe {
                libc::open(
                    bind.target.as_ptr(),
                    libc::O_CREAT | libc::O_WRONLY | libc::O_CLOEXEC,
                    0o644,
                )
            };
            if fd >= 0 {
                unsafe {
                    libc::close(fd);
                }
            } else if last_errno() != libc::EEXIST {
                child_fail(11, b"create bind target");
            }
            let mounted = unsafe {
                libc::mount(
                    bind.source.as_ptr(),
                    bind.target.as_ptr(),
                    std::ptr::null(),
                    (libc::MS_BIND | libc::MS_REC) as libc::c_ulong,
                    std::ptr::null(),
                )
            };
            if mounted != 0 {
                child_fail(11, b"mount-bind");
            }
            if !maybe_remount_ro(&bind.target, bind.read_only) {
                child_fail(11, b"remount-ro");
            }
        }
        if let Some(hostname) = &program.hostname {
            let len = hostname.as_bytes().len();
            if unsafe { libc::sethostname(hostname.as_ptr(), len) } != 0 {
                child_fail(12, b"sethostname");
            }
        }
    }

    // Fork into the PID namespace: the grandchild becomes PID 1 there. A raw
    // SYS_fork keeps glibc's atfork handlers (and their locks) out.
    let pid = unsafe { libc::syscall(libc::SYS_fork) };
    if pid < 0 {
        child_fail(13, b"fork");
    }
    if pid > 0 {
        // Supervisor: reap the container and mirror its status.
        let mut status: libc::c_int = 0;
        loop {
            let reaped = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
            if reaped == pid as libc::pid_t {
                break;
            }
            if reaped < 0 && last_errno() != libc::EINTR {
                unsafe { libc::_exit(127) };
            }
        }
        let code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else if libc::WIFSIGNALED(status) {
            128 + libc::WTERMSIG(status)
        } else {
            127
        };
        unsafe { libc::_exit(code) };
    }

    // ── PID 1 of the container ──
    if let Some(proc_target) = &program.proc_target {
        let mounted = unsafe {
            libc::mount(
                c"proc".as_ptr(),
                proc_target.as_ptr(),
                c"proc".as_ptr(),
                (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as libc::c_ulong,
                std::ptr::null(),
            )
        };
        if mounted != 0 {
            child_fail(14, b"mount-proc");
        }
    }
    if unsafe { libc::setsid() } < 0 {
        child_fail(15, b"setsid");
    }
    if program.claim_tty
        && unsafe { libc::ioctl(0, libc::TIOCSCTTY as libc::c_ulong, 0) } != 0
    {
        child_fail(16, b"TIOCSCTTY");
    }

    exec(&program.program, &program.argv, &program.envp)
}

// ─── Raw syscall helpers (async-signal-safe) ───────────────────

#[inline]
fn last_errno() -> libc::c_int {
    // SAFETY: __errno_location is thread-local and always valid.
    unsafe { *libc::__errno_location() }
}

fn make_private_root() -> bool {
    let rc = unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
            std::ptr::null(),
        )
    };
    rc == 0
}

fn bind_path(source: &CString, target: &CString) -> bool {
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            (libc::MS_BIND | libc::MS_REC) as libc::c_ulong,
            std::ptr::null(),
        )
    };
    rc == 0
}

fn maybe_remount_ro(path: &CString, read_only: bool) -> bool {
    if !read_only {
        return true;
    }
    let rc = unsafe {
        libc::mount(
            std::ptr::null(),
            path.as_ptr(),
            std::ptr::null(),
            (libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY) as libc::c_ulong,
            std::ptr::null(),
        )
    };
    rc == 0
}

/// `execve(2)` the payload with fixed-size, `NULL`-terminated pointer arrays.
///
/// Runs in the container's PID 1 after the final fork, so it is async-signal
/// safe by construction: the arrays live on the stack and are filled by a
/// pointer copy from `CString`s the parent allocated in
/// [`ChildProgram::build`] *before* the fork. No allocation, no formatting and
/// no panics happen here.
///
/// Indices `0..MAX_EXEC_VECTORS` receive every entry — including the 64th
/// argument — and index `MAX_EXEC_VECTORS` keeps the `NULL` terminator (G-L15).
fn exec(program: &CString, argv: &[CString], envp: &[CString]) -> ! {
    let mut argv_ptrs: [*const libc::c_char; MAX_EXEC_PTRS] =
        [std::ptr::null(); MAX_EXEC_PTRS];
    for (index, arg) in argv.iter().enumerate().take(MAX_EXEC_VECTORS) {
        argv_ptrs[index] = arg.as_ptr();
    }
    let mut envp_ptrs: [*const libc::c_char; MAX_EXEC_PTRS] =
        [std::ptr::null(); MAX_EXEC_PTRS];
    for (index, var) in envp.iter().enumerate().take(MAX_EXEC_VECTORS) {
        envp_ptrs[index] = var.as_ptr();
    }
    unsafe {
        libc::execve(program.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
    }
    child_fail_errno(17, b"execve", last_errno())
}

/// Like [`child_fail`], but appends ` errno=<n>` so the parent log names the
/// actual kernel refusal (e.g. `execve errno=2` for a missing interpreter).
fn child_fail_errno(stage: i32, what: &[u8], errno: libc::c_int) -> ! {
    let mut buf = [0u8; 96];
    let mut len = 0;
    for byte in b"extos-container: ".iter().chain(what.iter()) {
        if len >= buf.len() {
            break;
        }
        buf[len] = *byte;
        len += 1;
    }
    for byte in b" errno=" {
        if len >= buf.len() {
            break;
        }
        buf[len] = *byte;
        len += 1;
    }
    let mut digits = [0u8; 12];
    let mut count = 0;
    let mut value = errno.unsigned_abs();
    loop {
        digits[count] = b'0' + (value % 10) as u8;
        value /= 10;
        count += 1;
        if value == 0 {
            break;
        }
    }
    while count > 0 && len < buf.len() {
        count -= 1;
        buf[len] = digits[count];
        len += 1;
    }
    unsafe {
        libc::write(2, buf.as_ptr().cast(), len);
        libc::_exit(CHILD_EXIT_SETUP_BASE + stage);
    }
}

/// Write diagnostics to fd 2 and exit with `CHILD_EXIT_SETUP_BASE + stage`.
fn child_fail(stage: i32, what: &[u8]) -> ! {
    let mut buf = [0u8; 64];
    let prefix = b"extos-container: ";
    let mut len = 0;
    for byte in prefix.iter().chain(what.iter()) {
        if len == buf.len() {
            break;
        }
        buf[len] = *byte;
        len += 1;
    }
    unsafe {
        libc::write(2, buf.as_ptr().cast(), len);
        libc::_exit(CHILD_EXIT_SETUP_BASE + stage);
    }
}

/// Open `path` and write `bytes`, returning success.
fn write_path(path: &CStr, bytes: &[u8]) -> bool {
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return false;
    }
    let mut written = 0usize;
    while written < bytes.len() {
        let n = unsafe {
            libc::write(
                fd,
                bytes.as_ptr().add(written).cast(),
                bytes.len() - written,
            )
        };
        if n <= 0 {
            unsafe { libc::close(fd) };
            return false;
        }
        written += n as usize;
    }
    unsafe { libc::close(fd) };
    true
}

/// Report a failed namespace step as a typed error (parent-side helper).
pub(crate) fn namespace_failure(stage: &'static str, errno: i32) -> ContainerError {
    ns_err(stage, errno)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::gui::assemble_gui_spec;
    use crate::container::mounts::HostPaths;

    fn env() -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        map.insert("PATH".to_string(), "/usr/bin".to_string());
        map
    }

    fn child_spec<'a>(
        plan: &'a NamespacePlan,
        mounts: &'a MountPlan,
        top_level: &'a [String],
        env_map: &'a BTreeMap<String, String>,
        args: &'a [String],
        gui: Option<&'a GuiSpec>,
    ) -> ChildSpec<'a> {
        ChildSpec {
            plan,
            root: Path::new("/tmp/extos-root"),
            root_mode: RootMode::TmpfsBind,
            top_level,
            read_only_root: true,
            mounts,
            gui,
            hostname: "extos-test",
            program: "/bin/prog",
            args,
            env: env_map,
            claim_tty: true,
            tmpfs_size_kib: 8192,
        }
    }

    #[test]
    fn unshare_flags_follow_the_toggles() {
        let plan = NamespacePlan::for_level(IsolationLevel::Isolated);
        let flags = plan.unshare_flags();
        assert_ne!(flags & libc::CLONE_NEWUSER, 0);
        assert_ne!(flags & libc::CLONE_NEWNS, 0);
        assert_ne!(flags & libc::CLONE_NEWPID, 0);
        assert_ne!(flags & libc::CLONE_NEWIPC, 0);
        assert_ne!(flags & libc::CLONE_NEWUTS, 0);
        assert_ne!(flags & libc::CLONE_NEWNET, 0);
        assert_eq!(flags & libc::CLONE_NEWCGROUP, 0);

        let networked = NamespacePlan::for_level(IsolationLevel::Networked);
        assert_eq!(networked.unshare_flags() & libc::CLONE_NEWNET, 0);
        assert_ne!(networked.unshare_flags() & libc::CLONE_NEWUSER, 0);

        let privileged = NamespacePlan::for_level(IsolationLevel::Privileged);
        assert_eq!(privileged.unshare_flags(), 0);
    }

    #[test]
    fn syscall_sequence_is_documented_order() {
        let plan = NamespacePlan::for_level(IsolationLevel::Cli);
        let steps = plan.syscall_sequence();
        assert_eq!(steps.first().copied(), Some("unshare"));
        assert_eq!(steps.last().copied(), Some("execve"));
        assert!(steps.contains(&"uid_map"));
        assert!(steps.contains(&"chroot"));
        assert!(steps.contains(&"fork"));
    }

    #[test]
    fn child_program_prebuilds_every_path() {
        let plan = NamespacePlan::for_level(IsolationLevel::Cli);
        let mounts = MountPlan::for_level(IsolationLevel::Cli, &HostPaths::default(), 8192);
        let top_level = vec!["bin".to_string(), "usr".to_string()];
        let env_map = env();
        let args = vec!["-c".to_string(), "echo hi".to_string()];
        let program = ChildProgram::build(&child_spec(
            &plan, &mounts, &top_level, &env_map, &args, None,
        ))
        .unwrap();
        assert!(program.stages().contains(&"chroot"));
        assert_eq!(program.argv.len(), 3);
        assert_eq!(program.envp.len(), 1);
        assert!(program.proc_target.is_some());
        assert_eq!(
            program.hostname.as_ref().unwrap().to_str().unwrap(),
            "extos-test"
        );
        assert_eq!(
            program.root_binds[1].1.to_str().unwrap(),
            "/tmp/extos-root/.extos-root/usr"
        );
    }

    #[test]
    fn relative_program_is_rejected_with_a_typed_error() {
        let plan = NamespacePlan::for_level(IsolationLevel::Cli);
        let mounts = MountPlan::for_level(IsolationLevel::Cli, &HostPaths::default(), 4096);
        let top_level: Vec<String> = vec![];
        let env_map = env();
        let args: Vec<String> = vec![];
        let mut spec = child_spec(&plan, &mounts, &top_level, &env_map, &args, None);
        spec.program = "bin/sh";
        let err = ChildProgram::build(&spec).unwrap_err();
        assert!(err.to_string().contains("absolute"));
    }

    #[test]
    fn too_many_arguments_is_a_typed_error() {
        let plan = NamespacePlan::for_level(IsolationLevel::Cli);
        let mounts = MountPlan::for_level(IsolationLevel::Cli, &HostPaths::default(), 4096);
        let top_level: Vec<String> = vec![];
        let env_map = env();
        let args: Vec<String> = (0..MAX_EXEC_VECTORS).map(|i| i.to_string()).collect();
        let err = ChildProgram::build(&child_spec(
            &plan, &mounts, &top_level, &env_map, &args, None,
        ))
        .unwrap_err();
        assert!(err.to_string().contains("too many"));
    }

    #[test]
    fn maximum_arguments_are_all_kept_in_the_pointer_array() {
        // Boundary of the G-L15 fix: `program + 63 args` is exactly
        // `MAX_EXEC_VECTORS` argv entries and must be accepted, not truncated.
        let plan = NamespacePlan::for_level(IsolationLevel::Cli);
        let mounts = MountPlan::for_level(IsolationLevel::Cli, &HostPaths::default(), 4096);
        let top_level: Vec<String> = vec![];
        let env_map = env();
        let args: Vec<String> = (0..MAX_EXEC_VECTORS - 1).map(|i| i.to_string()).collect();
        let program = ChildProgram::build(&child_spec(
            &plan, &mounts, &top_level, &env_map, &args, None,
        ))
        .expect("program + 63 arguments is legal");
        assert_eq!(program.argv.len(), MAX_EXEC_VECTORS);
        assert_eq!(program.argv[0].to_str().unwrap(), "/bin/prog");
        assert_eq!(
            program.argv[MAX_EXEC_VECTORS - 1].to_str().unwrap(),
            (MAX_EXEC_VECTORS - 2).to_string()
        );

        // One argument more is one vector too many.
        let extra: Vec<String> = (0..MAX_EXEC_VECTORS).map(|i| i.to_string()).collect();
        let err = ChildProgram::build(&child_spec(
            &plan, &mounts, &top_level, &env_map, &extra, None,
        ))
        .unwrap_err();
        assert!(err.to_string().contains("too many"));
    }

    #[test]
    fn top_level_entries_reject_path_separators() {
        let plan = NamespacePlan::for_level(IsolationLevel::Cli);
        let mounts = MountPlan::for_level(IsolationLevel::Cli, &HostPaths::default(), 4096);
        let top_level = vec!["../etc".to_string()];
        let env_map = env();
        let args: Vec<String> = vec![];
        let err = ChildProgram::build(&child_spec(
            &plan, &mounts, &top_level, &env_map, &args, None,
        ))
        .unwrap_err();
        assert!(err.to_string().contains("invalid rootfs"));
    }

    #[test]
    fn gui_sockets_become_binds() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = tmp.path().join("runtime");
        std::fs::create_dir_all(&runtime).unwrap();
        let sock = runtime.join("wayland-1");
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();

        let gui_env = crate::container::GuiEnv {
            xdg_runtime_dir: Some(runtime.clone()),
            wayland_display: Some("wayland-1".into()),
            ..Default::default()
        };
        let gui = assemble_gui_spec(&[crate::manifest::ContainerSocket::Wayland], &gui_env);

        let plan = NamespacePlan::for_level(IsolationLevel::Gui);
        let mounts = MountPlan::for_level(IsolationLevel::Gui, &HostPaths::default(), 4096);
        let top_level: Vec<String> = vec!["usr".to_string()];
        let env_map = env();
        let args: Vec<String> = vec![];
        let program = ChildProgram::build(&child_spec(
            &plan,
            &mounts,
            &top_level,
            &env_map,
            &args,
            Some(&gui),
        ))
        .unwrap();
        assert!(program
            .binds
            .iter()
            .any(|b| b.target.to_str().unwrap() == "/run/user/0/wayland-1"));
        assert!(program
            .mkdirs
            .iter()
            .any(|d| d.to_str().unwrap() == "/run/user/0"));
        drop(listener);
    }

    #[test]
    fn exit_code_maps_back_to_stage() {
        assert_eq!(stage_for_exit_code(CHILD_EXIT_SETUP_BASE), Some("unshare"));
        assert_eq!(
            stage_for_exit_code(CHILD_EXIT_SETUP_BASE + 7),
            Some("chroot")
        );
        assert_eq!(stage_for_exit_code(1), None);
        assert_eq!(stage_for_exit_code(200), None);
    }

    #[test]
    fn child_exit_error_is_typed() {
        let err = child_exit_error(CHILD_EXIT_SETUP_BASE + 5).unwrap();
        match err {
            ContainerError::Namespace { op, .. } => assert_eq!(op, "tmpfs-root"),
            other => panic!("unexpected {other:?}"),
        }
        assert!(child_exit_error(0).is_none());
    }

    #[test]
    fn empty_hostname_is_rejected() {
        let plan = NamespacePlan::for_level(IsolationLevel::Cli);
        let mounts = MountPlan::for_level(IsolationLevel::Cli, &HostPaths::default(), 4096);
        let top_level: Vec<String> = vec![];
        let env_map = env();
        let args: Vec<String> = vec![];
        let mut spec = child_spec(&plan, &mounts, &top_level, &env_map, &args, None);
        spec.hostname = "";
        assert!(ChildProgram::build(&spec).is_err());
    }
}
