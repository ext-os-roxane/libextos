//! Forge execution: run a tool inside the tmpfs namespace (PLAN 4.2.2).
//!
//! Two interchangeable strategies produce the same observable effect — the
//! program runs with the [`MountPlan`] applied, its output captured, and the
//! namespace torn down when it exits:
//!
//! * [`NamespaceStrategy::SelfExec`] — `std::process::Command` with a
//!   `pre_exec` closure that calls [`MountPlan::apply_in_child`]. No helper
//!   binary, no shell: the child goes straight from `fork(2)` to the syscall
//!   sequence and then `execve(2)`.
//! * [`NamespaceStrategy::UnshareCli`] — util-linux `unshare` creates the
//!   namespaces, then a generated `mount(8)` script applies the plan and
//!   `exec`s the tool. Needs `unshare`, `mount` and a POSIX shell in the
//!   namespace (all supplied by the host runtime binds).
//!
//! Selection is explicit ([`ForgeConfig::strategy`]) or environmental:
//! `EXTOS_FORGE_NS=self|unshare`. `SelfExec` is the default because it needs no
//! external tooling beyond what the blueprint already provides.
//!
//! # Why there is no cleanup step
//!
//! Everything is mounted in a *new* mount namespace owned by a *new* user
//! namespace. When the last process leaves it the kernel drops the namespace and
//! with it every mount; the host tree never showed them. The only host-visible
//! side effects are the forge root directory (`<scratch>/forge`, empty again)
//! and whatever the tool wrote through the `<forge>/out` bind.

use std::ffi::{CString, OsString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;

use super::mount::MountPlan;
use super::{ForgeError, ForgeResult};

/// Environment variable selecting the namespace strategy.
pub const ENV_STRATEGY: &str = "EXTOS_FORGE_NS";

/// Environment variable overriding the `unshare` binary.
pub const ENV_UNSHARE: &str = "EXTOS_FORGE_UNSHARE";

/// Environment variable overriding the shell used by the CLI strategy.
pub const ENV_SHELL: &str = "EXTOS_FORGE_SHELL";

/// How the forge enters its namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceStrategy {
    /// `fork(2)` + `pre_exec` + direct `unshare(2)`/`mount(2)` syscalls.
    SelfExec,
    /// util-linux `unshare` + a generated `mount(8)` script.
    UnshareCli,
}

impl NamespaceStrategy {
    /// Blueprint/environment spelling: `"self"` or `"unshare"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SelfExec => "self",
            Self::UnshareCli => "unshare",
        }
    }

    /// Parse `"self"` / `"unshare"` (`"cli"` and `"direct"` are aliases).
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "self" | "direct" | "pre-exec" | "preexec" => Some(Self::SelfExec),
            "unshare" | "cli" | "wrapper" => Some(Self::UnshareCli),
            _ => None,
        }
    }
}

impl Default for NamespaceStrategy {
    fn default() -> Self {
        Self::SelfExec
    }
}

/// Runtime configuration for a forge run.
#[derive(Debug, Clone)]
pub struct ForgeConfig {
    /// Namespace strategy.
    pub strategy: NamespaceStrategy,
    /// `unshare` binary used by [`NamespaceStrategy::UnshareCli`].
    pub unshare_program: String,
    /// Shell used by [`NamespaceStrategy::UnshareCli`].
    pub shell: String,
}

impl Default for ForgeConfig {
    fn default() -> Self {
        Self {
            strategy: NamespaceStrategy::default(),
            unshare_program: "unshare".into(),
            shell: "sh".into(),
        }
    }
}

impl ForgeConfig {
    /// Read overrides from the environment.
    ///
    /// * `EXTOS_FORGE_NS` — `self` (default) or `unshare`;
    /// * `EXTOS_FORGE_UNSHARE` — replacement for the `unshare` binary;
    /// * `EXTOS_FORGE_SHELL` — replacement for `sh`.
    ///
    /// Unknown strategy words are ignored (the default is kept) rather than
    /// failing the whole run: the strategy is not part of the artifact.
    pub fn from_env() -> Self {
        let mut config = Self::default();
        if let Ok(value) = std::env::var(ENV_STRATEGY)
            && let Some(strategy) = NamespaceStrategy::parse(&value)
        {
            config.strategy = strategy;
        }
        if let Ok(value) = std::env::var(ENV_UNSHARE)
            && !value.trim().is_empty()
        {
            config.unshare_program = value;
        }
        if let Ok(value) = std::env::var(ENV_SHELL)
            && !value.trim().is_empty()
        {
            config.shell = value;
        }
        config
    }

    /// Builder helper: use a specific strategy.
    pub fn with_strategy(mut self, strategy: NamespaceStrategy) -> Self {
        self.strategy = strategy;
        self
    }
}

/// One program invocation inside a forge.
#[derive(Debug, Clone)]
pub struct ForgeCommand {
    /// Program name or in-forge absolute path.
    pub program: String,
    /// Arguments, passed verbatim.
    pub args: Vec<String>,
    /// Extra environment variables.
    pub env: Vec<(String, String)>,
    /// Override for the in-forge working directory (`None` = the plan default).
    ///
    /// A non-zero exit is *not* an error for [`Forge::run`];
    /// [`ForgeOutcome::require_success`] is the explicit check.
    pub workdir: Option<String>,
}

impl ForgeCommand {
    /// A command for `program`.
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
            workdir: None,
        }
    }

    /// Append one argument.
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Append several arguments.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Add an environment variable.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Run in a different in-forge directory.
    pub fn workdir(mut self, workdir: impl Into<String>) -> Self {
        self.workdir = Some(workdir.into());
        self
    }
}

/// Result of a forge run.
#[derive(Debug, Clone)]
pub struct ForgeOutcome {
    /// Exit status of the tool.
    pub status: ExitStatus,
    /// Captured stdout.
    pub stdout: String,
    /// Captured stderr.
    pub stderr: String,
}

impl ForgeOutcome {
    /// True when the tool exited with status 0.
    pub fn success(&self) -> bool {
        self.status.success()
    }

    /// Captured stderr without trailing whitespace.
    pub fn stderr_trimmed(&self) -> &str {
        self.stderr.trim_end()
    }

    /// Captured stdout without trailing whitespace.
    pub fn stdout_trimmed(&self) -> &str {
        self.stdout.trim_end()
    }

    /// Turn a non-zero exit into [`ForgeError::ToolFailed`], returning `self`
    /// (via `Ok`) on success.
    pub fn require_success(self, program: &str) -> ForgeResult<Self> {
        if self.status.success() {
            return Ok(self);
        }
        Err(ForgeError::ToolFailed {
            program: program.to_string(),
            status: describe_status(&self.status),
            stderr: self.stderr_trimmed().to_string(),
        })
    }
}

fn describe_status(status: &ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    if let Some(code) = status.code() {
        format!("exited with {code}")
    } else if let Some(signal) = status.signal() {
        format!("killed by signal {signal}")
    } else {
        format!("{status}")
    }
}

/// A forge bound to one plan.
#[derive(Debug)]
pub struct Forge {
    plan: Arc<MountPlan>,
    config: ForgeConfig,
}

impl Forge {
    /// Bind `plan` to `config`.
    pub fn new(plan: MountPlan, config: ForgeConfig) -> Self {
        Self {
            plan: Arc::new(plan),
            config,
        }
    }

    /// Bind `plan` with the default configuration.
    pub fn with_defaults(plan: MountPlan) -> Self {
        Self::new(plan, ForgeConfig::default())
    }

    /// The mount plan.
    pub fn plan(&self) -> &MountPlan {
        &self.plan
    }

    /// The configuration.
    pub fn config(&self) -> &ForgeConfig {
        &self.config
    }

    /// Run `command` inside the forge and capture its output.
    ///
    /// [`ForgeError::ToolFailed`] is *not* raised here — a non-zero exit is a
    /// regular outcome; call [`ForgeOutcome::require_success`] to promote it.
    /// Spawn failures are classified through [`ForgeError::from_io`].
    pub fn run(&self, command: &ForgeCommand) -> ForgeResult<ForgeOutcome> {
        match self.config.strategy {
            NamespaceStrategy::SelfExec => self.run_self_exec(command),
            NamespaceStrategy::UnshareCli => self.run_unshare_cli(command),
        }
    }

    /// Raw `fork`/`pre_exec` strategy.
    fn run_self_exec(&self, command: &ForgeCommand) -> ForgeResult<ForgeOutcome> {
        let mut child = Command::new(&command.program);
        child.args(&command.args);
        for (key, value) in &command.env {
            child.env(key, value);
        }
        child.stdin(Stdio::null());
        child.stdout(Stdio::piped());
        child.stderr(Stdio::piped());

        // `chdir(2)` must happen *after* the mounts, so the working directory is
        // resolved inside the forge; it is prepared before the fork because
        // `CString` allocation is not async-signal-safe.
        let workdir = CString::new(
            self.resolve_workdir(command)
                .as_os_str()
                .as_bytes()
                .to_vec(),
        )
        .map_err(|_| ForgeError::MountFailed {
            target: "workdir".into(),
            message: "working directory contains a NUL byte".into(),
        })?;

        // SAFETY: `apply_in_child_in` only performs async-signal-safe syscalls on
        // buffers prepared before the fork (see `mount` module docs). It is the
        // canonical use of `pre_exec`.
        let plan = Arc::clone(&self.plan);
        unsafe {
            child.pre_exec(move || plan.apply_in_child_in(Some(&workdir)));
        }

        // A `pre_exec` failure and an `execve` failure both surface here as the
        // child's `errno`; the label names the whole child phase rather than
        // pretending to know which syscall failed (see `ForgeError::from_io`).
        let output = child
            .output()
            .map_err(|error| ForgeError::from_io(error, "forge child (namespace + exec)"))?;
        Ok(ForgeOutcome {
            status: output.status,
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    /// util-linux `unshare` + generated `mount(8)` script strategy.
    fn run_unshare_cli(&self, command: &ForgeCommand) -> ForgeResult<ForgeOutcome> {
        let script = self.cli_script(command);
        let mut child = Command::new(&self.config.unshare_program);
        child.args([
            "--user",
            "--map-root-user",
            "--mount",
            "--propagation",
            "private",
            "--",
            &self.config.shell,
            "-c",
            &script,
        ]);
        // `sh -c script name arg…`: the program becomes `$0`, exactly what the
        // trailing `exec "$0" "$@"` in the script needs.
        child.arg(&command.program);
        child.args(&command.args);
        for (key, value) in &command.env {
            child.env(key, value);
        }
        child.stdin(Stdio::null());
        child.stdout(Stdio::piped());
        child.stderr(Stdio::piped());

        let output = child
            .output()
            .map_err(|error| ForgeError::from_io(error, "unshare"))?;
        Ok(ForgeOutcome {
            status: output.status,
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    /// Argument vector the CLI strategy builds for `command` (test surface).
    pub fn cli_argv(&self, command: &ForgeCommand) -> Vec<OsString> {
        let mut argv: Vec<OsString> = vec![
            self.config.unshare_program.clone().into(),
            "--user".into(),
            "--map-root-user".into(),
            "--mount".into(),
            "--propagation".into(),
            "private".into(),
            "--".into(),
            self.config.shell.clone().into(),
            "-c".into(),
            self.cli_script(command).into(),
        ];
        argv.push(command.program.clone().into());
        argv.extend(command.args.iter().map(OsString::from));
        argv
    }

    /// Mount script + working directory + `exec` epilogue for the CLI strategy.
    pub fn cli_script(&self, command: &ForgeCommand) -> String {
        let mut script = self.plan.mount_script();
        script.push_str(&format!(
            "cd {}\n",
            super::mount::shell_quote(&self.resolve_workdir(command).to_string_lossy())
        ));
        script.push_str("exec \"$0\" \"$@\"\n");
        script
    }

    /// Working directory for `command`: its override, else the plan default.
    fn resolve_workdir(&self, command: &ForgeCommand) -> PathBuf {
        match &command.workdir {
            Some(workdir) => PathBuf::from(workdir),
            None => self.plan.workdir().to_path_buf(),
        }
    }
}

/// Check whether unprivileged user namespaces are usable on this host.
///
/// Runs `unshare --user --map-root-user true` through [`ForgeConfig`]; returns
/// `Ok(())` when that succeeds. The probe needs the util-linux `unshare` binary
/// even for [`NamespaceStrategy::SelfExec`], so a missing binary reports
/// "unavailable" rather than attempting a raw `unshare(2)` probe. Used by tests and callers that want an honest
/// "cannot forge here" message instead of a failed artifact.
pub fn probe_unprivileged_userns(config: &ForgeConfig) -> Result<(), ForgeError> {
    let output = Command::new(&config.unshare_program)
        .args(["--user", "--map-root-user", "--", "true"])
        .stdin(Stdio::null())
        .output()
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("{} --user: {error}", config.unshare_program),
            )
        })?;
    if output.status.success() {
        Ok(())
    } else {
        Err(ForgeError::NamespaceUnavailable {
            message: format!(
                "unprivileged user namespaces are unavailable: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strategy_parse_and_spelling() {
        assert_eq!(
            NamespaceStrategy::parse("self"),
            Some(NamespaceStrategy::SelfExec)
        );
        assert_eq!(
            NamespaceStrategy::parse(" DIRECT "),
            Some(NamespaceStrategy::SelfExec)
        );
        assert_eq!(
            NamespaceStrategy::parse("unshare"),
            Some(NamespaceStrategy::UnshareCli)
        );
        assert_eq!(
            NamespaceStrategy::parse("cli"),
            Some(NamespaceStrategy::UnshareCli)
        );
        assert_eq!(NamespaceStrategy::parse("bogus"), None);
        assert_eq!(NamespaceStrategy::default().as_str(), "self");
    }

    #[test]
    fn test_config_defaults() {
        let config = ForgeConfig::default();
        assert_eq!(config.strategy, NamespaceStrategy::SelfExec);
        assert_eq!(config.unshare_program, "unshare");
        assert_eq!(config.shell, "sh");
        assert_eq!(
            config.with_strategy(NamespaceStrategy::UnshareCli).strategy,
            NamespaceStrategy::UnshareCli
        );
    }

    #[test]
    fn test_command_builder() {
        let command = ForgeCommand::new("mkinitcpio")
            .arg("-g")
            .args(["/out/img", "-p", "linux"])
            .env("K", "V")
            .workdir("/w");
        assert_eq!(command.program, "mkinitcpio");
        assert_eq!(command.args, ["-g", "/out/img", "-p", "linux"]);
        assert_eq!(command.env, [("K".to_string(), "V".to_string())]);
        assert_eq!(command.workdir.as_deref(), Some("/w"));
    }

    #[test]
    fn test_status_description() {
        use std::os::unix::process::ExitStatusExt;
        let exited = ExitStatus::from_raw(3 << 8);
        assert_eq!(describe_status(&exited), "exited with 3");
        let signalled = ExitStatus::from_raw(9);
        assert_eq!(describe_status(&signalled), "killed by signal 9");
    }
}
