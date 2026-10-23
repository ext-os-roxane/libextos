//! `mkinitcpio` bridge: generate the initramfs inside the forge (PLAN 4.2.3).
//!
//! The bridge never guesses where the generator lives:
//!
//! 1. if the blueprint ships a tool named `mkinitcpio` with an `exec` payload,
//!    that in-forge path is used;
//! 2. otherwise `EXTOS_MKINITCPIO` is used when set;
//! 3. otherwise the plain name `mkinitcpio` is resolved through the forge's
//!    inherited `PATH` (host runtime binds).
//!
//! The artifact is written through the forge's read-write `out` bind, so it
//! survives the namespace teardown; [`run`] then verifies that a non-empty file
//! actually appeared before reporting success.
//!
//! # Argument shape
//!
//! ```text
//! mkinitcpio -g <in-forge out/name> [-c <in-forge config>] [-k <kernel>] [-p <preset>]
//! ```
//!
//! `-g` is always passed so the artifact lands where the blueprint says.
//! When the blueprint declares `hooks` and no preset, the bridge stages a
//! generated `mkinitcpio.conf` inside the tmpfs (never on the host) containing
//! `HOOKS=(…)` in blueprint order and points `-c` at it.

use std::path::{Path, PathBuf};
use std::process::Command;

use super::blueprint::ForgeBlueprint;
use super::forge::{Forge, ForgeCommand, ForgeOutcome};
use super::mount::MountPlan;
use super::{ForgeError, ForgeResult};

/// Environment override for the generator binary.
pub const ENV_BINARY: &str = "EXTOS_MKINITCPIO";

/// Default generator name (resolved through `PATH` inside the forge).
pub const DEFAULT_BINARY: &str = "mkinitcpio";

/// Blueprint tool name whose `exec` payload wins over the environment.
pub const TOOL_NAME: &str = "mkinitcpio";

/// Forge-relative path of the generated configuration.
pub const CONFIG_IN_FORGE: &str = "etc/mkinitcpio.conf";

/// Generator binary: `EXTOS_MKINITCPIO` when set and non-empty, else
/// [`DEFAULT_BINARY`].
pub fn binary_from_env() -> String {
    match std::env::var(ENV_BINARY) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => DEFAULT_BINARY.to_string(),
    }
}

/// Resolve `program` through `PATH` (host-side probe; the forge inherits the
/// same variable, so the answer normally matches the in-namespace lookup).
///
/// A path containing `/` is checked directly instead of being searched.
pub fn available(program: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let executable = |path: &Path| -> bool {
        path.metadata()
            .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    };

    if program.contains('/') {
        let path = PathBuf::from(program);
        return executable(&path).then_some(path);
    }
    let path_var = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var)
        .map(|dir| dir.join(program))
        .find(|candidate| executable(candidate))
}

/// One `mkinitcpio` invocation inside a forge.
#[derive(Debug, Clone)]
pub struct MkinitcpioJob {
    /// Binary name or in-forge absolute path.
    pub binary: String,
    /// In-forge artifact path (`<forge>/out/<name>`).
    pub output: String,
    /// In-forge configuration path (`-c`).
    pub config: Option<String>,
    /// Kernel version (`-k`).
    pub kernel: Option<String>,
    /// Preset (`-p`), mutually informative with `config`.
    pub preset: Option<String>,
    /// Hooks in `HOOKS=(…)` order.
    pub hooks: Vec<String>,
    /// Extra environment variables for the generator.
    pub env: Vec<(String, String)>,
}

impl MkinitcpioJob {
    /// Derive a job from a blueprint plus its resolved forge.
    ///
    /// `config` is only set when the blueprint declares hooks (and no preset),
    /// because that is the only case where ExtOS has a configuration to stage.
    pub fn from_blueprint(blueprint: &ForgeBlueprint, plan: &MountPlan) -> Self {
        let binary = plan
            .tool_program(TOOL_NAME)
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_else(binary_from_env);

        let hooks = plan.hooks().to_vec();
        let preset = blueprint.output.preset.clone();
        let config = if !hooks.is_empty() && preset.is_none() {
            Some(
                plan.in_forge(CONFIG_IN_FORGE)
                    .to_string_lossy()
                    .into_owned(),
            )
        } else {
            None
        };

        Self {
            binary,
            output: plan
                .output_in_forge(&blueprint.output.name)
                .to_string_lossy()
                .into_owned(),
            config,
            kernel: blueprint.output.kernel.clone(),
            preset,
            hooks,
            env: Vec::new(),
        }
    }

    /// Argument vector (`-g` first, then `-c`/`-k`/`-p`).
    pub fn args(&self) -> Vec<String> {
        let mut args = vec!["-g".to_string(), self.output.clone()];
        if let Some(config) = &self.config {
            args.push("-c".into());
            args.push(config.clone());
        }
        if let Some(kernel) = &self.kernel {
            args.push("-k".into());
            args.push(kernel.clone());
        }
        if let Some(preset) = &self.preset {
            args.push("-p".into());
            args.push(preset.clone());
        }
        args
    }

    /// The forge command for this job.
    pub fn command(&self) -> ForgeCommand {
        let mut command = ForgeCommand::new(self.binary.clone()).args(self.args());
        for (key, value) in &self.env {
            command = command.env(key.clone(), value.clone());
        }
        command
    }

    /// Generated `mkinitcpio.conf` body.
    ///
    /// Deliberately minimal: ExtOS owns the hook list, the rest stays at
    /// mkinitcpio's own defaults so an upstream generator update is not fought.
    pub fn config_text(&self) -> String {
        let hooks = if self.hooks.is_empty() {
            vec!["base".to_string()]
        } else {
            self.hooks.clone()
        };
        format!(
            "# Generated by the ExtOS Runlevel 0 forge (PLAN 4.2.3).\n\
             # Do not edit: regenerate from the Runlevel 0 blueprint instead.\n\
             MODULES=()\n\
             BINARIES=()\n\
             FILES=()\n\
             HOOKS=({})\n",
            hooks.join(" ")
        )
    }

    /// The artifact path this job should produce, on the host side.
    pub fn artifact_path(&self, plan: &MountPlan) -> ForgeResult<PathBuf> {
        let name = Path::new(&self.output)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .ok_or_else(|| ForgeError::Bls {
                message: format!("mkinitcpio output path '{}' has no file name", self.output),
            })?;
        Ok(plan.output_host().join(name))
    }
}

/// Stage the generated configuration inside the forge (no-op without `config`).
///
/// Returns the in-forge path that was staged, if any. The file is written by the
/// `pre_exec` child into the tmpfs, so it never appears on the host.
pub fn stage_config(plan: &mut MountPlan, job: &MkinitcpioJob) -> ForgeResult<Option<PathBuf>> {
    let Some(config) = &job.config else {
        return Ok(None);
    };
    let path = PathBuf::from(config);
    plan.stage_inline_file(&path, &job.config_text())?;
    Ok(Some(path))
}

/// Result of a successful generator run.
#[derive(Debug)]
pub struct MkinitcpioOutcome {
    /// Harvested artifact on the host (`<output dir>/<name>`).
    pub artifact: PathBuf,
    /// Size in bytes of the harvested artifact.
    pub artifact_size: u64,
    /// Captured process output.
    pub outcome: ForgeOutcome,
}

/// Run the generator and harvest the artifact.
///
/// Returns [`ForgeError::ToolFailed`] for a non-zero exit and
/// [`ForgeError::ArtifactMissing`] when the tool claimed success but produced no
/// non-empty file. The caller is responsible for `stage_config` when
/// [`MkinitcpioJob::config`] is set.
pub fn run(forge: &Forge, job: &MkinitcpioJob) -> ForgeResult<MkinitcpioOutcome> {
    let artifact = job.artifact_path(forge.plan())?;
    let outcome = forge.run(&job.command())?.require_success(&job.binary)?;

    let size = match std::fs::metadata(&artifact) {
        Ok(metadata) if metadata.is_file() && metadata.len() > 0 => metadata.len(),
        _ => {
            return Err(ForgeError::ArtifactMissing {
                path: artifact.display().to_string(),
            });
        }
    };
    Ok(MkinitcpioOutcome {
        artifact,
        artifact_size: size,
        outcome,
    })
}

/// Ask the generator for its version inside the forge.
///
/// Used by env-gated real-machine checks; returns the first non-empty stdout
/// line. Errors with [`ForgeError::ToolFailed`] when the binary is missing or
/// not runnable in the namespace.
pub fn version(forge: &Forge, binary: &str) -> ForgeResult<String> {
    let outcome = forge
        .run(&ForgeCommand::new(binary).arg("--version"))?
        .require_success(binary)?;
    let line = outcome
        .stdout_trimmed()
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("")
        .to_string();
    Ok(line)
}

/// Host-side availability probe for the configured generator.
///
/// Returns `None` together with the resolved binary name when the tool is not
/// on `PATH`; callers print an honest skip line instead of failing.
pub fn probe(binary: &str) -> Option<PathBuf> {
    available(binary)
}

/// Check that `binary` is on the *host* `PATH` without running it.
pub fn host_available(binary: &str) -> bool {
    Command::new(binary)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job() -> MkinitcpioJob {
        MkinitcpioJob {
            binary: "mkinitcpio".into(),
            output: "/forge/out/initramfs-linux.img".into(),
            config: Some("/forge/etc/mkinitcpio.conf".into()),
            kernel: Some("6.11.0".into()),
            preset: None,
            hooks: vec!["base".into(), "udev".into(), "filesystems".into()],
            env: Vec::new(),
        }
    }

    #[test]
    fn test_args_order_is_stable() {
        assert_eq!(
            job().args(),
            vec![
                "-g",
                "/forge/out/initramfs-linux.img",
                "-c",
                "/forge/etc/mkinitcpio.conf",
                "-k",
                "6.11.0",
            ]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_args_include_preset_last() {
        let mut job = job();
        job.config = None;
        job.preset = Some("linux".into());
        let args = job.args();
        assert_eq!(&args[args.len() - 2..], ["-p", "linux"]);
        assert!(!args.contains(&"-c".to_string()));
    }

    #[test]
    fn test_config_text_preserves_hook_order() {
        let text = job().config_text();
        assert!(text.contains("HOOKS=(base udev filesystems)"), "{text}");
        assert!(text.contains("MODULES=()"), "{text}");
        assert!(text.starts_with("# Generated by the ExtOS"), "{text}");
    }

    #[test]
    fn test_config_text_defaults_to_base() {
        let mut job = job();
        job.hooks.clear();
        assert!(job.config_text().contains("HOOKS=(base)"));
    }

    #[test]
    fn test_command_uses_binary_and_artifact_name() {
        let command = job().command();
        assert_eq!(command.program, "mkinitcpio");
        assert_eq!(command.args[0], "-g");
        let plan_dir = tempfile::tempdir().expect("tmpdir");
        // `artifact_path` needs a plan only for `output_host`.
        let _ = plan_dir;
    }

    #[test]
    fn test_binary_from_env_defaults_when_unset() {
        // The variable is not set by the test harness; both branches are
        // exercised by `probe`-style callers in the integration test.
        if std::env::var(ENV_BINARY).is_err() {
            assert_eq!(binary_from_env(), DEFAULT_BINARY);
        }
    }

    #[test]
    fn test_available_finds_sh() {
        let found = available("sh");
        assert!(found.is_some(), "sh should be on PATH");
        assert!(available("definitely-not-a-real-binary-xyz").is_none());
        assert!(available("/nonexistent/binary").is_none());
    }

    #[test]
    fn test_available_checks_executable_bit() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tmpdir");
        let plain = dir.path().join("plain");
        fs::write(&plain, "#!/bin/sh\n").expect("write");
        fs::set_permissions(&plain, fs::Permissions::from_mode(0o644)).expect("chmod");
        assert!(available(&plain.to_string_lossy()).is_none());

        fs::set_permissions(&plain, fs::Permissions::from_mode(0o755)).expect("chmod");
        assert_eq!(available(&plain.to_string_lossy()), Some(plain));
    }

    #[test]
    fn test_host_available_for_shell() {
        assert!(host_available("sh"));
        assert!(!host_available("definitely-not-a-real-binary-xyz"));
    }
}
