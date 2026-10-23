//! GUI proxy-socket assembly for isolation level 2 and above (PLAN 4.4.4).
//!
//! ExtOS does **not** pass a display server through by sharing `/tmp` or by
//! importing `$XAUTHORITY`. Each socket is bind-mounted individually into
//! `/run/user/0/…` inside the container and the matching environment variable is
//! rewritten, so the container can reach exactly the sockets its profile lists
//! and nothing else.
//!
//! # Precedence
//!
//! 1. **Wayland** (`$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY`, default `wayland-0`) —
//!    preferred whenever a compositor socket is present.
//! 2. **PipeWire** (`$XDG_RUNTIME_DIR/pipewire-0`) and its PulseAudio shim
//!    (`$XDG_RUNTIME_DIR/pulse/native`) — audio/video; the PulseAudio entry is an
//!    explicit profile request, not an automatic fallback.
//! 3. **D-Bus** session bus (`$DBUS_SESSION_BUS_ADDRESS`, `unix:` only) and
//!    system bus (fixed well-known path, injectable through
//!    `EXTOS_CONTAINER_SYSTEM_BUS`).
//! 4. **X11** (`$DISPLAY`, `:<n>`) — a fallback that is *off* unless the profile
//!    lists `x11`, and even then it is only assembled when `$DISPLAY` is set.
//!    `$XAUTHORITY` is never bind-mounted: X11 auth passthrough is disabled by
//!    default (the assembled spec records that as a warning). A compositor on
//!    Wayland therefore always wins.
//!
//! Assembly is pure: it only *probes* (stat + socket-type check) and never
//! mounts. [`GuiSpec::validate`] turns absent-but-requested sources into typed
//! errors, and is only called when a launch is actually imminent.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::container::mounts::is_socket;
use crate::container::{ContainerError, ContainerSocket};

/// Well-known in-container runtime directory for the proxy sockets.
pub const CONTAINER_RUNTIME_DIR: &str = "/run/user/0";

/// Host-side values the GUI assembler reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GuiEnv {
    /// `$XDG_RUNTIME_DIR`.
    pub xdg_runtime_dir: Option<PathBuf>,
    /// `$WAYLAND_DISPLAY` (defaults to `wayland-0` when the directory exists).
    pub wayland_display: Option<String>,
    /// `$DBUS_SESSION_BUS_ADDRESS`.
    pub dbus_session_address: Option<String>,
    /// `$DISPLAY`.
    pub display: Option<String>,
    /// `$XAUTHORITY` — recorded, never passed through.
    pub xauthority: Option<PathBuf>,
    /// System bus socket path.
    pub system_bus: PathBuf,
}

impl GuiEnv {
    /// Snapshot the process environment.
    pub fn from_env() -> Self {
        let system_bus = std::env::var_os("EXTOS_CONTAINER_SYSTEM_BUS")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/run/dbus/system_bus_socket"));
        Self {
            xdg_runtime_dir: std::env::var_os("XDG_RUNTIME_DIR")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from),
            wayland_display: std::env::var("WAYLAND_DISPLAY").ok(),
            dbus_session_address: std::env::var("DBUS_SESSION_BUS_ADDRESS").ok(),
            display: std::env::var("DISPLAY").ok(),
            xauthority: std::env::var_os("XAUTHORITY")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from),
            system_bus,
        }
    }
}

/// One socket bind-mount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketMount {
    /// Which host resource this is.
    pub kind: ContainerSocket,
    /// Host socket path, or `None` when it could not be resolved from the
    /// environment at all (as opposed to resolved-but-absent).
    pub source: Option<PathBuf>,
    /// Where it appears inside the container.
    pub target: PathBuf,
    /// Whether the profile requires this socket (see [`GuiSpec::validate`]).
    pub required: bool,
}

impl SocketMount {
    /// Whether the source exists *and* is a Unix socket.
    pub fn is_available(&self) -> bool {
        self.source.as_deref().map(is_socket).unwrap_or(false)
    }

    /// Human-readable diagnostic (`wayland /run/user/1000/wayland-0 -> /run/user/0/wayland-0`).
    pub fn describe(&self) -> String {
        let source = self
            .source
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<unresolved>".into());
        format!(
            "{} {} -> {}",
            self.kind.as_str(),
            source,
            self.target.display()
        )
    }
}

/// The assembled GUI sandbox specification.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GuiSpec {
    /// Socket binds in application order.
    pub mounts: Vec<SocketMount>,
    /// Environment variables the container should see.
    pub env: BTreeMap<String, String>,
    /// Environment variables that must be dropped inside the container.
    pub unset: Vec<String>,
    /// Non-fatal notes (absent sockets, refused transports, X11 auth, …).
    pub warnings: Vec<String>,
}

impl GuiSpec {
    /// Sockets that were requested but whose source is missing or not a socket.
    pub fn missing(&self) -> Vec<&SocketMount> {
        self.mounts
            .iter()
            .filter(|mount| !mount.is_available())
            .collect()
    }

    /// Turn missing sockets into typed errors.
    ///
    /// `strict == false` is the default launch behaviour for levels 2/3 (a
    /// desktop without PipeWire should not make every GUI container fail);
    /// `strict == true` is used when the caller promised the socket exists.
    pub fn validate(&self, strict: bool) -> Result<(), ContainerError> {
        if !strict {
            return Ok(());
        }
        for mount in self.missing() {
            if !mount.required {
                continue;
            }
            return Err(ContainerError::SocketAbsent(mount.describe()));
        }
        Ok(())
    }

    /// Mark every assembled socket as required (used by `strict` launches and by
    /// tests that assert the full spec).
    pub fn require_all(mut self) -> Self {
        for mount in &mut self.mounts {
            mount.required = true;
        }
        self
    }

    /// Environment variable lookup helper (for tests and diagnostics).
    pub fn env_var(&self, key: &str) -> Option<&str> {
        self.env.get(key).map(String::as_str)
    }
}

/// Assemble the GUI spec for a profile's socket list.
///
/// The result is deterministic for a given [`GuiEnv`], which is what makes it
/// testable without a compositor.
pub fn assemble_gui_spec(sockets: &[ContainerSocket], env: &GuiEnv) -> GuiSpec {
    let mut spec = GuiSpec::default();
    let runtime_target = PathBuf::from(CONTAINER_RUNTIME_DIR);

    // A container always gets its own runtime dir, even with no sockets, so
    // toolkit environment variables stay coherent.
    spec.env
        .insert("XDG_RUNTIME_DIR".into(), CONTAINER_RUNTIME_DIR.to_string());

    // Wayland wins over X11: decided before we look at $DISPLAY.
    let wants_wayland = sockets.contains(&ContainerSocket::Wayland);
    let mut wayland_bound = false;

    for kind in sockets {
        match kind {
            ContainerSocket::Wayland => {
                let display = env
                    .wayland_display
                    .clone()
                    .unwrap_or_else(|| "wayland-0".to_string());
                let source = env
                    .xdg_runtime_dir
                    .as_ref()
                    .map(|dir| dir.join(&display));
                let target = runtime_target.join(&display);
                wayland_bound = source.as_deref().map(is_socket).unwrap_or(false);
                if source.is_none() {
                    spec.warnings.push(
                        "wayland requested but XDG_RUNTIME_DIR is unset; the compositor socket \
                         cannot be located"
                            .into(),
                    );
                } else if !wayland_bound {
                    spec.warnings.push(format!(
                        "wayland socket {} is missing; the container will not reach a compositor",
                        source
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default()
                    ));
                }
                spec.env.insert("WAYLAND_DISPLAY".into(), display);
                spec.mounts.push(SocketMount {
                    kind: *kind,
                    source,
                    target,
                    required: false,
                });
            }
            ContainerSocket::Pipewire => {
                let source = env.xdg_runtime_dir.as_ref().map(|dir| dir.join("pipewire-0"));
                if source.is_none() {
                    spec.warnings
                        .push("pipewire requested but XDG_RUNTIME_DIR is unset".into());
                }
                spec.env.insert(
                    "PIPEWIRE_RUNTIME_DIR".into(),
                    CONTAINER_RUNTIME_DIR.to_string(),
                );
                spec.mounts.push(SocketMount {
                    kind: *kind,
                    source,
                    target: runtime_target.join("pipewire-0"),
                    required: false,
                });
            }
            ContainerSocket::PulseAudio => {
                let source = env
                    .xdg_runtime_dir
                    .as_ref()
                    .map(|dir| dir.join("pulse/native"));
                if source.is_none() {
                    spec.warnings
                        .push("pulse-audio requested but XDG_RUNTIME_DIR is unset".into());
                }
                spec.env.insert(
                    "PULSE_SERVER".into(),
                    format!("unix:{CONTAINER_RUNTIME_DIR}/pulse/native"),
                );
                spec.mounts.push(SocketMount {
                    kind: *kind,
                    source,
                    target: runtime_target.join("pulse/native"),
                    required: false,
                });
            }
            ContainerSocket::DbusSession => {
                let parsed = env
                    .dbus_session_address
                    .as_deref()
                    .and_then(parse_unix_bus_address);
                match (&env.dbus_session_address, parsed.as_ref()) {
                    (None, _) => spec.warnings.push(
                        "dbus-session requested but DBUS_SESSION_BUS_ADDRESS is unset".into(),
                    ),
                    (Some(address), None) => spec.warnings.push(format!(
                        "dbus-session address {address:?} is not a unix: socket; TCP bus transports \
                         are never proxied"
                    )),
                    (Some(_), Some(_)) => {}
                }
                spec.env.insert(
                    "DBUS_SESSION_BUS_ADDRESS".into(),
                    format!("unix:path={CONTAINER_RUNTIME_DIR}/bus"),
                );
                spec.mounts.push(SocketMount {
                    kind: *kind,
                    source: parsed,
                    target: runtime_target.join("bus"),
                    required: false,
                });
            }
            ContainerSocket::DbusSystem => {
                if !is_socket(&env.system_bus) {
                    spec.warnings.push(format!(
                        "dbus-system source {} is missing or not a socket",
                        env.system_bus.display()
                    ));
                }
                spec.mounts.push(SocketMount {
                    kind: *kind,
                    source: Some(env.system_bus.clone()),
                    target: PathBuf::from("/run/dbus/system_bus_socket"),
                    required: false,
                });
            }
            ContainerSocket::X11 => {
                // X11 is a fallback: skip it when a Wayland socket was bound.
                if wants_wayland && wayland_bound {
                    spec.warnings.push(
                        "x11 requested but a wayland compositor socket was found; wayland wins and \
                         X11 is not bound"
                            .into(),
                    );
                    continue;
                }
                let Some(display) = env.display.clone() else {
                    spec.warnings
                        .push("x11 requested but $DISPLAY is unset".into());
                    continue;
                };
                let Some(number) = x11_display_number(&display) else {
                    spec.warnings.push(format!(
                        "x11 display {display:?} is not a local :N display; remote X11 is never \
                         proxied"
                    ));
                    continue;
                };
                let socket = PathBuf::from(format!("/tmp/.X11-unix/X{number}"));
                if !is_socket(&socket) {
                    spec.warnings.push(format!(
                        "x11 socket {} is missing",
                        socket.display()
                    ));
                }
                spec.env.insert("DISPLAY".into(), format!(":{number}"));
                spec.unset.push("XAUTHORITY".into());
                spec.warnings.push(
                    "x11 auth passthrough is disabled by default; set up a per-container cookie \
                     separately if the application needs one"
                        .into(),
                );
                spec.mounts.push(SocketMount {
                    kind: *kind,
                    source: Some(socket.clone()),
                    target: socket,
                    required: false,
                });
            }
        }
    }

    // Never leak the host display auth file, even when X11 was not requested.
    if env.xauthority.is_some() && !spec.unset.iter().any(|v| v == "XAUTHORITY") {
        spec.unset.push("XAUTHORITY".into());
        spec.warnings.push(
            "XAUTHORITY is set on the host; it is intentionally not passed into the container"
                .into(),
        );
    }
    spec
}

/// Extract the socket path from `unix:path=/…` (or `unix:abstract=` → `None`).
fn parse_unix_bus_address(address: &str) -> Option<PathBuf> {
    let rest = address.strip_prefix("unix:")?;
    let path = rest
        .split(',')
        .find_map(|part| part.strip_prefix("path="))?;
    if path.is_empty() {
        return None;
    }
    Some(PathBuf::from(path))
}

/// `:0` / `:0.0` → `0`; anything with a host part (`host:0`, `localhost:10.0`)
/// is refused.
fn x11_display_number(display: &str) -> Option<u32> {
    let rest = display.strip_prefix(':')?;
    let number = rest.split('.').next()?;
    number.parse::<u32>().ok()
}

/// Convenience: does `path` look like the wayland socket for `env`?
#[cfg(test)]
pub(crate) fn wayland_socket(env: &GuiEnv) -> Option<PathBuf> {
    let display = env
        .wayland_display
        .clone()
        .unwrap_or_else(|| "wayland-0".to_string());
    let source = env.xdg_runtime_dir.as_ref()?.join(display);
    if is_socket(&source) { Some(source) } else { None }
}

/// Symmetry helper for [`wayland_socket`].
#[cfg(test)]
pub(crate) fn system_bus_present(env: &GuiEnv) -> bool {
    is_socket(&env.system_bus)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn unix_socket(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        // Keep the listener alive for the duration of the test.
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        std::mem::forget(listener);
        path
    }

    fn full_env(runtime: &Path) -> GuiEnv {
        GuiEnv {
            xdg_runtime_dir: Some(runtime.to_path_buf()),
            wayland_display: Some("wayland-1".into()),
            dbus_session_address: Some(format!("unix:path={}", runtime.join("bus").display())),
            display: Some(":0".into()),
            xauthority: Some(PathBuf::from("/home/u/.Xauthority")),
            system_bus: runtime.join("system_bus_socket"),
        }
    }

    #[test]
    fn wayland_bind_mounts_the_compositor_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = tmp.path().join("runtime");
        std::fs::create_dir_all(&runtime).unwrap();
        let sock = unix_socket(&runtime, "wayland-1");

        let spec = assemble_gui_spec(&[ContainerSocket::Wayland], &full_env(&runtime));
        assert_eq!(spec.mounts.len(), 1);
        assert_eq!(spec.mounts[0].source.as_deref(), Some(sock.as_path()));
        assert_eq!(
            spec.mounts[0].target,
            PathBuf::from("/run/user/0/wayland-1")
        );
        assert!(spec.mounts[0].is_available());
        assert_eq!(spec.env_var("WAYLAND_DISPLAY"), Some("wayland-1"));
        assert_eq!(spec.env_var("XDG_RUNTIME_DIR"), Some("/run/user/0"));
        spec.validate(true).unwrap();
    }

    #[test]
    fn missing_wayland_socket_is_recorded_and_fails_strict_validation() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = tmp.path().join("runtime");
        std::fs::create_dir_all(&runtime).unwrap();

        let mut spec = assemble_gui_spec(&[ContainerSocket::Wayland], &full_env(&runtime));
        spec = spec.require_all();
        assert_eq!(spec.missing().len(), 1);
        assert!(matches!(
            spec.validate(true),
            Err(ContainerError::SocketAbsent(_))
        ));
        // Non-strict (the launch default) only warns.
        spec.validate(false).unwrap();
        assert!(spec.warnings.iter().any(|w| w.contains("missing")));
    }

    #[test]
    fn dbus_session_only_accepts_unix_addresses() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = tmp.path().join("runtime");
        std::fs::create_dir_all(&runtime).unwrap();
        unix_socket(&runtime, "bus");

        let mut env = full_env(&runtime);
        env.dbus_session_address = Some("unix:path=".to_string() + &runtime.join("bus").display().to_string());
        let spec = assemble_gui_spec(&[ContainerSocket::DbusSession], &env);
        assert!(spec.mounts[0].is_available());
        assert_eq!(
            spec.env_var("DBUS_SESSION_BUS_ADDRESS"),
            Some("unix:path=/run/user/0/bus")
        );

        env.dbus_session_address = Some("tcp:host=127.0.0.1,port=5555".into());
        let refused = assemble_gui_spec(&[ContainerSocket::DbusSession], &env);
        assert!(refused.mounts[0].source.is_none());
        assert!(refused.warnings.iter().any(|w| w.contains("TCP")));
    }

    #[test]
    fn wayland_wins_over_x11() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = tmp.path().join("runtime");
        std::fs::create_dir_all(&runtime).unwrap();
        unix_socket(&runtime, "wayland-1");

        let spec = assemble_gui_spec(
            &[ContainerSocket::Wayland, ContainerSocket::X11],
            &full_env(&runtime),
        );
        assert_eq!(spec.mounts.len(), 1, "x11 must be skipped: {:?}", spec.mounts);
        assert!(spec.warnings.iter().any(|w| w.contains("wayland wins")));
        assert!(!spec.env.contains_key("DISPLAY"));
    }

    #[test]
    fn x11_fallback_sets_display_and_drops_xauthority() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = tmp.path().join("runtime");
        std::fs::create_dir_all(&runtime).unwrap();
        // No wayland socket → X11 fallback is used.
        let spec = assemble_gui_spec(&[ContainerSocket::X11], &full_env(&runtime));
        assert_eq!(spec.mounts.len(), 1);
        assert_eq!(spec.env_var("DISPLAY"), Some(":0"));
        assert!(spec.unset.iter().any(|v| v == "XAUTHORITY"));
        assert!(spec
            .warnings
            .iter()
            .any(|w| w.contains("auth passthrough is disabled")));
    }

    #[test]
    fn remote_x11_display_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = tmp.path().join("runtime");
        std::fs::create_dir_all(&runtime).unwrap();
        let mut env = full_env(&runtime);
        env.display = Some("localhost:10.0".into());
        let spec = assemble_gui_spec(&[ContainerSocket::X11], &env);
        assert!(spec.mounts.is_empty());
        assert!(spec.warnings.iter().any(|w| w.contains("remote X11")));
    }

    #[test]
    fn xauthority_is_never_passed_through() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = tmp.path().join("runtime");
        std::fs::create_dir_all(&runtime).unwrap();
        unix_socket(&runtime, "wayland-1");
        let spec = assemble_gui_spec(&[ContainerSocket::Wayland], &full_env(&runtime));
        assert!(spec.unset.iter().any(|v| v == "XAUTHORITY"));
        assert!(!spec.env.contains_key("XAUTHORITY"));
    }

    #[test]
    fn pulse_and_pipewire_map_to_runtime_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = tmp.path().join("runtime");
        std::fs::create_dir_all(runtime.join("pulse")).unwrap();
        unix_socket(&runtime, "pipewire-0");
        unix_socket(&runtime, "pulse/native");

        let spec = assemble_gui_spec(
            &[ContainerSocket::Pipewire, ContainerSocket::PulseAudio],
            &full_env(&runtime),
        );
        assert_eq!(spec.mounts.len(), 2);
        assert!(spec.env_var("PIPEWIRE_RUNTIME_DIR").is_some());
        assert_eq!(
            spec.env_var("PULSE_SERVER"),
            Some("unix:/run/user/0/pulse/native")
        );
        assert!(spec.missing().is_empty());
    }

    #[test]
    fn socket_probe_helpers() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = tmp.path().join("runtime");
        std::fs::create_dir_all(&runtime).unwrap();
        unix_socket(&runtime, "wayland-1");
        let env = full_env(&runtime);
        assert_eq!(
            wayland_socket(&env),
            Some(runtime.join("wayland-1"))
        );
        assert!(!system_bus_present(&env));
    }

    #[test]
    fn display_number_parser() {
        assert_eq!(x11_display_number(":0"), Some(0));
        assert_eq!(x11_display_number(":10.0"), Some(10));
        assert_eq!(x11_display_number("host:0"), None);
        assert_eq!(x11_display_number("0"), None);
    }
}
