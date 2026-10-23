//! Package manifest types and parsing.
//!
//! Represents the ExtOS `manifest.nix` stored at
//! `/repository/objects/<hash>/metadata/manifest.nix`.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::str::FromStr;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::config::NixValue;
use crate::dependency::{CapabilityRequest, DependencySpec};
use crate::error::ExtosError;
use crate::types::PackageFormat;

/// The well-known cross-origin spoof mapping table, embedded at compile time.
///
/// See `data/spoof_mappings.toml` for the schema. Used by
/// [`resolve_auto_spoofs`] as a fallback when a manifest does not declare
/// explicit [`PackageManifest::phantom_spoofs`].
pub const SPOOF_MAPPINGS_TOML: &str = include_str!("../data/spoof_mappings.toml");

/// A fully parsed ExtOS package manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageManifest {
    /// Core package identity
    pub identity: PackageIdentity,
    /// Package archive/payload format (transport)
    pub archive: Option<crate::types::ArchiveFormat>,
    /// Package installation format (layout in CAS)
    pub format: PackageFormat,
    /// Runtime dependencies (Tier 1/2/3)
    pub requires: Vec<DependencySpec>,
    /// Optional dependencies (user-activated)
    pub suggests: Vec<SuggestGroup>,
    /// Build-time dependencies (for source compilations)
    pub build_requires: Vec<DependencySpec>,
    /// What this package provides to the system
    pub capabilities: Capabilities,
    /// Security declarations (file capabilities, MAC profiles)
    pub security: Option<SecurityBlock>,
    /// Additional phantom rows this package emits for foreign package managers
    /// (PhantomDB row spoofing, PLAN 2.7). Empty by default; older manifests
    /// that predate the field deserialize to an empty map.
    #[serde(default)]
    pub phantom_spoofs: BTreeMap<SpoofTarget, Vec<SpoofEntry>>,
    /// Tier-4 container profile declared by `containerPermissions`
    /// (PLAN 4.4.1). `None` means "this package is not containerised"; older
    /// manifests that predate the field deserialize to `None`.
    #[serde(default)]
    pub container: Option<ContainerPermissions>,
}

/// A foreign package-manager database that a package can spoof rows into.
///
/// The canonical spelling (see [`SpoofTarget::as_str`]) doubles as the key used
/// in the `phantom_spoofs` Nix table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SpoofTarget {
    /// Arch Linux / pacman (`/var/lib/pacman/local`).
    Arch,
    /// Debian / dpkg (`/var/lib/dpkg/status`).
    Debian,
    /// Alpine / apk (`/lib/apk/db/installed`).
    Alpine,
    /// Void Linux / xbps (`/var/db/xbps`).
    Void,
    /// RPM-based distributions (`/var/lib/rpm`).
    Rpm,
}

impl SpoofTarget {
    /// All supported targets, in canonical order.
    pub const ALL: [SpoofTarget; 5] = [
        SpoofTarget::Arch,
        SpoofTarget::Debian,
        SpoofTarget::Alpine,
        SpoofTarget::Void,
        SpoofTarget::Rpm,
    ];

    /// The canonical key for this target (`"arch"`, `"debian"`, …).
    pub fn as_str(&self) -> &'static str {
        match self {
            SpoofTarget::Arch => "arch",
            SpoofTarget::Debian => "debian",
            SpoofTarget::Alpine => "alpine",
            SpoofTarget::Void => "void",
            SpoofTarget::Rpm => "rpm",
        }
    }

    /// The canonical `manifest.identity.origin` value for this target.
    pub fn canonical_origin(&self) -> &'static str {
        match self {
            SpoofTarget::Arch => "archlinux",
            SpoofTarget::Debian => "debian",
            SpoofTarget::Alpine => "alpine",
            SpoofTarget::Void => "void",
            SpoofTarget::Rpm => "rpm",
        }
    }

    /// Map a manifest origin (`"archlinux"`, `"dpkg"`, `"fedora"`, …) to a target.
    ///
    /// Returns `None` for origins that have no phantom database (Nix, pypi,
    /// android, …).
    pub fn from_origin(origin: &str) -> Option<Self> {
        match origin.to_ascii_lowercase().as_str() {
            "archlinux" | "arch" | "pacman" => Some(SpoofTarget::Arch),
            "debian" | "ubuntu" | "dpkg" | "apt" => Some(SpoofTarget::Debian),
            "alpine" | "apk" => Some(SpoofTarget::Alpine),
            "void" | "xbps" => Some(SpoofTarget::Void),
            "rpm" | "fedora" | "suse" | "rhel" | "centos" | "dnf" | "yum" | "zypper" => {
                Some(SpoofTarget::Rpm)
            }
            _ => None,
        }
    }
}

impl FromStr for SpoofTarget {
    type Err = ExtosError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_origin(s).ok_or_else(|| ExtosError::ConfigParse {
            path: String::new(),
            line: 0,
            message: format!("unknown phantom spoof target: {s}"),
        })
    }
}

impl fmt::Display for SpoofTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One spoofed phantom row: the name/version a foreign package manager should
/// see, plus any extra capability strings that row should advertise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpoofEntry {
    /// Package name in the target package manager's namespace.
    pub name: String,
    /// Version to report; empty means "inherit the ingested package version".
    #[serde(default)]
    pub version: String,
    /// Extra `Provides`-style strings for the spoofed row (e.g. `libc.so.6`).
    #[serde(default)]
    pub extra_provides: Vec<String>,
}

impl SpoofEntry {
    /// Construct a spoof entry with no extra provides.
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            extra_provides: Vec::new(),
        }
    }

    /// Attach extra provides to this entry.
    pub fn with_extra_provides(mut self, provides: impl IntoIterator<Item = String>) -> Self {
        self.extra_provides.extend(provides);
        self
    }
}

/// The identity block — who this package is and what it replaces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageIdentity {
    pub origin: String,
    pub name: String,
    pub version: String,
    /// Packages this one replaces (from upstream `replaces` + `provides`)
    pub aliases: Vec<String>,
}

/// What this package advertises to the ExtOS DAG.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Capabilities {
    /// Executable binaries (e.g., `["htop", "htop-vim"]`)
    pub binaries: Vec<String>,
    /// Shared library SONAMEs (e.g., `["libssl.so.3", "libcrypto.so.3"]`)
    pub libraries: Vec<String>,
    /// Virtual capabilities (e.g., `["system-monitor", "modules/6.8.2-extos-zen"]`)
    pub virtual_caps: Vec<String>,
    /// Shared resources (e.g., `["/usr/share/applications/htop.desktop"]`)
    pub resources: Vec<String>,
}

/// A named group of optional dependencies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuggestGroup {
    pub name: String,
    pub description: Option<String>,
    pub deps: Vec<DependencySpec>,
}

/// Security declarations for the weaver to apply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityBlock {
    /// File capabilities: path → list of caps (e.g., `"bin/ping" → ["CAP_NET_RAW"]`)
    pub capabilities: HashMap<String, Vec<String>>,
    /// MAC profile references (AppArmor/SELinux)
    pub mac_profile: Option<String>,
}

// ─── Container permissions (PLAN 4.4.1) ─────────────────────────

/// One of the five Tier-4 isolation levels (PLAN 4.4, `design/ARCHITECTURE.md`
/// §5).
///
/// | Level | Name | Network | IPC | Display |
/// |-------|------|---------|-----|---------|
/// | 0 | [`Isolated`](IsolationLevel::Isolated) | ✗ | ✗ | ✗ |
/// | 1 | [`Cli`](IsolationLevel::Cli) | ✗ | ✗ | PTY |
/// | 2 | [`Gui`](IsolationLevel::Gui) | ✗ | proxy sockets | Wayland + PipeWire |
/// | 3 | [`Networked`](IsolationLevel::Networked) | host | proxy sockets | Wayland + PipeWire |
/// | 4 | [`Privileged`](IsolationLevel::Privileged) | host | host | host |
///
/// The level is *declared* by a package manifest (`containerPermissions.level`)
/// but never trusted blindly: the launcher re-checks it against the selected
/// backend and refuses combinations the backend cannot honour with a typed
/// error (see `container::backend`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IsolationLevel {
    /// Level 0: fresh user/mount/pid/ipc/uts/net namespaces, tmpfs root.
    Isolated,
    /// Level 1: Level 0 plus a controlling PTY.
    Cli,
    /// Level 2: Level 1 plus Wayland/PipeWire/D-Bus proxy socket bind-mounts.
    Gui,
    /// Level 3: Level 2 but the network namespace is inherited from the host.
    Networked,
    /// Level 4: no namespace restriction — build tools, Android, system agents.
    Privileged,
}

impl IsolationLevel {
    /// All levels, ascending.
    pub const ALL: [IsolationLevel; 5] = [
        IsolationLevel::Isolated,
        IsolationLevel::Cli,
        IsolationLevel::Gui,
        IsolationLevel::Networked,
        IsolationLevel::Privileged,
    ];

    /// Numeric level (`0..=4`).
    pub fn as_u8(&self) -> u8 {
        match self {
            IsolationLevel::Isolated => 0,
            IsolationLevel::Cli => 1,
            IsolationLevel::Gui => 2,
            IsolationLevel::Networked => 3,
            IsolationLevel::Privileged => 4,
        }
    }

    /// Inverse of [`IsolationLevel::as_u8`].
    pub fn from_u8(level: u8) -> Option<Self> {
        IsolationLevel::ALL
            .into_iter()
            .find(|candidate| candidate.as_u8() == level)
    }

    /// Canonical lower-case name (`"isolated"`, `"cli"`, …).
    pub fn as_str(&self) -> &'static str {
        match self {
            IsolationLevel::Isolated => "isolated",
            IsolationLevel::Cli => "cli",
            IsolationLevel::Gui => "gui",
            IsolationLevel::Networked => "networked",
            IsolationLevel::Privileged => "privileged",
        }
    }

    /// Whether this level needs a controlling PTY (levels ≥ 1).
    pub fn needs_pty(&self) -> bool {
        *self != IsolationLevel::Isolated
    }

    /// Whether the network namespace is inherited from the host.
    pub fn shares_host_network(&self) -> bool {
        matches!(
            self,
            IsolationLevel::Networked | IsolationLevel::Privileged
        )
    }

    /// Whether graphical proxy sockets are part of the level's default profile.
    pub fn has_display(&self) -> bool {
        matches!(
            self,
            IsolationLevel::Gui | IsolationLevel::Networked | IsolationLevel::Privileged
        )
    }
}

impl fmt::Display for IsolationLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for IsolationLevel {
    type Err = ExtosError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let normalized = s.trim().to_ascii_lowercase();
        if let Some(level) = normalized
            .strip_prefix('l')
            .and_then(|rest| rest.parse::<u8>().ok())
            .and_then(IsolationLevel::from_u8)
        {
            return Ok(level);
        }
        if let Ok(level) = normalized.parse::<u8>() {
            return IsolationLevel::from_u8(level).ok_or_else(|| spec_err(format!(
                "container isolation level out of range: {level} (expected 0..=4)"
            )));
        }
        IsolationLevel::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == normalized)
            .ok_or_else(|| {
                spec_err(format!(
                    "unknown container isolation level: {s:?} (expected isolated|cli|gui|networked|privileged or 0..=4)"
                ))
            })
    }
}

/// Namespace toggles a container profile asks for.
///
/// Defaults are derived from the [`IsolationLevel`]
/// ([`NamespaceToggles::for_level`]); a manifest may override individual flags
/// with a `namespaces = { net = false; … };` block. `cgroup` is off by default
/// for every level: unprivileged hosts cannot mount a delegated cgroup v2 tree,
/// so ExtOS leaves that to the backend (documented limit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceToggles {
    /// Fresh user namespace with the caller mapped to `root` inside.
    pub user: bool,
    /// Fresh mount namespace (private propagation).
    pub mount: bool,
    /// Fresh PID namespace (the container entrypoint becomes PID 1).
    pub pid: bool,
    /// Fresh SysV/POSIX IPC namespace.
    pub ipc: bool,
    /// Fresh UTS namespace (the container may set its own hostname).
    pub uts: bool,
    /// Fresh network namespace (`false` = inherit the host's).
    pub net: bool,
    /// Fresh cgroup namespace (off by default, see the type docs).
    pub cgroup: bool,
}

impl NamespaceToggles {
    /// Default toggles for `level`.
    pub fn for_level(level: IsolationLevel) -> Self {
        match level {
            IsolationLevel::Isolated | IsolationLevel::Cli | IsolationLevel::Gui => Self {
                user: true,
                mount: true,
                pid: true,
                ipc: true,
                uts: true,
                net: true,
                cgroup: false,
            },
            IsolationLevel::Networked => Self {
                user: true,
                mount: true,
                pid: true,
                ipc: true,
                uts: true,
                net: false,
                cgroup: false,
            },
            IsolationLevel::Privileged => Self {
                user: false,
                mount: false,
                pid: false,
                ipc: false,
                uts: false,
                net: false,
                cgroup: false,
            },
        }
    }

    /// Whether any namespace is unshared at all.
    pub fn any(&self) -> bool {
        self.user || self.mount || self.pid || self.ipc || self.uts || self.net || self.cgroup
    }
}

impl Default for NamespaceToggles {
    fn default() -> Self {
        Self::for_level(IsolationLevel::Isolated)
    }
}

/// A host resource a Tier-4 profile is allowed to reach through a bind-mounted
/// socket (PLAN 4.4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContainerSocket {
    /// `$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY` compositor socket.
    Wayland,
    /// `$XDG_RUNTIME_DIR/pipewire-0`.
    Pipewire,
    /// `$XDG_RUNTIME_DIR/pulse/native` (PulseAudio or the PipeWire pulse shim).
    PulseAudio,
    /// `$DBUS_SESSION_BUS_ADDRESS` (unix socket only).
    DbusSession,
    /// The system bus (`/run/dbus/system_bus_socket`), resolved at runtime.
    DbusSystem,
    /// `$DISPLAY` X11 socket — fallback only, never selected over Wayland.
    X11,
}

impl ContainerSocket {
    /// Canonical manifest spelling.
    pub fn as_str(&self) -> &'static str {
        match self {
            ContainerSocket::Wayland => "wayland",
            ContainerSocket::Pipewire => "pipewire",
            ContainerSocket::PulseAudio => "pulse-audio",
            ContainerSocket::DbusSession => "dbus-session",
            ContainerSocket::DbusSystem => "dbus-system",
            ContainerSocket::X11 => "x11",
        }
    }

    /// Default socket set for a level (empty for levels 0/1).
    pub fn defaults_for_level(level: IsolationLevel) -> Vec<ContainerSocket> {
        match level {
            IsolationLevel::Isolated | IsolationLevel::Cli => Vec::new(),
            IsolationLevel::Gui | IsolationLevel::Networked => vec![
                ContainerSocket::Wayland,
                ContainerSocket::Pipewire,
                ContainerSocket::DbusSession,
            ],
            IsolationLevel::Privileged => vec![
                ContainerSocket::Wayland,
                ContainerSocket::Pipewire,
                ContainerSocket::PulseAudio,
                ContainerSocket::DbusSession,
                ContainerSocket::DbusSystem,
            ],
        }
    }
}

impl fmt::Display for ContainerSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ContainerSocket {
    type Err = ExtosError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let normalized = s.trim().to_ascii_lowercase().replace('_', "-");
        match normalized.as_str() {
            "wayland" => Ok(ContainerSocket::Wayland),
            "pipewire" => Ok(ContainerSocket::Pipewire),
            "pulse" | "pulseaudio" | "pulse-audio" => Ok(ContainerSocket::PulseAudio),
            "dbus" | "dbus-session" => Ok(ContainerSocket::DbusSession),
            "dbus-system" | "system-dbus" => Ok(ContainerSocket::DbusSystem),
            "x11" | "xorg" => Ok(ContainerSocket::X11),
            _ => Err(spec_err(format!("unknown container socket kind: {s:?}"))),
        }
    }
}

/// The parsed `containerPermissions` block of a manifest (PLAN 4.4.1).
///
/// Grammar (all keys optional except the level):
///
/// ```nix
/// containerPermissions = {
///   level = "gui";            # or "2" / "l2"; also accepted: bare string form
///   sockets = [ "wayland" "pipewire" "dbus-session" ];   # overrides the level default
///   namespaces = { net = false; pid = true; };            # overrides per flag
///   command = [ "/usr/bin/app" "--flag" ];                # entrypoint hint (instanz run)
/// };
/// // shorthand equivalent to level = "isolated":
/// containerPermissions = "isolated";
/// ```
///
/// Parsing is strictly additive: a manifest without the block keeps
/// `PackageManifest::container == None` and every Phase 1–3 code path unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerPermissions {
    /// Declared isolation level.
    pub level: IsolationLevel,
    /// Sockets the profile may bind-mount. Empty for levels 0/1.
    #[serde(default)]
    pub sockets: Vec<ContainerSocket>,
    /// Namespace toggles (level defaults + manifest overrides).
    #[serde(default)]
    pub namespaces: NamespaceToggles,
    /// Entrypoint hint, absolute path inside the container rootfs plus args.
    /// Empty means "the launcher must be told what to run".
    #[serde(default)]
    pub command: Vec<String>,
}

impl Default for ContainerPermissions {
    fn default() -> Self {
        Self::new(IsolationLevel::Isolated)
    }
}

impl ContainerPermissions {
    /// A profile with the level's default socket set and namespace toggles.
    pub fn new(level: IsolationLevel) -> Self {
        Self {
            level,
            sockets: ContainerSocket::defaults_for_level(level),
            namespaces: NamespaceToggles::for_level(level),
            command: Vec::new(),
        }
    }

    /// Replace the socket set.
    pub fn with_sockets(mut self, sockets: impl IntoIterator<Item = ContainerSocket>) -> Self {
        self.sockets = sockets.into_iter().collect();
        self
    }

    /// Replace the entrypoint hint.
    pub fn with_command(mut self, command: impl IntoIterator<Item = String>) -> Self {
        self.command = command.into_iter().collect();
        self
    }

    /// Whether `socket` is in the profile.
    pub fn allows(&self, socket: ContainerSocket) -> bool {
        self.sockets.contains(&socket)
    }

    /// Parse a `containerPermissions` value.
    ///
    /// Returns `Ok(None)` when the manifest has no such block (the common case).
    pub fn from_nix(val: &NixValue) -> Result<Option<Self>, ExtosError> {
        let Some(root) = val.get_path("containerPermissions") else {
            return Ok(None);
        };

        // Shorthand: `containerPermissions = "gui";`
        if let Some(text) = root.as_str() {
            let level: IsolationLevel = text.parse()?;
            return Ok(Some(Self::new(level)));
        }

        let table = root.as_attrset().ok_or_else(|| {
            spec_err("manifest field 'containerPermissions' must be an attribute set or a level string")
        })?;

        let level: IsolationLevel = match table.get("level") {
            Some(value) => {
                if let Some(text) = value.as_str() {
                    text.parse()?
                } else if let Some(number) = value.as_int() {
                    u8::try_from(number)
                        .ok()
                        .and_then(IsolationLevel::from_u8)
                        .ok_or_else(|| {
                            spec_err(format!(
                                "containerPermissions.level out of range: {number} (expected 0..=4)"
                            ))
                        })?
                } else {
                    return Err(spec_err(
                        "containerPermissions.level must be a string or an integer",
                    ));
                }
            }
            None => {
                return Err(spec_err(
                    "containerPermissions is missing the required 'level' key",
                ));
            }
        };

        let sockets = match table.get("sockets") {
            Some(value) => {
                let list = value.as_list().ok_or_else(|| {
                    spec_err("containerPermissions.sockets must be a list of socket names")
                })?;
                let mut out = Vec::with_capacity(list.len());
                for item in list {
                    let name = item.as_str().ok_or_else(|| {
                        spec_err("containerPermissions.sockets entries must be strings")
                    })?;
                    let socket: ContainerSocket = name.parse()?;
                    if !out.contains(&socket) {
                        out.push(socket);
                    }
                }
                out
            }
            None => ContainerSocket::defaults_for_level(level),
        };

        let mut namespaces = NamespaceToggles::for_level(level);
        if let Some(value) = table.get("namespaces") {
            let ns = value.as_attrset().ok_or_else(|| {
                spec_err("containerPermissions.namespaces must be an attribute set")
            })?;
            for (key, flag) in ns {
                let enabled = flag.as_bool().ok_or_else(|| {
                    spec_err(format!(
                        "containerPermissions.namespaces.{key} must be a boolean"
                    ))
                })?;
                let slot = match key.as_str() {
                    "user" => &mut namespaces.user,
                    "mount" => &mut namespaces.mount,
                    "pid" => &mut namespaces.pid,
                    "ipc" => &mut namespaces.ipc,
                    "uts" => &mut namespaces.uts,
                    "net" | "network" => &mut namespaces.net,
                    "cgroup" | "cgroups" => &mut namespaces.cgroup,
                    other => {
                        return Err(spec_err(format!(
                            "containerPermissions.namespaces has unknown flag: {other}"
                        )));
                    }
                };
                *slot = enabled;
            }
        }
        if level == IsolationLevel::Privileged && namespaces.any() {
            return Err(spec_err(
                "containerPermissions declares level \"privileged\" but asks for namespace isolation; \
                 privileged profiles must not restrict namespaces",
            ));
        }

        let command = match table.get("command") {
            Some(value) => value
                .as_list()
                .ok_or_else(|| spec_err("containerPermissions.command must be a list"))?
                .iter()
                .map(|item| {
                    item.as_str().map(str::to_string).ok_or_else(|| {
                        spec_err("containerPermissions.command entries must be strings")
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
            None => Vec::new(),
        };
        if let Some(program) = command.first() {
            if !program.starts_with('/') {
                return Err(spec_err(format!(
                    "containerPermissions.command must start with an absolute in-container path, got {program:?}"
                )));
            }
        }

        Ok(Some(ContainerPermissions {
            level,
            sockets,
            namespaces,
            command,
        }))
    }
}

/// Build a `ConfigParse` error attributed to the manifest grammar.
fn spec_err(message: impl Into<String>) -> ExtosError {
    ExtosError::ConfigParse {
        path: "manifest.nix".into(),
        line: 0,
        message: message.into(),
    }
}

// ─── Parsing from NixValue ──────────────────────────────────────

impl PackageManifest {
    /// Parse a `PackageManifest` from a parsed `.nix` `NixValue`.
    pub fn from_nix(val: &NixValue) -> Result<Self, ExtosError> {
        let identity = parse_identity(val)?;
        let format = val
            .get_str("format")
            .unwrap_or("extracted-tree")
            .parse::<PackageFormat>()
            .map_err(|e| ExtosError::ConfigParse {
                path: String::new(),
                line: 0,
                message: e,
            })?;

        let requires = parse_dep_list(val, "requires")?;
        let build_requires = parse_dep_list(val, "buildRequires")?;
        let suggests = parse_suggests(val)?;
        let capabilities = parse_capabilities(val)?;
        let phantom_spoofs = parse_phantom_spoofs(val)?;
        let container = ContainerPermissions::from_nix(val)?;
        let archive = val
            .get_str("archive")
            .map(|s| s.parse::<crate::types::ArchiveFormat>())
            .transpose()
            .map_err(|e| ExtosError::ConfigParse {
                path: String::new(),
                line: 0,
                message: e,
            })?;

        Ok(PackageManifest {
            identity,
            archive,
            format,
            requires,
            suggests,
            build_requires,
            capabilities,
            security: None,
            phantom_spoofs,
            container,
        })
    }

    /// Render the `phantom_spoofs` block as `manifest.nix`-compatible text.
    ///
    /// Returns `None` when the package declares no spoofs, so callers can omit
    /// the block entirely and stay byte-compatible with older manifests.
    pub fn phantom_spoofs_nix(&self) -> Option<String> {
        render_phantom_spoofs_nix(&self.phantom_spoofs)
    }

    /// The spoof rows to emit for `target`.
    ///
    /// Explicit manifest declarations win; when the manifest has none at all
    /// (for any target) the well-known mapping table is consulted as a fallback
    /// (PLAN 2.7.17). Entries with an empty version inherit the package version.
    pub fn effective_spoofs_for(&self, target: SpoofTarget) -> Vec<SpoofEntry> {
        let explicit = self.phantom_spoofs.get(&target);
        let mut entries: Vec<SpoofEntry> = match explicit {
            Some(list) if !list.is_empty() => list.clone(),
            _ if self.phantom_spoofs.is_empty() => {
                resolve_auto_spoofs(&self.identity.origin, &self.identity.name)
                    .into_iter()
                    .filter(|(t, _)| *t == target)
                    .map(|(_, e)| e)
                    .collect()
            }
            _ => Vec::new(),
        };
        for entry in &mut entries {
            if entry.version.is_empty() {
                entry.version.clone_from(&self.identity.version);
            }
        }
        entries
    }
}

fn parse_identity(val: &NixValue) -> Result<PackageIdentity, ExtosError> {
    // Support both flat and nested identity blocks:
    // Flat:   { name = "foo"; origin = "archlinux"; version = "1.0"; }
    // Nested: { identity = { name = "foo"; ... }; }
    let id_root = val.get_path("identity").unwrap_or(val);

    let origin = id_root
        .get_str("origin")
        .unwrap_or("scratch")
        .to_string();
    let name = id_root
        .get_str("name")
        .ok_or_else(|| ExtosError::ConfigParse {
            path: String::new(),
            line: 0,
            message: "manifest missing 'name' field".into(),
        })?
        .to_string();
    let version = id_root
        .get_str("version")
        .unwrap_or("0.0.0")
        .to_string();
    let aliases = id_root
        .get_str_list("aliases")
        .unwrap_or_default()
        .into_iter()
        .map(|s| s.to_string())
        .collect();

    Ok(PackageIdentity {
        origin,
        name,
        version,
        aliases,
    })
}

fn parse_dep_list(val: &NixValue, key: &str) -> Result<Vec<DependencySpec>, ExtosError> {
    let list = match val.get_path(key) {
        Some(v) => match v.as_list() {
            Some(l) => l,
            None => return Ok(vec![]),
        },
        None => return Ok(vec![]),
    };

    list.iter().map(parse_single_dep).collect()
}

fn parse_single_dep(val: &NixValue) -> Result<DependencySpec, ExtosError> {
    // Check the type of dependency by which keys are present
    if let Some(provides) = val.get_str("provides") {
        return Ok(DependencySpec::Capability(CapabilityRequest::Provides(
            provides.to_string(),
        )));
    }
    if let Some(executable) = val.get_str("executable") {
        let version = val.get_str("version").map(|s| s.to_string());
        return Ok(DependencySpec::Capability(CapabilityRequest::Executable {
            name: executable.to_string(),
            version,
        }));
    }
    if let Some(resource) = val.get_str("resource") {
        return Ok(DependencySpec::Capability(CapabilityRequest::Resource(
            resource.to_string(),
        )));
    }
    if let Some(feature) = val.get_str("feature") {
        return Ok(DependencySpec::Capability(CapabilityRequest::Virtual(
            feature.to_string(),
        )));
    }

    // If it has origin + name, it's a Tier 1/2 dep
    if let Some(name) = val.get_str("name") {
        let origin = val.get_str("origin").unwrap_or("virtual").to_string();
        let version = val.get_str("version").map(|s| s.to_string());

        // If version is an exact pin (no >= prefix), it's Tier 1
        if let Some(ref v) = version {
            if !v.starts_with(">=") && !v.starts_with("<=") && v != "current" {
                return Ok(DependencySpec::StrictPin {
                    origin,
                    name: name.to_string(),
                    version: v.clone(),
                });
            }
        }
        return Ok(DependencySpec::LooseEcosystem {
            origin,
            name: name.to_string(),
            version_constraint: version,
        });
    }

    Err(ExtosError::ConfigParse {
        path: String::new(),
        line: 0,
        message: format!("cannot parse dependency: {val:?}"),
    })
}

fn parse_suggests(val: &NixValue) -> Result<Vec<SuggestGroup>, ExtosError> {
    let suggests_map = match val.get_path("suggests") {
        Some(NixValue::AttrSet(map)) => map,
        _ => return Ok(vec![]),
    };

    let mut groups = Vec::new();
    for (name, group_val) in suggests_map {
        let deps = match group_val.as_list() {
            Some(list) => list.iter().map(parse_single_dep).collect::<Result<Vec<_>, _>>()?,
            None => vec![],
        };
        groups.push(SuggestGroup {
            name: name.clone(),
            description: None,
            deps,
        });
    }
    Ok(groups)
}

fn parse_capabilities(val: &NixValue) -> Result<Capabilities, ExtosError> {
    let caps_root = match val.get_path("capabilities") {
        Some(v) => v,
        None => return Ok(Capabilities::default()),
    };

    Ok(Capabilities {
        binaries: caps_root
            .get_str_list("binaries")
            .unwrap_or_default()
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
        libraries: caps_root
            .get_str_list("libraries")
            .unwrap_or_default()
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
        virtual_caps: caps_root
            .get_str_list("virtual")
            .unwrap_or_default()
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
        resources: caps_root
            .get_str_list("resources")
            .unwrap_or_default()
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
    })
}

// ─── Phantom spoofs (PLAN 2.7) ──────────────────────────────────

/// Parse `phantom_spoofs = { <target> = [ { name; version; extra_provides } ]; }`.
fn parse_phantom_spoofs(
    val: &NixValue,
) -> Result<BTreeMap<SpoofTarget, Vec<SpoofEntry>>, ExtosError> {
    let mut out = BTreeMap::new();
    let root = match val.get_path("phantom_spoofs") {
        Some(v) => v,
        None => return Ok(out),
    };
    let table = root.as_attrset().ok_or_else(|| ExtosError::ConfigParse {
        path: String::new(),
        line: 0,
        message: "manifest field 'phantom_spoofs' must be an attribute set".into(),
    })?;

    for (key, entries_val) in table {
        let target: SpoofTarget = key.parse()?;
        let list = entries_val.as_list().ok_or_else(|| ExtosError::ConfigParse {
            path: String::new(),
            line: 0,
            message: format!("phantom_spoofs.{key} must be a list"),
        })?;

        let mut entries = Vec::with_capacity(list.len());
        for item in list {
            let name = item
                .get_str("name")
                .ok_or_else(|| ExtosError::ConfigParse {
                    path: String::new(),
                    line: 0,
                    message: format!("phantom_spoofs.{key} entry missing 'name'"),
                })?
                .to_string();
            let version = item
                .get_str("version")
                .unwrap_or_default()
                .to_string();
            let mut extra_provides: Vec<String> = item
                .get_str_list("extra_provides")
                .or_else(|| item.get_str_list("provides"))
                .unwrap_or_default()
                .into_iter()
                .map(str::to_string)
                .collect();
            extra_provides.dedup();
            entries.push(SpoofEntry {
                name,
                version,
                extra_provides,
            });
        }
        out.insert(target, entries);
    }

    Ok(out)
}

/// Render a spoof map as `manifest.nix` text (empty map → `None`).
fn render_phantom_spoofs_nix(spoofs: &BTreeMap<SpoofTarget, Vec<SpoofEntry>>) -> Option<String> {
    let mut non_empty = spoofs.iter().filter(|(_, entries)| !entries.is_empty()).peekable();
    non_empty.peek()?;

    let mut out = String::from("phantom_spoofs = {\n");
    for (target, entries) in non_empty {
        out.push_str(&format!("  {} = [\n", target.as_str()));
        for entry in entries {
            out.push_str(&format!("    {{ name = {}; version = {};", quote(entry.name.as_str()), quote(entry.version.as_str())));
            if !entry.extra_provides.is_empty() {
                let list = entry
                    .extra_provides
                    .iter()
                    .map(|p| quote(p.as_str()))
                    .collect::<Vec<_>>()
                    .join(" ");
                out.push_str(&format!(" extra_provides = [ {list} ];"));
            }
            out.push_str(" }\n");
        }
        out.push_str("  ];\n");
    }
    out.push_str("};\n");
    Some(out)
}

/// Quote a string for Nix output.
fn quote(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// One row of the embedded spoof mapping table.
#[derive(Debug, Clone)]
struct MappingRecord {
    origin: String,
    name: String,
    target: SpoofTarget,
    entry: SpoofEntry,
}

#[derive(Debug, Default)]
struct MappingBuilder {
    origin: Option<String>,
    name: Option<String>,
    target: Option<String>,
    spoof_name: Option<String>,
    spoof_version: Option<String>,
    extra_provides: Vec<String>,
}

impl MappingBuilder {
    fn finish(self, line: usize) -> Result<MappingRecord, ExtosError> {
        let origin = self.origin.ok_or_else(|| mapping_err(line, "missing 'origin'"))?;
        let name = self.name.ok_or_else(|| mapping_err(line, "missing 'name'"))?;
        let target_raw = self
            .target
            .ok_or_else(|| mapping_err(line, "missing 'target'"))?;
        let target: SpoofTarget = target_raw.parse().map_err(|_| {
            mapping_err(line, &format!("unknown 'target' value: {target_raw}"))
        })?;
        let spoof_name = self
            .spoof_name
            .ok_or_else(|| mapping_err(line, "missing 'spoof_name'"))?;
        Ok(MappingRecord {
            origin,
            name,
            target,
            entry: SpoofEntry {
                name: spoof_name,
                version: self.spoof_version.unwrap_or_default(),
                extra_provides: self.extra_provides,
            },
        })
    }
}

fn mapping_err(line: usize, message: &str) -> ExtosError {
    ExtosError::ConfigParse {
        path: "data/spoof_mappings.toml".into(),
        line: line + 1,
        message: message.into(),
    }
}

/// Parse the embedded, intentionally-minimal TOML subset used by
/// `data/spoof_mappings.toml`.
fn parse_spoof_mappings(text: &str) -> Result<Vec<MappingRecord>, ExtosError> {
    let mut out = Vec::new();
    let mut current: Option<MappingBuilder> = None;

    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            if line != "[[spoof]]" {
                return Err(mapping_err(idx, &format!("unsupported table header: {line}")));
            }
            if let Some(builder) = current.take() {
                out.push(builder.finish(idx)?);
            }
            current = Some(MappingBuilder::default());
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| mapping_err(idx, &format!("expected key = value, got: {line}")))?;
        let builder = current
            .as_mut()
            .ok_or_else(|| mapping_err(idx, "key/value pair outside a [[spoof]] table"))?;

        match key.trim() {
            "origin" => builder.origin = Some(parse_toml_string(value, idx)?),
            "name" => builder.name = Some(parse_toml_string(value, idx)?),
            "target" => builder.target = Some(parse_toml_string(value, idx)?),
            "spoof_name" => builder.spoof_name = Some(parse_toml_string(value, idx)?),
            "spoof_version" => builder.spoof_version = Some(parse_toml_string(value, idx)?),
            "extra_provides" => builder.extra_provides = parse_toml_string_list(value, idx)?,
            other => {
                return Err(mapping_err(idx, &format!("unknown key: {other}")));
            }
        }
    }

    if let Some(builder) = current {
        out.push(builder.finish(text.lines().count())?);
    }
    Ok(out)
}

/// Parse a quoted single-line TOML string with `\\` and `\"` escapes.
fn parse_toml_string(value: &str, line: usize) -> Result<String, ExtosError> {
    let v = value.trim();
    let inner = v
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .ok_or_else(|| mapping_err(line, &format!("expected a quoted string, got: {v}")))?;

    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some(other) => {
                return Err(mapping_err(line, &format!("unsupported escape: \\{other}")));
            }
            None => return Err(mapping_err(line, "dangling escape")),
        }
    }
    Ok(out)
}

/// Parse `[ "a", "b" ]`.
fn parse_toml_string_list(value: &str, line: usize) -> Result<Vec<String>, ExtosError> {
    let v = value.trim();
    let inner = v
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(|| mapping_err(line, &format!("expected a string list, got: {v}")))?;

    let mut items = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if !in_string => in_string = true,
            '"' if in_string => {
                in_string = false;
                items.push(std::mem::take(&mut current));
            }
            '\\' if in_string => match chars.next() {
                Some('"') => current.push('"'),
                Some('\\') => current.push('\\'),
                Some(other) => {
                    return Err(mapping_err(line, &format!("unsupported escape: \\{other}")));
                }
                None => return Err(mapping_err(line, "dangling escape")),
            },
            ',' if !in_string => {}
            c if in_string => current.push(c),
            c if c.is_whitespace() => {}
            other => {
                return Err(mapping_err(
                    line,
                    &format!("unexpected character in list: {other}"),
                ));
            }
        }
    }
    if in_string {
        return Err(mapping_err(line, "unterminated string in list"));
    }
    Ok(items)
}

/// The parsed, embedded mapping table (parsed once per process).
fn spoof_mapping_table() -> &'static [MappingRecord] {
    static TABLE: OnceLock<Vec<MappingRecord>> = OnceLock::new();
    TABLE.get_or_init(|| match parse_spoof_mappings(SPOOF_MAPPINGS_TOML) {
        Ok(records) => records,
        Err(e) => {
            tracing::warn!("embedded spoof mapping table is invalid: {e}");
            Vec::new()
        }
    })
}

/// Normalized origin key, so `"arch"`/`"pacman"` match `"archlinux"`.
fn canonical_origin_key(origin: &str) -> String {
    SpoofTarget::from_origin(origin)
        .map(|t| t.canonical_origin().to_string())
        .unwrap_or_else(|| origin.to_ascii_lowercase())
}

/// Look up automatic spoof rows for an ingested package (PLAN 2.7.17).
///
/// Consulted only when a manifest declares no explicit
/// [`PackageManifest::phantom_spoofs`]. Matching is by normalized origin and
/// exact upstream name. Entries may carry an empty version, meaning "inherit
/// the package version" — [`PackageManifest::effective_spoofs_for`] resolves it.
///
/// # Examples
///
/// ```
/// use libextos::manifest::resolve_auto_spoofs;
///
/// let rows = resolve_auto_spoofs("archlinux", "glibc");
/// assert!(rows.iter().any(|(target, entry)| {
///     target.as_str() == "debian" && entry.name == "libc6"
/// }));
/// ```
pub fn resolve_auto_spoofs(origin: &str, name: &str) -> Vec<(SpoofTarget, SpoofEntry)> {
    let origin_key = canonical_origin_key(origin);
    spoof_mapping_table()
        .iter()
        .filter(|record| {
            record.name == name && canonical_origin_key(&record.origin) == origin_key
        })
        .map(|record| (record.target, record.entry.clone()))
        .collect()
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_nix;

    #[test]
    fn test_parse_manifest_flat() {
        let input = r#"{
            name = "hyprland";
            version = "0.39.1";
            origin = "archlinux";
            format = "extracted-tree";
            requires = [
                { provides = "wayland-server"; }
                { name = "mesa"; origin = "archlinux"; }
            ];
        }"#;
        let nix = parse_nix(input).unwrap();
        let m = PackageManifest::from_nix(&nix).unwrap();
        assert_eq!(m.identity.name, "hyprland");
        assert_eq!(m.identity.origin, "archlinux");
        assert_eq!(m.format, PackageFormat::ExtractedTree);
        assert_eq!(m.requires.len(), 2);
    }

    #[test]
    fn test_parse_manifest_nested_identity() {
        let input = r#"{
            identity = {
                origin = "archlinux";
                name = "htop";
                version = "3.3.0-1";
                aliases = [ "htop-legacy" ];
            };
            format = "extracted-tree";
            capabilities = {
                binaries = [ "htop" ];
                virtual = [ "system-monitor" ];
                resources = [ "/usr/share/applications/htop.desktop" ];
            };
            requires = [
                { provides = "libncursesw.so.6"; }
                { provides = "libc.so.6"; }
            ];
            suggests = {
                lsof-support = [
                    { executable = "lsof"; }
                ];
            };
        }"#;
        let nix = parse_nix(input).unwrap();
        let m = PackageManifest::from_nix(&nix).unwrap();
        assert_eq!(m.identity.name, "htop");
        assert_eq!(m.identity.aliases, vec!["htop-legacy"]);
        assert_eq!(m.capabilities.binaries, vec!["htop"]);
        assert_eq!(m.capabilities.virtual_caps, vec!["system-monitor"]);
        assert_eq!(m.requires.len(), 2);
        assert_eq!(m.suggests.len(), 1);
        assert_eq!(m.suggests[0].name, "lsof-support");
    }

    #[test]
    fn test_parse_loop_image_format() {
        let input = r#"{
            name = "system";
            version = "14.0";
            origin = "android";
            format = "loop-image";
            requires = [
                { origin = "android"; name = "vendor"; version = "14.0"; }
            ];
        }"#;
        let nix = parse_nix(input).unwrap();
        let m = PackageManifest::from_nix(&nix).unwrap();
        assert_eq!(m.format, PackageFormat::LoopImage);
        assert_eq!(m.requires.len(), 1);
        match &m.requires[0] {
            DependencySpec::StrictPin {
                origin,
                name,
                version,
            } => {
                assert_eq!(origin, "android");
                assert_eq!(name, "vendor");
                assert_eq!(version, "14.0");
            }
            other => panic!("expected StrictPin, got: {other:?}"),
        }
    }

    #[test]
    fn test_parse_wrapper_format() {
        let input = r#"{
            name = "numpy";
            version = "1.26.0";
            origin = "pypi";
            format = "wrapper";
            requires = [
                { executable = "python3"; version = ">=3.11"; }
            ];
        }"#;
        let nix = parse_nix(input).unwrap();
        let m = PackageManifest::from_nix(&nix).unwrap();
        assert_eq!(m.format, PackageFormat::Wrapper);
        match &m.requires[0] {
            DependencySpec::Capability(CapabilityRequest::Executable { name, version }) => {
                assert_eq!(name, "python3");
                assert_eq!(version.as_deref(), Some(">=3.11"));
            }
            other => panic!("expected Capability::Executable, got: {other:?}"),
        }
    }

    #[test]
    fn test_parse_archive_format() {
        let input = r#"{
            name = "p7zip";
            version = "17.05";
            origin = "archlinux";
            format = "extracted-tree";
            archive = "pkt.tar.xz";
        }"#;
        let nix = parse_nix(input).unwrap();
        let m = PackageManifest::from_nix(&nix).unwrap();
        assert_eq!(m.archive, Some(crate::types::ArchiveFormat::PktTarXz));
    }

    #[test]
    fn test_manifest_without_spoofs_defaults_to_empty() {
        let input = r#"{ name = "htop"; version = "3.3.0"; origin = "archlinux"; }"#;
        let nix = parse_nix(input).unwrap();
        let m = PackageManifest::from_nix(&nix).unwrap();
        assert!(m.phantom_spoofs.is_empty());
        assert!(m.phantom_spoofs_nix().is_none());
    }

    #[test]
    fn test_parse_phantom_spoofs() {
        let input = r#"{
            name = "glibc";
            version = "2.39";
            origin = "archlinux";

            phantom_spoofs = {
                debian = [
                    { name = "libc6";     version = "2.39-0extos1"; }
                    { name = "libc6-dev"; version = "2.39-0extos1"; }
                ];
                alpine = [
                    { name = "musl"; version = "1.2.5-r0"; extra_provides = [ "libc.so.6" ]; }
                ];
            };
        }"#;
        let nix = parse_nix(input).unwrap();
        let m = PackageManifest::from_nix(&nix).unwrap();

        let debian = m.phantom_spoofs.get(&SpoofTarget::Debian).unwrap();
        assert_eq!(debian.len(), 2);
        assert_eq!(debian[0].name, "libc6");
        assert_eq!(debian[1].name, "libc6-dev");

        let alpine = m.phantom_spoofs.get(&SpoofTarget::Alpine).unwrap();
        assert_eq!(alpine[0].extra_provides, vec!["libc.so.6"]);

        assert!(!m.phantom_spoofs.contains_key(&SpoofTarget::Rpm));
    }

    #[test]
    fn test_parse_phantom_spoofs_accepts_empty_version() {
        let input = r#"{
            name = "glibc";
            version = "2.39";
            origin = "archlinux";
            phantom_spoofs = { rpm = [ { name = "glibc-devel"; } ]; };
        }"#;
        let nix = parse_nix(input).unwrap();
        let m = PackageManifest::from_nix(&nix).unwrap();
        let entries = m.effective_spoofs_for(SpoofTarget::Rpm);
        assert_eq!(entries[0].version, "2.39");
    }

    #[test]
    fn test_parse_phantom_spoofs_rejects_unknown_target() {
        let input = r#"{
            name = "glibc";
            version = "2.39";
            origin = "archlinux";
            phantom_spoofs = { gentoo = [ { name = "glibc"; } ]; };
        }"#;
        let nix = parse_nix(input).unwrap();
        let err = PackageManifest::from_nix(&nix).unwrap_err();
        assert!(err.to_string().contains("unknown phantom spoof target"));
    }

    #[test]
    fn test_phantom_spoofs_nix_roundtrip() {
        let input = r#"{
            name = "glibc";
            version = "2.39";
            origin = "archlinux";
            phantom_spoofs = {
                debian = [ { name = "libc6"; version = "2.39-0extos1"; } ];
                void = [ { name = "glibc"; version = ""; } ];
            };
        }"#;
        let nix = parse_nix(input).unwrap();
        let m = PackageManifest::from_nix(&nix).unwrap();

        let rendered = m.phantom_spoofs_nix().expect("spoof fragment");
        let parsed_back = parse_nix(&format!(
            "{{ name = \"glibc\"; version = \"2.39\"; origin = \"archlinux\"; {rendered} }}"
        ))
        .unwrap();
        let m2 = PackageManifest::from_nix(&parsed_back).unwrap();
        assert_eq!(m.phantom_spoofs, m2.phantom_spoofs);
    }

    #[test]
    fn test_spoof_target_from_str_and_as_str() {
        assert_eq!("debian".parse::<SpoofTarget>().unwrap(), SpoofTarget::Debian);
        assert_eq!(
            "archlinux".parse::<SpoofTarget>().unwrap(),
            SpoofTarget::Arch
        );
        assert_eq!("fedora".parse::<SpoofTarget>().unwrap(), SpoofTarget::Rpm);
        assert_eq!(SpoofTarget::Void.as_str(), "void");
        assert_eq!(SpoofTarget::Arch.canonical_origin(), "archlinux");
        assert!("plan9".parse::<SpoofTarget>().is_err());
        assert_eq!(SpoofTarget::from_origin("pypi"), None);
    }

    #[test]
    fn test_resolve_auto_spoofs_glibc() {
        let rows = resolve_auto_spoofs("archlinux", "glibc");
        assert!(
            rows.iter()
                .any(|(t, e)| *t == SpoofTarget::Debian && e.name == "libc6"),
            "rows: {rows:?}"
        );
        assert!(
            rows.iter()
                .any(|(t, e)| *t == SpoofTarget::Debian && e.name == "libc6-dev")
        );
        assert!(
            rows.iter()
                .any(|(t, e)| *t == SpoofTarget::Rpm && e.name == "glibc-devel")
        );

        // Origin aliases normalize to the same namespace.
        assert_eq!(
            resolve_auto_spoofs("arch", "glibc").len(),
            rows.len()
        );

        // Reverse direction: Debian libc6 → Arch glibc.
        let reverse = resolve_auto_spoofs("debian", "libc6");
        assert!(
            reverse
                .iter()
                .any(|(t, e)| *t == SpoofTarget::Arch && e.name == "glibc"),
            "reverse: {reverse:?}"
        );
    }

    #[test]
    fn test_resolve_auto_spoofs_unknown_is_empty() {
        assert!(resolve_auto_spoofs("archlinux", "no-such-package").is_empty());
        assert!(resolve_auto_spoofs("pypi", "numpy").is_empty());
    }

    #[test]
    fn test_spoof_mappings_toml_is_well_formed() {
        let records = parse_spoof_mappings(SPOOF_MAPPINGS_TOML).unwrap();
        assert!(records.len() >= 10, "records: {}", records.len());
        assert!(records.iter().any(|r| r.name == "glibc"));
        assert!(
            parse_spoof_mappings("[[spoof]]\norigin = \"x\"\nname = \"y\"\n").is_err()
        );
    }

    #[test]
    fn test_manifest_deserializes_without_spoof_field() {
        let json = r#"{
            "identity": { "origin": "archlinux", "name": "htop", "version": "3.3.0", "aliases": [] },
            "archive": null,
            "format": "ExtractedTree",
            "requires": [],
            "suggests": [],
            "build_requires": [],
            "capabilities": { "binaries": [], "libraries": [], "virtual_caps": [], "resources": [] },
            "security": null
        }"#;
        let m: PackageManifest = serde_json::from_str(json).unwrap();
        assert!(m.phantom_spoofs.is_empty());
    }
}
