//! Runlevel 0 blueprint parser — `tools`, `hooks`, `output` (PLAN 4.2.1).
//!
//! A *forge blueprint* is an ordinary ExtOS `.nix` document parsed by the
//! crate's existing configuration parser ([`crate::config::parse_nix`], so the
//! whole ExtOS grammar applies: comments, dotted keys, `rec { }`, optional
//! trailing `';'` before a closer). It describes **what** goes into an
//! initramfs forge and **where** the result lands. It never names a host path
//! implicitly: the boot/output directory is a mandatory blueprint field, so no
//! `/boot` or CAS-root default is baked into the library.
//!
//! # Blueprint syntax
//!
//! ```nix
//! {
//!   # Tools: CAS objects whose payloads are bind-mounted read-only into the
//!   # forge. `exec` names the file (inside the object's `content/`) to run;
//!   # it is optional for objects that only provide libraries or data.
//!   tools = [
//!     {
//!       name = "mkinitcpio";
//!       object = "BLAKE3-1f0c…";
//!       exec = "usr/bin/mkinitcpio";
//!     }
//!   ];
//!
//!   # Hooks: mkinitcpio install/runtime hooks. `name` is the entry placed in
//!   # the generated `HOOKS=(…)` array (declared order is preserved). A hook
//!   # that ships its own script also names the CAS object plus the path of
//!   # the script inside that object's content tree; it is staged at
//!   # `<forge>/etc/initcpio/{install,hooks}/<name>`.
//!   hooks = [
//!     {
//!       name = "base";
//!       object = "BLAKE3-9a41…";
//!       path = "usr/lib/initcpio/install/base";
//!     }
//!     { name = "udev"; }
//!   ];
//!
//!   # Binds: extra host trees to expose read-only (or read-write) inside the
//!   # forge. `target` is relative to the forge root. Use this for a host
//!   # toolchain when the blueprint does not ship every tool as a CAS object.
//!   binds = [
//!     { source = "/usr"; target = "usr"; readonly = true; }
//!   ];
//!
//!   # Output: where the produced artifact and the BLS entries land.
//!   output = {
//!     dir = "/boot";                      # mandatory, caller/host supplied
//!     name = "initramfs-linux.img";       # mandatory artifact file name
//!     preset = "linux";                   # optional mkinitcpio preset
//!     kernel = "linux";                   # optional kernel package label
//!   };
//! }
//! ```
//!
//! Missing required keys and wrong value kinds are reported as typed
//! [`ForgeError::Blueprint`] (field-addressed) or
//! [`ForgeError::BlueprintParse`] (whole-document) errors; nothing panics and
//! no default is silently invented for `dir`, `name`, `object`, or `path`.

use std::path::{Path, PathBuf};

use crate::config::{NixValue, parse_nix_with_path};
use crate::error::ExtosError;

use super::{ForgeError, ForgeResult};

/// Maximum length of a tool, hook or bind target name.
pub const MAX_NAME_LEN: usize = 64;

/// Maximum length of a CAS object identifier accepted from a blueprint.
pub const MAX_OBJECT_ID_LEN: usize = 200;

/// Where a hook script is staged inside the forge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookKind {
    /// `etc/initcpio/install/<name>` — the build-time hook.
    Install,
    /// `etc/initcpio/hooks/<name>` — the runtime hook.
    Runtime,
}

impl HookKind {
    /// Blueprint spelling: `"install"` or `"runtime"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Runtime => "runtime",
        }
    }

    /// Parse a blueprint `kind =` value.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "install" => Some(Self::Install),
            "runtime" => Some(Self::Runtime),
            _ => None,
        }
    }
}

/// A tool shipped as a CAS object and exposed inside the forge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgeTool {
    /// Unique tool name; also the directory name under the forge tool root.
    pub name: String,
    /// CAS object id (`BLAKE3-…` / `SHA256-…`) whose `content/` is bind-mounted.
    pub object: String,
    /// Optional executable path *inside* the object's content tree.
    pub exec: Option<PathBuf>,
}

/// An initramfs hook declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgeHook {
    /// Hook name as it appears in `HOOKS=(…)`.
    pub name: String,
    /// Install (default) or runtime hook.
    pub kind: HookKind,
    /// CAS object that provides the hook script, if any.
    pub object: Option<String>,
    /// Script path inside the object's content tree; required with `object`.
    pub path: Option<PathBuf>,
}

/// An extra host mount for the forge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgeBind {
    /// Host path to expose.
    pub source: PathBuf,
    /// Forge-relative target path (no leading `/`).
    pub target: PathBuf,
    /// Mount read-only (default `true`).
    pub readonly: bool,
}

/// Where the forge writes its artifact and the BLS entries live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgeOutput {
    /// Host directory for the produced artifact (typically the boot root).
    pub dir: PathBuf,
    /// Artifact file name inside [`ForgeOutput::dir`].
    pub name: String,
    /// Optional `mkinitcpio` preset.
    pub preset: Option<String>,
    /// Optional kernel package label used for BLS metadata.
    pub kernel: Option<String>,
}

/// A fully validated Runlevel 0 blueprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgeBlueprint {
    /// CAS-object tools, in declared order.
    pub tools: Vec<ForgeTool>,
    /// Hooks in declared order (= `HOOKS=(…)` order).
    pub hooks: Vec<ForgeHook>,
    /// Additional host binds.
    pub binds: Vec<ForgeBind>,
    /// Artifact destination.
    pub output: ForgeOutput,
}

impl ForgeBlueprint {
    /// Parse a blueprint from `.nix` source text.
    ///
    /// `source` is only used for error messages (typically the file name).
    pub fn parse(input: &str, source: &str) -> ForgeResult<Self> {
        let value = parse_nix_with_path(input, source).map_err(|e| match e {
            ExtosError::ConfigParse {
                path,
                line,
                message,
            } => ForgeError::BlueprintParse {
                file: path,
                message: if line == 0 {
                    message
                } else {
                    format!("line {line}: {message}")
                },
            },
            other => ForgeError::Extos(other),
        })?;
        Self::from_value(&value, source)
    }

    /// Parse a blueprint file. The path is used for error messages.
    pub fn parse_file(path: &Path) -> ForgeResult<Self> {
        let source = path.display().to_string();
        let text = std::fs::read_to_string(path)?;
        Self::parse(&text, &source)
    }

    /// Validate an already-parsed [`NixValue`] against the blueprint schema.
    pub fn from_value(value: &NixValue, source: &str) -> ForgeResult<Self> {
        let ctx = Ctx { source };
        let root = ctx.attrset(value, "")?;

        let tools_value = ctx.require(root, "tools", "")?;
        let tools = parse_tools(&ctx, tools_value)?;

        let hooks = match root.get("hooks") {
            Some(value) => parse_hooks(&ctx, value)?,
            None => Vec::new(),
        };

        let binds = match root.get("binds") {
            Some(value) => parse_binds(&ctx, value)?,
            None => Vec::new(),
        };

        let output_value = ctx.require(root, "output", "")?;
        let output = parse_output(&ctx, output_value)?;

        let blueprint = Self {
            tools,
            hooks,
            binds,
            output,
        };
        blueprint.validate()?;
        Ok(blueprint)
    }

    /// Look up a tool by name.
    pub fn tool(&self, name: &str) -> Option<&ForgeTool> {
        self.tools.iter().find(|tool| tool.name == name)
    }

    /// Hook names in declaration order (= generated `HOOKS=(…)` order).
    pub fn hook_names(&self) -> Vec<&str> {
        self.hooks.iter().map(|hook| hook.name.as_str()).collect()
    }

    /// Cross-field validation not covered by the per-field parsers.
    pub fn validate(&self) -> ForgeResult<()> {
        let ctx = Ctx { source: "" };
        let mut seen = std::collections::BTreeSet::new();
        for tool in &self.tools {
            if !seen.insert(tool.name.as_str()) {
                return Err(ctx.fail("tools.name", format!("duplicate tool name '{}'", tool.name)));
            }
        }

        let mut seen = std::collections::BTreeSet::new();
        for hook in &self.hooks {
            if !seen.insert(hook.name.as_str()) {
                return Err(ctx.fail("hooks.name", format!("duplicate hook name '{}'", hook.name)));
            }
        }

        // A bind target must be a distinct, non-nested location, otherwise the
        // mount order (and therefore the result) would be surprising.
        for (index, bind) in self.binds.iter().enumerate() {
            for other in &self.binds[index + 1..] {
                if bind.target == other.target {
                    return Err(ctx.fail(
                        "binds.target",
                        format!("duplicate bind target '{}'", bind.target.display()),
                    ));
                }
            }
        }

        if self.tools.is_empty() {
            return Err(ctx.fail("tools", "at least one tool is required"));
        }
        Ok(())
    }
}

/// Field-addressed blueprint validation context.
struct Ctx<'a> {
    source: &'a str,
}

impl Ctx<'_> {
    fn fail(&self, field: &str, message: impl Into<String>) -> ForgeError {
        ForgeError::Blueprint {
            file: self.source.to_string(),
            field: field.to_string(),
            message: message.into(),
        }
    }

    fn attrset<'v>(
        &self,
        value: &'v NixValue,
        field: &str,
    ) -> ForgeResult<&'v std::collections::BTreeMap<String, NixValue>> {
        value
            .as_attrset()
            .ok_or_else(|| self.fail(field, format!("expected an attribute set, got {value}")))
    }

    fn require<'v>(
        &self,
        map: &'v std::collections::BTreeMap<String, NixValue>,
        key: &str,
        parent: &str,
    ) -> ForgeResult<&'v NixValue> {
        map.get(key)
            .ok_or_else(|| self.fail(&join_field(parent, key), "missing required key"))
    }

    fn string(&self, value: &NixValue, field: &str) -> ForgeResult<String> {
        value
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| self.fail(field, format!("expected a string, got {value}")))
    }

    fn bool(&self, value: &NixValue, field: &str) -> ForgeResult<bool> {
        value
            .as_bool()
            .ok_or_else(|| self.fail(field, format!("expected true or false, got {value}")))
    }

    fn list<'v>(&self, value: &'v NixValue, field: &str) -> ForgeResult<&'v [NixValue]> {
        value
            .as_list()
            .ok_or_else(|| self.fail(field, format!("expected a list, got {value}")))
    }

    /// Validate a plain identifier (tool/hook name).
    fn name(&self, value: &str, field: &str) -> ForgeResult<()> {
        if value.is_empty() {
            return Err(self.fail(field, "name must not be empty"));
        }
        if value.len() > MAX_NAME_LEN {
            return Err(self.fail(field, format!("name exceeds {MAX_NAME_LEN} characters")));
        }
        if !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+'))
        {
            return Err(self.fail(
                field,
                format!("name '{value}' contains characters outside [A-Za-z0-9-_.+]"),
            ));
        }
        Ok(())
    }

    /// Validate a CAS object id: no separators, bounded length.
    fn object_id(&self, value: &str, field: &str) -> ForgeResult<()> {
        if value.is_empty() {
            return Err(self.fail(field, "object id must not be empty"));
        }
        if value.len() > MAX_OBJECT_ID_LEN {
            return Err(self.fail(
                field,
                format!("object id exceeds {MAX_OBJECT_ID_LEN} characters"),
            ));
        }
        if !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            return Err(self.fail(
                field,
                format!("object id '{value}' is not a CAS object id (no paths allowed)"),
            ));
        }
        Ok(())
    }

    /// Validate a path that must stay inside a content tree / the forge root.
    fn relative_path(&self, value: &NixValue, field: &str) -> ForgeResult<PathBuf> {
        let raw = self.string(value, field)?;
        validate_relative(&raw).map_err(|message| self.fail(field, message))?;
        Ok(PathBuf::from(raw))
    }
}

fn join_field(parent: &str, key: &str) -> String {
    if parent.is_empty() {
        key.to_string()
    } else {
        format!("{parent}.{key}")
    }
}

fn validate_relative(raw: &str) -> Result<(), String> {
    if raw.is_empty() {
        return Err("path must not be empty".into());
    }
    let path = Path::new(raw);
    if path.is_absolute() {
        return Err(format!("path '{raw}' must be relative"));
    }
    for component in path.components() {
        match component {
            std::path::Component::Normal(_) => {}
            std::path::Component::CurDir => {}
            _ => return Err(format!("path '{raw}' escapes its root")),
        }
    }
    if raw.split('/').any(|part| part == "..") {
        return Err(format!("path '{raw}' escapes its root"));
    }
    Ok(())
}

fn parse_tools(ctx: &Ctx, value: &NixValue) -> ForgeResult<Vec<ForgeTool>> {
    let items = ctx.list(value, "tools")?;
    let mut tools = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let field = format!("tools[{index}]");
        let map = ctx.attrset(item, &field)?;
        let name_value = ctx.require(map, "name", &field)?;
        let name = ctx.string(name_value, &format!("{field}.name"))?;
        ctx.name(&name, &format!("{field}.name"))?;

        let object_value = ctx.require(map, "object", &field)?;
        let object = ctx.string(object_value, &format!("{field}.object"))?;
        ctx.object_id(&object, &format!("{field}.object"))?;

        let exec = match map.get("exec") {
            Some(value) => Some(ctx.relative_path(value, &format!("{field}.exec"))?),
            None => None,
        };

        tools.push(ForgeTool { name, object, exec });
    }
    Ok(tools)
}

fn parse_hooks(ctx: &Ctx, value: &NixValue) -> ForgeResult<Vec<ForgeHook>> {
    let items = ctx.list(value, "hooks")?;
    let mut hooks = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let field = format!("hooks[{index}]");
        let map = ctx.attrset(item, &field)?;
        let name_value = ctx.require(map, "name", &field)?;
        let name = ctx.string(name_value, &format!("{field}.name"))?;
        ctx.name(&name, &format!("{field}.name"))?;

        let kind = match map.get("kind") {
            Some(value) => {
                let raw = ctx.string(value, &format!("{field}.kind"))?;
                HookKind::parse(&raw).ok_or_else(|| {
                    ctx.fail(
                        &format!("{field}.kind"),
                        format!("unknown hook kind '{raw}' (expected \"install\" or \"runtime\")"),
                    )
                })?
            }
            None => HookKind::Install,
        };

        let object = match map.get("object") {
            Some(value) => {
                let raw = ctx.string(value, &format!("{field}.object"))?;
                ctx.object_id(&raw, &format!("{field}.object"))?;
                Some(raw)
            }
            None => None,
        };
        let path = match map.get("path") {
            Some(value) => Some(ctx.relative_path(value, &format!("{field}.path"))?),
            None => None,
        };
        match (&object, &path) {
            (Some(_), None) => {
                return Err(ctx.fail(
                    &format!("{field}.path"),
                    "a hook with `object` must also name the script `path`",
                ));
            }
            (None, Some(_)) => {
                return Err(ctx.fail(
                    &format!("{field}.object"),
                    "a hook with `path` must also name its `object`",
                ));
            }
            _ => {}
        }

        hooks.push(ForgeHook {
            name,
            kind,
            object,
            path,
        });
    }
    Ok(hooks)
}

fn parse_binds(ctx: &Ctx, value: &NixValue) -> ForgeResult<Vec<ForgeBind>> {
    let items = ctx.list(value, "binds")?;
    let mut binds = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let field = format!("binds[{index}]");
        let map = ctx.attrset(item, &field)?;

        let source_value = ctx.require(map, "source", &field)?;
        let source = ctx.string(source_value, &format!("{field}.source"))?;
        if source.is_empty() {
            return Err(ctx.fail(&format!("{field}.source"), "source must not be empty"));
        }
        if !Path::new(&source).is_absolute() {
            return Err(ctx.fail(
                &format!("{field}.source"),
                format!("source '{source}' must be an absolute host path"),
            ));
        }

        let target_value = ctx.require(map, "target", &field)?;
        let target = ctx.relative_path(target_value, &format!("{field}.target"))?;

        let readonly = match map.get("readonly") {
            Some(value) => ctx.bool(value, &format!("{field}.readonly"))?,
            None => true,
        };

        binds.push(ForgeBind {
            source: PathBuf::from(source),
            target,
            readonly,
        });
    }
    Ok(binds)
}

fn parse_output(ctx: &Ctx, value: &NixValue) -> ForgeResult<ForgeOutput> {
    let map = ctx.attrset(value, "output")?;

    let dir_value = ctx.require(map, "dir", "output")?;
    let dir = ctx.string(dir_value, "output.dir")?;
    if dir.is_empty() {
        return Err(ctx.fail("output.dir", "directory must not be empty"));
    }

    let name_value = ctx.require(map, "name", "output")?;
    let name = ctx.string(name_value, "output.name")?;
    if name.is_empty() {
        return Err(ctx.fail("output.name", "artifact name must not be empty"));
    }
    if name.contains('/') {
        return Err(ctx.fail(
            "output.name",
            format!("artifact name '{name}' must be a plain file name"),
        ));
    }

    let preset = match map.get("preset") {
        Some(value) => {
            let raw = ctx.string(value, "output.preset")?;
            ctx.name(&raw, "output.preset")?;
            Some(raw)
        }
        None => None,
    };
    let kernel = match map.get("kernel") {
        Some(value) => {
            let raw = ctx.string(value, "output.kernel")?;
            ctx.name(&raw, "output.kernel")?;
            Some(raw)
        }
        None => None,
    };

    Ok(ForgeOutput {
        dir: PathBuf::from(dir),
        name,
        preset,
        kernel,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
{
  tools = [
    { name = "mkinitcpio"; object = "BLAKE3-abc123"; exec = "usr/bin/mkinitcpio"; }
    { name = "libs"; object = "BLAKE3-def456"; }
  ];
  hooks = [
    { name = "base"; object = "BLAKE3-aaa"; path = "usr/lib/initcpio/install/base"; }
    { name = "udev"; }
    { name = "keymap"; kind = "runtime"; }
  ];
  binds = [ { source = "/usr"; target = "usr"; } ];
  output = { dir = "/boot"; name = "initramfs-linux.img"; preset = "linux"; kernel = "linux"; };
}
"#;

    fn err(src: &str) -> ForgeError {
        match ForgeBlueprint::parse(src, "test.nix") {
            Ok(bp) => panic!("expected a blueprint error, got {bp:?}"),
            Err(e) => e,
        }
    }

    fn field_of(e: &ForgeError) -> String {
        match e {
            ForgeError::Blueprint { field, .. } => field.clone(),
            other => panic!("expected a field error, got {other}"),
        }
    }

    #[test]
    fn test_parse_valid_blueprint() {
        let bp = ForgeBlueprint::parse(VALID, "test.nix").expect("valid blueprint");
        assert_eq!(bp.tools.len(), 2);
        assert_eq!(bp.tools[0].name, "mkinitcpio");
        assert_eq!(bp.tools[0].object, "BLAKE3-abc123");
        assert_eq!(
            bp.tools[0].exec.as_deref(),
            Some(Path::new("usr/bin/mkinitcpio"))
        );
        assert_eq!(bp.tools[1].exec, None);

        assert_eq!(bp.hooks.len(), 3);
        assert_eq!(bp.hook_names(), vec!["base", "udev", "keymap"]);
        assert_eq!(bp.hooks[0].kind, HookKind::Install);
        assert_eq!(bp.hooks[2].kind, HookKind::Runtime);
        assert_eq!(bp.hooks[1].object, None);

        assert_eq!(bp.binds.len(), 1);
        assert!(bp.binds[0].readonly, "readonly defaults to true");

        assert_eq!(bp.output.dir, PathBuf::from("/boot"));
        assert_eq!(bp.output.name, "initramfs-linux.img");
        assert_eq!(bp.output.preset.as_deref(), Some("linux"));
    }

    #[test]
    fn test_parse_accepts_trailing_semicolon_and_comments() {
        let src = r#"
        # a comment
        {
          tools = [ { name = "t"; object = "BLAKE3-1" } ];
          output = { dir = "/b"; name = "i.img" }
        }
        "#;
        let bp = ForgeBlueprint::parse(src, "s.nix").expect("should parse");
        assert!(bp.hooks.is_empty());
        assert!(bp.binds.is_empty());
    }

    #[test]
    fn test_missing_tools_key() {
        let e = err("{ output = { dir = \"/b\"; name = \"i\"; }; }");
        assert_eq!(field_of(&e), "tools");
        assert!(e.to_string().contains("missing required key"), "{e}");
    }

    #[test]
    fn test_missing_output_key() {
        let e = err("{ tools = [ { name = \"t\"; object = \"BLAKE3-1\"; } ]; }");
        assert_eq!(field_of(&e), "output");
    }

    #[test]
    fn test_missing_output_dir_and_name() {
        let e = err(
            "{ tools = [ { name = \"t\"; object = \"BLAKE3-1\"; } ]; output = { name = \"i\"; }; }",
        );
        assert_eq!(field_of(&e), "output.dir");

        let e = err(
            "{ tools = [ { name = \"t\"; object = \"BLAKE3-1\"; } ]; output = { dir = \"/b\"; }; }",
        );
        assert_eq!(field_of(&e), "output.name");
    }

    #[test]
    fn test_missing_tool_object() {
        let e = err("{ tools = [ { name = \"t\"; } ]; output = { dir = \"/b\"; name = \"i\"; }; }");
        assert_eq!(field_of(&e), "tools[0].object");
    }

    #[test]
    fn test_wrong_kind_for_tools_is_typed() {
        let e = err("{ tools = \"nope\"; output = { dir = \"/b\"; name = \"i\"; }; }");
        assert_eq!(field_of(&e), "tools");
        assert!(e.to_string().contains("expected a list"), "{e}");
    }

    #[test]
    fn test_wrong_kind_for_name_is_typed() {
        let e = err(
            "{ tools = [ { name = 42; object = \"BLAKE3-1\"; } ]; output = { dir = \"/b\"; name = \"i\"; }; }",
        );
        assert_eq!(field_of(&e), "tools[0].name");
        assert!(e.to_string().contains("expected a string"), "{e}");
    }

    #[test]
    fn test_object_id_rejects_paths_and_empties() {
        let e = err(
            "{ tools = [ { name = \"t\"; object = \"objects/abc\"; } ]; output = { dir = \"/b\"; name = \"i\"; }; }",
        );
        assert_eq!(field_of(&e), "tools[0].object");
        assert!(e.to_string().contains("not a CAS object id"), "{e}");

        let e = err(
            "{ tools = [ { name = \"t\"; object = \"../x\"; } ]; output = { dir = \"/b\"; name = \"i\"; }; }",
        );
        assert_eq!(field_of(&e), "tools[0].object");
    }

    #[test]
    fn test_exec_must_stay_inside_content_tree() {
        for bad in ["/usr/bin/x", "../x", "a/../../b"] {
            let src = format!(
                "{{ tools = [ {{ name = \"t\"; object = \"BLAKE3-1\"; exec = \"{bad}\"; }} ]; output = {{ dir = \"/b\"; name = \"i\"; }}; }}"
            );
            let e = err(&src);
            assert_eq!(field_of(&e), "tools[0].exec", "for {bad}");
        }
    }

    #[test]
    fn test_tool_name_charset() {
        let e = err(
            "{ tools = [ { name = \"bad name\"; object = \"BLAKE3-1\"; } ]; output = { dir = \"/b\"; name = \"i\"; }; }",
        );
        assert_eq!(field_of(&e), "tools[0].name");
    }

    #[test]
    fn test_duplicate_tool_names_rejected() {
        let e = err(
            "{ tools = [ { name = \"t\"; object = \"BLAKE3-1\"; } { name = \"t\"; object = \"BLAKE3-2\"; } ]; output = { dir = \"/b\"; name = \"i\"; }; }",
        );
        assert_eq!(field_of(&e), "tools.name");
        assert!(e.to_string().contains("duplicate"), "{e}");
    }

    #[test]
    fn test_duplicate_hook_names_rejected() {
        let e = err(
            "{ tools = [ { name = \"t\"; object = \"BLAKE3-1\"; } ]; hooks = [ { name = \"base\"; } { name = \"base\"; } ]; output = { dir = \"/b\"; name = \"i\"; }; }",
        );
        assert_eq!(field_of(&e), "hooks.name");
    }

    #[test]
    fn test_hook_object_requires_path() {
        let e = err(
            "{ tools = [ { name = \"t\"; object = \"BLAKE3-1\"; } ]; hooks = [ { name = \"base\"; object = \"BLAKE3-9\"; } ]; output = { dir = \"/b\"; name = \"i\"; }; }",
        );
        assert_eq!(field_of(&e), "hooks[0].path");
    }

    #[test]
    fn test_hook_path_requires_object() {
        let e = err(
            "{ tools = [ { name = \"t\"; object = \"BLAKE3-1\"; } ]; hooks = [ { name = \"base\"; path = \"x\"; } ]; output = { dir = \"/b\"; name = \"i\"; }; }",
        );
        assert_eq!(field_of(&e), "hooks[0].object");
    }

    #[test]
    fn test_unknown_hook_kind_rejected() {
        let e = err(
            "{ tools = [ { name = \"t\"; object = \"BLAKE3-1\"; } ]; hooks = [ { name = \"base\"; kind = \"post\"; } ]; output = { dir = \"/b\"; name = \"i\"; }; }",
        );
        assert_eq!(field_of(&e), "hooks[0].kind");
        assert!(e.to_string().contains("unknown hook kind"), "{e}");
    }

    #[test]
    fn test_bind_requires_absolute_source_and_relative_target() {
        let e = err(
            "{ tools = [ { name = \"t\"; object = \"BLAKE3-1\"; } ]; binds = [ { source = \"usr\"; target = \"usr\"; } ]; output = { dir = \"/b\"; name = \"i\"; }; }",
        );
        assert_eq!(field_of(&e), "binds[0].source");

        let e = err(
            "{ tools = [ { name = \"t\"; object = \"BLAKE3-1\"; } ]; binds = [ { source = \"/usr\"; target = \"../usr\"; } ]; output = { dir = \"/b\"; name = \"i\"; }; }",
        );
        assert_eq!(field_of(&e), "binds[0].target");
    }

    #[test]
    fn test_bind_readonly_false_honoured() {
        let bp = ForgeBlueprint::parse(
            "{ tools = [ { name = \"t\"; object = \"BLAKE3-1\"; } ]; binds = [ { source = \"/tmp\"; target = \"tmp\"; readonly = false; } ]; output = { dir = \"/b\"; name = \"i\"; }; }",
            "s.nix",
        )
        .expect("valid");
        assert!(!bp.binds[0].readonly);
    }

    #[test]
    fn test_output_name_must_be_plain_file() {
        let e = err(
            "{ tools = [ { name = \"t\"; object = \"BLAKE3-1\"; } ]; output = { dir = \"/b\"; name = \"sub/i\"; }; }",
        );
        assert_eq!(field_of(&e), "output.name");
    }

    #[test]
    fn test_empty_tool_list_rejected() {
        let e = err("{ tools = [ ]; output = { dir = \"/b\"; name = \"i\"; }; }");
        assert_eq!(field_of(&e), "tools");
    }

    #[test]
    fn test_document_must_be_attrset() {
        let e = err("[ 1 2 3 ]");
        assert_eq!(field_of(&e), "");
    }

    #[test]
    fn test_syntax_error_maps_to_blueprint_parse() {
        let e = err("{ tools = [ }");
        match e {
            ForgeError::BlueprintParse { file, .. } => assert_eq!(file, "test.nix"),
            other => panic!("expected parse error, got {other}"),
        }
    }

    #[test]
    fn test_parse_file_reads_and_reports_path() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("blueprint.nix");
        std::fs::write(&path, VALID).expect("write");
        let bp = ForgeBlueprint::parse_file(&path).expect("parse file");
        assert_eq!(bp.tools.len(), 2);

        let missing = dir.path().join("nope.nix");
        match ForgeBlueprint::parse_file(&missing) {
            Err(ForgeError::Io(_)) => {}
            other => panic!("expected io error, got {other:?}"),
        }
    }

    #[test]
    fn test_tool_lookup_and_blueprint_to_extos_error() {
        let bp = ForgeBlueprint::parse(VALID, "test.nix").expect("valid");
        assert_eq!(bp.tool("libs").map(|t| t.name.as_str()), Some("libs"));
        assert!(bp.tool("nope").is_none());

        // The forge error must convert into the crate-wide error type.
        let e = ForgeBlueprint::parse("{ }", "x.nix").expect_err("must fail");
        let converted: ExtosError = e.into();
        assert!(matches!(converted, ExtosError::ConfigParse { .. }));
    }
}
