//! Integration tests for PLAN Phase 6 sub-phase 6.1 (CAS sanitization).
//!
//! * 6.1.1 — the sanitizer strips setuid/setgid from regular files while
//!   leaving directories and unaffected files alone.
//! * 6.1.3 — end to end: ingest a setuid payload, verify the CAS copy is
//!   clean, verify the weave plan re-applies declared file capabilities, and
//!   verify the journal records the kernel's refusal honestly on this
//!   unprivileged host.
//!
//! The real-application probe re-executes this test binary inside an
//! unprivileged user+mount namespace (`unshare --user --map-root-user
//! --mount`) and calls [`filecaps::apply_file_caps`] on a namespace-owned
//! tmpfs, where the mapped root holds `CAP_SETFCAP`. The child then reads the
//! result back with the host `getcap`, proving the encoder produces a
//! kernel-valid `security.capability` xattr. Hosts without `unshare` or with
//! user namespaces disabled print an honest `SKIP …` — never a silent pass.

use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;

use libextos::cas::CasRepository;
use libextos::ingest;
use libextos::security::filecaps;
use libextos::types::HashAlgorithm;
use libextos::weaver::plan::{JournalAction, PlanOp};

// ─── Fixtures ───────────────────────────────────────────────────

fn tar_xz(archive: &Path, src: &Path) {
    let status = Command::new("tar")
        .arg("--xz")
        .arg("-cf")
        .arg(archive)
        .arg("-C")
        .arg(src)
        .arg(".")
        .status()
        .expect("spawn tar");
    assert!(status.success(), "failed to create {}", archive.display());
}

/// Native `.pkt.tar.xz`: `metadata/manifest.nix` + `content/` with a setuid
/// tool and a `security` block declaring a capability grant on it.
fn native_security_fixture(tmpdir: &Path) -> PathBuf {
    let src = tmpdir.join("native_src");
    fs::create_dir_all(src.join("metadata")).unwrap();
    fs::create_dir_all(src.join("content/usr/bin")).unwrap();
    fs::write(
        src.join("metadata/manifest.nix"),
        r#"{
  identity = {
    origin = "scratch";
    name = "idtool";
    version = "1.0";
  };
  format = "extracted-tree";
  capabilities = {
    binaries = [ "idtool" ];
    libraries = [];
  };
  security = {
    capabilities = {
      "usr/bin/idtool" = [ "CAP_NET_RAW" ];
    };
    mac_profile = "idtools";
  };
}"#,
    )
    .unwrap();
    fs::write(src.join("content/usr/bin/idtool"), "#!/bin/sh\necho id\n").unwrap();
    // The privilege bit the CAS sanitizer must never let into the store.
    fs::set_permissions(
        src.join("content/usr/bin/idtool"),
        fs::Permissions::from_mode(0o4755u32),
    )
    .unwrap();

    let archive = tmpdir.join("idtool-1.0-1-x86_64.pkt.tar.xz");
    tar_xz(&archive, &src);
    archive
}

fn file_mode(path: impl AsRef<Path>) -> u32 {
    fs::metadata(path.as_ref())
        .expect("stat fixture output")
        .permissions()
        .mode()
}

// ─── 6.1.1: the sanitizer ───────────────────────────────────────

#[test]
fn sanitizer_strips_setuid_setgid_from_files_but_not_dirs() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    fs::write(root.join("setuid"), b"x").unwrap();
    fs::set_permissions(root.join("setuid"), fs::Permissions::from_mode(0o4755u32)).unwrap();
    fs::write(root.join("setgid"), b"x").unwrap();
    fs::set_permissions(root.join("setgid"), fs::Permissions::from_mode(0o2750u32)).unwrap();
    fs::write(root.join("plain"), b"x").unwrap();
    fs::set_permissions(root.join("plain"), fs::Permissions::from_mode(0o755u32)).unwrap();
    fs::create_dir(root.join("dropbox")).unwrap();
    fs::set_permissions(root.join("dropbox"), fs::Permissions::from_mode(0o2770u32)).unwrap();
    symlink("plain", root.join("link")).unwrap();

    let stripped = ingest::sanitize_permissions(root).unwrap();

    assert_eq!(stripped, 2, "exactly the two hardened regular files");
    assert_eq!(file_mode(root.join("setuid")) & 0o6000u32, 0);
    assert_eq!(file_mode(root.join("setuid")) & 0o755u32, 0o755u32, "rwx bits survive");
    assert_eq!(file_mode(root.join("setgid")) & 0o6000u32, 0);
    assert_eq!(file_mode(root.join("setgid")) & 0o750u32, 0o750u32);
    assert_eq!(file_mode(root.join("plain")) & 0o777u32, 0o755u32);
    // Directory setgid is legitimate (shared drop-boxes) and stays.
    assert_eq!(file_mode(root.join("dropbox")) & 0o2000u32, 0o2000u32);
}

// ─── 6.1.3: ingest → CAS → plan → weave ─────────────────────────

#[test]
fn setuid_never_reaches_the_cas_and_caps_are_reapplied_on_weave() {
    let dir = tempfile::tempdir().unwrap();
    let repo_dir = dir.path().join("repo");
    let repo = CasRepository::open(&repo_dir, HashAlgorithm::Blake3).expect("open CAS");

    let archive = native_security_fixture(dir.path());
    let result = ingest::ingest_local_archive(&repo, &archive).expect("ingest native fixture");
    assert_eq!(result.name, "idtool");
    // tar-rs may already drop the setuid bit while unpacking; the sanitizer
    // is the guarantee, not the count (test 1 above proves the strip on a
    // hardened tree). Either way nothing hardened may reach the CAS.
    assert!(result.sanitized_bits <= 1, "sanitized_bits: {}", result.sanitized_bits);

    // The CAS copy — the immutable substrate every roof is woven from —
    // carries no setuid/setgid on any regular file.
    let cas_tool = repo
        .object_path(&result.hash)
        .join("content/usr/bin/idtool");
    assert_eq!(file_mode(&cas_tool) & 0o6000u32, 0, "CAS copy must be clean");

    // The plan re-applies the declared grant on the woven copy (6.1.2).
    let plan = libextos::weaver::plan::plan_from_refs(
        &repo,
        &[libextos::weaver::plan::CasRef {
            origin: "scratch".into(),
            name: "idtool".into(),
            version: "1.0".into(),
        }],
    )
    .expect("build plan");
    let caps_ops: Vec<_> = plan
        .entries()
        .iter()
        .filter_map(|e| match &e.op {
            PlanOp::FileCaps {
                rel_path,
                capabilities,
            } => Some((rel_path.clone(), capabilities.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(
        caps_ops,
        vec![(PathBuf::from("usr/bin/idtool"), vec!["CAP_NET_RAW".to_string()])],
        "exactly one file-capability op for the declared path"
    );

    // Execute into a scratch roof. On this unprivileged host the kernel
    // refuses the xattr write — the journal must record an honest skip with
    // a reason, and the woven file itself stays clean of setuid.
    let roof = dir.path().join("roof");
    let execution =
        libextos::weaver::plan::execute_plan(&plan, &roof).expect("execute plan");
    let woven = roof.join("usr/bin/idtool");
    assert!(woven.exists(), "woven tool materialized");
    assert_eq!(file_mode(&woven) & 0o6000u32, 0, "woven copy inherits the clean CAS mode");

    assert_eq!(execution.file_caps_applied, 0);
    assert_eq!(execution.file_caps_skipped, 1);
    let skipped = execution
        .journal
        .iter()
        .find_map(|row| match &row.action {
            JournalAction::FileCapsSkipped(reason) => Some(reason.clone()),
            _ => None,
        })
        .expect("journal records the skip");
    assert!(
        skipped.contains("security.capability") || skipped.contains("set file capabilities"),
        "skip reason names the kernel refusal: {skipped}"
    );

    // Idempotent re-run: the skip is repeatable, nothing fatal.
    let rerun =
        libextos::weaver::plan::execute_plan(&plan, &roof).expect("re-execute plan");
    assert_eq!(rerun.file_caps_skipped, 1);
    assert_eq!(rerun.file_caps_applied, 0);
}

// ─── Real-application probe (unprivileged user namespace) ───────

/// The in-namespace child: mounts a private tmpfs, applies the encoder's
/// output for real, then reads it back with the host `getcap`.
#[test]
#[ignore = "only run as the unshare probe child (see file docs)"]
fn file_caps_probe_child() {
    let dir = std::env::var_os("EXTOS_CAPS_PROBE_DIR")
        .expect("probe child requires EXTOS_CAPS_PROBE_DIR");
    let dir = PathBuf::from(dir);

    // Root inside the new user+mount namespace: mount a tmpfs owned by this
    // namespace so CAP_SETFCAP covers it (host mounts stay out of reach).
    let c_dir = std::ffi::CString::new(dir.as_os_str().as_bytes()).unwrap();
    // SAFETY: c_dir outlives the call; the syscall arguments are plain data.
    let rc = unsafe {
        libc::mount(
            std::ptr::null(),
            c_dir.as_ptr(),
            c"tmpfs".as_ptr(),
            0 as libc::c_ulong,
            std::ptr::null(),
        )
    };
    assert_eq!(rc, 0, "tmpfs mount inside the namespace failed");

    let tool = dir.join("tool");
    fs::write(&tool, b"#!/bin/sh\n").unwrap();
    filecaps::apply_file_caps(&tool, &["CAP_NET_RAW".into()])
        .expect("apply_file_caps must succeed with CAP_SETFCAP in the namespace");

    // The canonical reader must interpret the encoded xattr as +ep.
    let out = Command::new("getcap")
        .arg(&tool)
        .output()
        .expect("spawn getcap");
    assert!(out.status.success(), "getcap failed: {:?}", out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("cap_net_raw=ep"),
        "getcap must report cap_net_raw=ep, got: {stdout}"
    );
}

#[test]
fn real_application_probe_inside_user_namespace() {
    let Some(unshare) = probe_unshare() else {
        println!("SKIP unshare CLI not available; file-capability application not host-proven");
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    let probe_dir = dir.path().join("probe");
    fs::create_dir_all(&probe_dir).unwrap();

    let exe = std::env::current_exe().expect("locate test binary");
    let output = Command::new(&unshare)
        .args(["--user", "--map-root-user", "--mount"])
        .arg(&exe)
        .args(["file_caps_probe_child", "--exact", "--ignored", "--nocapture"])
        .env("EXTOS_CAPS_PROBE_DIR", &probe_dir)
        .output()
        .expect("spawn unshare probe");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Kernel/userns restrictions (containers, seccomp) are an honest skip.
        assert!(
            stderr.contains("Operation not permitted")
                || stderr.contains("EPERM")
                || stderr.contains("user namespaces")
                || stderr.contains("disabled"),
            "unexpected probe failure (rc={:?}): {stderr}",
            output.status.code()
        );
        println!("SKIP user namespaces unavailable; file-capability application not host-proven");
        return;
    }
    // Success: the child already asserted cap_net_raw=ep via getcap.
}

/// Locate the `unshare` CLI, if this host has one.
fn probe_unshare() -> Option<PathBuf> {
    probe_tool("unshare")
}

/// Locate an executable on `PATH`, if present.
fn probe_tool(name: &str) -> Option<PathBuf> {
    for dir in std::env::split_paths(&std::env::var_os("PATH")?) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

// ─── Adversarial: plan-level declaration handling ───────────────

/// Native fixture with an arbitrary `security` block.
fn adversarial_fixture(tmpdir: &Path, name: &str, security: &str) -> (PathBuf, PathBuf) {
    let src = tmpdir.join(format!("{name}_src"));
    fs::create_dir_all(src.join("metadata")).unwrap();
    fs::create_dir_all(src.join("content/usr/bin")).unwrap();
    fs::write(
        src.join("metadata/manifest.nix"),
        format!(
            r#"{{
  identity = {{ origin = "scratch"; name = "{name}"; version = "1.0"; }};
  format = "extracted-tree";
  capabilities = {{ binaries = [ "{name}" ]; libraries = []; }};
  security = {security};
}}"#
        ),
    )
    .unwrap();
    fs::write(src.join("content/usr/bin/x"), "#!/bin/sh\n").unwrap();

    let archive = tmpdir.join(format!("{name}-1.0.pkt.tar.xz"));
    tar_xz(&archive, &src);
    (archive, tmpdir.join(format!("{name}_repo")))
}

#[test]
fn unknown_capability_name_fails_plan_construction() {
    let dir = tempfile::tempdir().unwrap();
    let (archive, repo_dir) = adversarial_fixture(
        dir.path(),
        "badcap",
        r#"{ capabilities = { "usr/bin/x" = [ "CAP_TOTALLY_MADE_UP" ]; }; }"#,
    );
    let repo = CasRepository::open(&repo_dir, HashAlgorithm::Blake3).unwrap();
    ingest::ingest_local_archive(&repo, &archive).unwrap();

    let err = libextos::weaver::plan::plan_from_refs(
        &repo,
        &[libextos::weaver::plan::CasRef {
            origin: "scratch".into(),
            name: "badcap".into(),
            version: "1.0".into(),
        }],
    )
    .expect_err("unknown CAP_* must fail the plan");
    assert!(
        err.to_string().contains("CAP_TOTALLY_MADE_UP"),
        "error names the offender: {err}"
    );
}

#[test]
fn unshipped_and_foreign_capability_paths_are_warned_not_applied() {
    let dir = tempfile::tempdir().unwrap();

    // `ghost` declares a grant for a file it does not ship.
    let (ghost_archive, ghost_repo) = adversarial_fixture(
        dir.path(),
        "ghost",
        r#"{ capabilities = { "usr/bin/does-not-exist" = [ "CAP_NET_RAW" ]; }; }"#,
    );
    let repo = CasRepository::open(&ghost_repo, HashAlgorithm::Blake3).unwrap();
    ingest::ingest_local_archive(&repo, &ghost_archive).unwrap();
    let plan = libextos::weaver::plan::plan_from_refs(
        &repo,
        &[libextos::weaver::plan::CasRef {
            origin: "scratch".into(),
            name: "ghost".into(),
            version: "1.0".into(),
        }],
    )
    .expect("plan builds");
    assert!(
        plan.entries()
            .iter()
            .all(|e| !matches!(e.op, PlanOp::FileCaps { .. })),
        "no caps op for a missing payload"
    );
    assert!(
        plan.warnings()
            .iter()
            .any(|w| w.contains("does-not-exist") && w.contains("skipped")),
        "warning names the path: {:?}",
        plan.warnings()
    );

    // `claimer` declares a grant for a file `owner` ships: after collision
    // resolution (scratch priority 10 beats debian 20) the foreign claim is
    // dropped with a warning and only the winner's grant is applied.
    let shared = CasRepository::open(dir.path().join("shared"), HashAlgorithm::Blake3).unwrap();
    for (name, origin, body, security) in [
        (
            "owner",
            "scratch",
            "#!/bin/sh\necho owner",
            r#"{ capabilities = { "usr/bin/clash" = [ "CAP_NET_RAW" ]; }; }"#,
        ),
        (
            "claimer",
            "debian",
            "#!/bin/sh\necho claimer",
            r#"{ capabilities = { "usr/bin/clash" = [ "CAP_NET_ADMIN" ]; }; }"#,
        ),
    ] {
        let src = dir.path().join(format!("{name}_src2"));
        fs::create_dir_all(src.join("metadata")).unwrap();
        fs::create_dir_all(src.join("content/usr/bin")).unwrap();
        fs::write(
            src.join("metadata/manifest.nix"),
            format!(
                r#"{{ identity = {{ origin = "{origin}"; name = "{name}"; version = "1.0"; }}; format = "extracted-tree"; capabilities = {{ binaries = []; libraries = []; }}; security = {security}; }}"#
            ),
        )
        .unwrap();
        fs::write(src.join("content/usr/bin/clash"), body).unwrap();
        let archive = dir.path().join(format!("{name}-1.0.pkt.tar.xz"));
        tar_xz(&archive, &src);
        ingest::ingest_local_archive(&shared, &archive).unwrap();
    }
    let plan = libextos::weaver::plan::plan_from_refs(
        &shared,
        &[
            libextos::weaver::plan::CasRef {
                origin: "scratch".into(),
                name: "owner".into(),
                version: "1.0".into(),
            },
            libextos::weaver::plan::CasRef {
                origin: "debian".into(),
                name: "claimer".into(),
                version: "1.0".into(),
            },
        ],
    )
    .expect("plan builds with a collision");
    let caps: Vec<_> = plan
        .entries()
        .iter()
        .filter_map(|e| match &e.op {
            PlanOp::FileCaps {
                rel_path,
                capabilities,
                ..
            } => Some((rel_path.clone(), capabilities.clone())),
            _ => None,
        })
        .collect();
    assert!(
        caps.iter().all(|(p, c)| p == &PathBuf::from("usr/bin/clash")
            && c == &vec!["CAP_NET_RAW".to_string()]),
        "only the winner's grant is applied: {caps:?}"
    );
    assert!(
        plan.warnings()
            .iter()
            .any(|w| w.contains("provided by scratch/owner")),
        "foreign claimant warned: {:?}",
        plan.warnings()
    );
}

// ─── 6.2 glue: roof security pass ───────────────────────────────

#[test]
fn roof_security_writes_apparmor_profiles_and_records_selinux_refusals() {
    use libextos::security::{apply_roof_security, RoofPackage};

    let dir = tempfile::tempdir().unwrap();
    let repo_dir = dir.path().join("repo");
    let repo = CasRepository::open(&repo_dir, HashAlgorithm::Blake3).expect("open CAS");
    let archive = native_security_fixture(dir.path());
    let result = ingest::ingest_local_archive(&repo, &archive).expect("ingest");

    let roof = dir.path().join("roof");
    libextos::weaver::plan::execute_plan(
        &libextos::weaver::plan::plan_from_refs(
            &repo,
            &[libextos::weaver::plan::CasRef {
                origin: "scratch".into(),
                name: "idtool".into(),
                version: "1.0".into(),
            }],
        )
        .unwrap(),
        &roof,
    )
    .unwrap();

    let report = apply_roof_security(
        &repo,
        &[RoofPackage {
            label: "scratch/idtool".into(),
            hash: result.hash.clone(),
        }],
        &roof,
    )
    .expect("roof security pass");

    // PLAN 6.2.1: the profile is written where apparmor_parser would find it.
    let profile_path = roof.join("etc/apparmor.d/idtools");
    let text = fs::read_to_string(&profile_path).expect("profile written");
    assert!(text.contains("profile idtools /usr/bin/idtool flags="));
    assert!(text.contains("capability net_raw,"));
    assert_eq!(report.apparmor_profiles, vec!["idtools".to_string()]);
    assert!(report.apparmor_skipped.is_empty());

    // PLAN 6.2.2: the labeling pass is honest on every host. On kernels that
    // accept `security.selinux` xattrs without SELinux enabled (this host's
    // 6.18 tmpfs does), the label applies; elsewhere the kernel refuses and
    // the pass records exactly one skip per package. Either way every woven
    // file is accounted for.
    let content_files = 1; // usr/bin/idtool
    assert_eq!(
        report.selinux_applied + report.selinux_skipped.len(),
        content_files,
        "every woven file is applied or honestly recorded: {:?}",
        report
    );
    for skip in &report.selinux_skipped {
        assert!(
            skip.contains("scratch/idtool"),
            "skips name the package: {skip}"
        );
    }

    // Byte-identical re-run (idempotent declarative write).
    let rerun = apply_roof_security(
        &repo,
        &[RoofPackage {
            label: "scratch/idtool".into(),
            hash: result.hash,
        }],
        &roof,
    )
    .unwrap();
    assert_eq!(
        fs::read_to_string(&profile_path).unwrap(),
        text,
        "profile write is idempotent"
    );
    assert_eq!(rerun.apparmor_profiles, vec!["idtools".to_string()]);
}

#[test]
fn rendered_apparmor_profile_parses_with_apparmor_parser() {
    use libextos::manifest::SecurityBlock;
    use libextos::security::apparmor::AppArmorProfile;
    use std::collections::HashMap;

    let Some(parser) = probe_tool("apparmor_parser") else {
        println!("SKIP apparmor_parser not available; profile syntax not parser-proven");
        return;
    };

    let security = SecurityBlock {
        capabilities: HashMap::from([(
            "usr/bin/idtool".to_string(),
            vec!["CAP_NET_RAW".to_string(), "CAP_NET_ADMIN".to_string()],
        )]),
        mac_profile: None,
    };
    let profile =
        AppArmorProfile::from_security("extos-idtools", &["idtool".to_string()], &security)
            .expect("synthesize profile");
    let text = profile.render();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("extos-idtools");
    fs::write(&path, &text).unwrap();

    // -Q: never load into the kernel; -T: bypass the profile cache.
    let out = Command::new(&parser).args(["-Q", "-T"]).arg(&path).output();
    match out {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            println!("SKIP apparmor_parser vanished mid-run");
        }
        Err(err) => panic!("spawn apparmor_parser: {err}"),
        Ok(out) => {
            assert!(
                out.status.success(),
                "apparmor_parser rejected the synthesized profile:\n{}\nstdout: {}\nstderr: {}",
                text,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}
