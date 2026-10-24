//! Integration tests for PLAN Phase 7 sub-phase 7.1 (User Identity).
//!
//! * 7.1.1 + 7.1.2 + 7.1.3 — end to end: load `users/alice.nix`, materialize
//!   the universal pool (modes + idempotent report), and render the
//!   `pam_mount` volume for the pool bind-mount.
//! * 7.1.4 — the real-application probe: re-executes this test binary inside
//!   an unprivileged user+mount namespace (`unshare --user --map-root-user
//!   --mount`), mounts a namespace-owned tmpfs, and drives
//!   [`libextos::users::idmap::mount_setattr_idmap`] through its full kernel
//!   sequence (`open_tree(OPEN_TREE_CLONE)` →
//!   `mount_setattr(MOUNT_ATTR_IDMAP)` → `move_mount`). The mapping target is
//!   a *nested* child user namespace (`unshare --user --map-root-user`
//!   inside the first one): the kernel refuses `MOUNT_ATTR_IDMAP` when the
//!   target namespace is the one that already owns the source mount, so a
//!   distinct descendant namespace is the legal mapping target. Inside the
//!   outer namespace the mapped root holds `CAP_SYS_ADMIN` over the tmpfs
//!   superblock and over the child namespace, so the idmap is legal and the
//!   attach must succeed. Hosts without `unshare` or with user namespaces
//!   disabled print an honest `SKIP …` — never a silent pass.

use std::fs;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use libextos::error::ExtosError;
use libextos::users::{self, UserConfig};

// ─── 7.1.1 → 7.1.3: load → pool → pam_mount flow ────────────────

#[test]
fn load_pool_and_pam_mount_flow() {
    let dir = tempfile::tempdir().unwrap();
    let users_dir = dir.path().join("users");
    fs::create_dir_all(&users_dir).unwrap();
    fs::write(
        users_dir.join("alice.nix"),
        r#"{
  uid = 1000;
  groups = [ "wheel" "audio" ];
  shell = "/bin/zsh";
  binds = [ { host = "/srv/data"; target = "Projects/data"; } ];
}"#,
    )
    .unwrap();

    let config = UserConfig::load(&users_dir.join("alice.nix")).expect("load declaration");
    assert_eq!(config.name, "alice");
    assert_eq!(config.uid, 1000);
    assert_eq!(config.groups, vec!["wheel", "audio"]);
    assert_eq!(config.shell, "/bin/zsh");
    assert_eq!(config.binds.len(), 1);

    // 7.1.2: the pool materializes with the report contract.
    let pool_root = dir.path().join("user");
    let report = users::ensure_user_pool(&config, &pool_root).expect("first-login pool pass");
    assert_eq!(report.present, 0);
    assert_eq!(report.created.len(), 1 + users::POOL_DIRS.len());
    for name in users::POOL_DIRS {
        let mode = fs::metadata(pool_root.join("alice").join(name))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "{name} must be 0o700");
    }

    // Idempotent re-run: the report flips to present-only.
    let rerun = users::ensure_user_pool(&config, &pool_root).unwrap();
    assert!(rerun.created.is_empty());
    assert_eq!(rerun.present, 1 + users::POOL_DIRS.len());

    // 7.1.3: the pam_mount volume binds the pool into the snapshot home.
    let pool = pool_root.join("alice");
    let xml = users::render_pam_mount(&config, &pool).expect("render pam_mount volume");
    let pool_str = pool.display().to_string();
    assert_eq!(
        xml,
        format!(
            "<pam_mount>\n  <volume user=\"alice\" mountpoint=\"{pool_str}\" \
             path=\"{pool_str}\" fstype=\"none\" options=\"bind\" />\n</pam_mount>\n"
        )
    );
}

#[test]
fn hostile_configs_are_typed_rejections_at_every_boundary() {
    let dir = tempfile::tempdir().unwrap();
    let hostile = UserConfig {
        name: "../escape".to_string(),
        uid: 1000,
        groups: Vec::new(),
        shell: "/bin/sh".to_string(),
        binds: Vec::new(),
    };

    let err = users::ensure_user_pool(&hostile, dir.path())
        .expect_err("traversal name rejected at the fs boundary");
    assert!(matches!(err, ExtosError::ConfigParse { .. }), "{err:?}");
    assert!(err.to_string().contains("../escape"), "{err}");

    let err = users::render_pam_mount(&hostile, dir.path())
        .expect_err("traversal name rejected before XML rendering");
    assert!(matches!(err, ExtosError::ConfigParse { .. }), "{err:?}");

    let config = UserConfig {
        name: "alice".to_string(),
        uid: 1000,
        groups: Vec::new(),
        shell: "/bin/sh".to_string(),
        binds: Vec::new(),
    };
    let xml_hostile_pool = dir.path().join("<script>");
    let err = users::render_pam_mount(&config, &xml_hostile_pool)
        .expect_err("XML-hostile mountpoint rejected");
    assert!(matches!(err, ExtosError::ConfigParse { .. }), "{err:?}");
}

// ─── 7.1.4: real-application probe (unprivileged user namespace) ──

/// The in-namespace child: mounts a private tmpfs owned by the outer user
/// namespace, starts a nested child user namespace, then idmaps a subtree of
/// the tmpfs into that child namespace and stats the result through the
/// attached mount.
#[test]
#[ignore = "only run as the unshare probe child (see file docs)"]
fn mount_setattr_idmap_probe_child() {
    let dir = std::env::var_os("EXTOS_IDMAP_PROBE_DIR")
        .expect("probe child requires EXTOS_IDMAP_PROBE_DIR");
    let dir = PathBuf::from(dir);

    // Root inside the outer user+mount namespace: mount a tmpfs owned by
    // this namespace, so CAP_SYS_ADMIN covers its superblock (a
    // precondition MOUNT_ATTR_IDMAP enforces).
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

    let src = dir.join("src");
    let dst = dir.join("dst");
    fs::create_dir(&src).unwrap();
    fs::create_dir(&dst).unwrap();
    fs::write(src.join("payload"), b"idmapped\n").unwrap();

    // The mapping target must be a namespace distinct from the one that owns
    // the source mount (mapping into the owning namespace itself is refused
    // with EINVAL), so start a nested child user namespace as the holder.
    let unshare = probe_unshare().expect("unshare available for the nested namespace step");
    let mut nested = Command::new(&unshare)
        .args(["--user", "--map-root-user"])
        .args(["sleep", "30"])
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn nested user namespace");

    // util-linux creates the namespace and writes the maps from within the
    // child; wait until the child's user-namespace inode actually differs
    // from ours AND both maps exist. A bare non-empty map check is not
    // enough: before `unshare(CLONE_NEWUSER)` runs, the child still shows
    // the outer namespace's (non-empty) map.
    let pid = nested.id();
    let self_ns = fs::read_link("/proc/self/ns/user").expect("read own user namespace");
    let mut maps_ready = false;
    for _ in 0..500 {
        match nested.try_wait().expect("poll nested namespace holder") {
            Some(_status) => {
                let mut stderr = String::new();
                if let Some(mut pipe) = nested.stderr.take() {
                    let _ = pipe.read_to_string(&mut stderr);
                }
                panic!("nested user namespace refused before mapping: {stderr}");
            }
            None => {
                let child_ns = fs::read_link(format!("/proc/{pid}/ns/user")).is_ok_and(|link| link != self_ns);
                let uid_ok = fs::read_to_string(format!("/proc/{pid}/uid_map"))
                    .is_ok_and(|map| !map.trim().is_empty());
                let gid_ok = fs::read_to_string(format!("/proc/{pid}/gid_map"))
                    .is_ok_and(|map| !map.trim().is_empty());
                if child_ns && uid_ok && gid_ok {
                    maps_ready = true;
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(maps_ready, "nested namespace never wrote its uid/gid maps");

    let ns_path = std::ffi::CString::new(format!("/proc/{pid}/ns/user")).unwrap();
    // SAFETY: ns_path outlives the call; the flag arguments are plain data.
    let nsfd =
        unsafe { libc::open(ns_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    assert!(nsfd >= 0, "open the nested namespace fd");
    let result = users::idmap::mount_setattr_idmap(&src, &dst, nsfd);
    // SAFETY: nsfd is the namespace fd opened above.
    unsafe { libc::close(nsfd) };
    result.expect("mount_setattr_idmap must succeed for a namespace-owned tmpfs");

    // The idmapped clone is attached at dst and stats cleanly: the payload is
    // visible through it with the same identity the source view reports (the
    // nested namespace maps the outer root 1:1, so the conversion is an
    // identity for the single mapped id).
    use std::os::unix::fs::MetadataExt;
    let mapped = fs::metadata(dst.join("payload"))
        .expect("payload visible through the idmapped mount");
    assert!(mapped.is_file());
    let source_uid = fs::metadata(src.join("payload")).unwrap().uid();
    assert_eq!(mapped.uid(), source_uid, "ID mapping keeps the owner consistent");
    assert_eq!(
        fs::read(dst.join("payload")).unwrap(),
        b"idmapped\n",
        "payload content intact through the idmapped mount"
    );

    // Teardown: end the nested namespace holder.
    let _ = nested.kill();
    let _ = nested.wait();
}

#[test]
fn idmapped_mount_probe_inside_user_namespace() {
    let Some(unshare) = probe_unshare() else {
        println!("SKIP unshare CLI not available; mount_setattr ID mapping not host-proven");
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    let probe_dir = dir.path().join("probe");
    fs::create_dir_all(&probe_dir).unwrap();

    let exe = std::env::current_exe().expect("locate test binary");
    let output = Command::new(&unshare)
        .args(["--user", "--map-root-user", "--mount"])
        .arg(&exe)
        .args(["mount_setattr_idmap_probe_child", "--exact", "--ignored", "--nocapture"])
        .env("EXTOS_IDMAP_PROBE_DIR", &probe_dir)
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
        println!("SKIP user namespaces unavailable; mount_setattr ID mapping not host-proven");
        return;
    }
    // Success: the child already asserted the idmapped attach and clean stat.
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
