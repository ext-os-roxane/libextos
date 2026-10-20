//! Generation tracking (M8.4).
//!
//! Each generation is a snapshot + lockfile + metadata bundle:
//!
//! ```text
//! <system root>/
//!   gen-42/                    snapshot with the woven tree
//!   current → gen-42           atomic symlink, the active generation
//!   generations.json           history, pins and GC eligibility
//! <entries dir>/gen-42.conf    Boot Loader Specification entry
//! ```
//!
//! [`GenerationTracker`] owns the history/metadata side, [`advance`] performs a
//! full transactional generation bump (snapshot → BLS entry → record →
//! `current` switch) and [`gc`] reaps old generations while respecting pins and
//! the active generation. All paths come from the caller; nothing here assumes
//! a rootfs layout.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::engine::{SnapshotEngine, SnapshotInfo};
use crate::error::ExtosError;

/// A single generation record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Generation {
    /// Generation number
    pub number: u64,
    /// Timestamp (seconds since epoch)
    pub timestamp: u64,
    /// Lockfile hash (ties this gen to a specific package set)
    pub lockfile_hash: Option<String>,
    /// Human-readable description
    pub description: String,
    /// Whether this generation is pinned (immune to GC)
    pub pinned: bool,
}

/// Tracks generations in a JSON metadata file.
pub struct GenerationTracker {
    /// Path to the generations metadata file
    meta_path: PathBuf,
    /// All known generations
    generations: Vec<Generation>,
}

impl GenerationTracker {
    /// Open or create a generation tracker.
    pub fn open(system_root: &Path) -> Result<Self, ExtosError> {
        let meta_path = system_root.join("generations.json");
        let generations = if meta_path.exists() {
            let content = fs::read_to_string(&meta_path)?;
            serde_json::from_str(&content).map_err(|e| {
                ExtosError::Serialization(format!("generations.json: {e}"))
            })?
        } else {
            Vec::new()
        };

        Ok(Self { meta_path, generations })
    }

    /// Record a new generation.
    pub fn record(
        &mut self,
        number: u64,
        lockfile_hash: Option<String>,
        description: &str,
    ) -> Result<&Generation, ExtosError> {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let entry = Generation {
            number,
            timestamp: ts,
            lockfile_hash,
            description: description.to_string(),
            pinned: false,
        };

        self.generations.push(entry);
        self.save()?;
        Ok(self.generations.last().unwrap())
    }

    /// Get the latest generation number.
    pub fn latest(&self) -> Option<u64> {
        self.generations.iter().map(|g| g.number).max()
    }

    /// Get the next generation number.
    pub fn next_number(&self) -> u64 {
        self.latest().map(|n| n + 1).unwrap_or(1)
    }

    /// Get a generation by number.
    pub fn get(&self, number: u64) -> Option<&Generation> {
        self.generations.iter().find(|g| g.number == number)
    }

    /// List all generations.
    pub fn list(&self) -> &[Generation] {
        &self.generations
    }

    /// Pin a generation (protect from GC).
    pub fn pin(&mut self, number: u64) -> Result<(), ExtosError> {
        if let Some(found) = self.generations.iter_mut().find(|g| g.number == number) {
            found.pinned = true;
            self.save()
        } else {
            Err(ExtosError::Snapshot(format!("generation {number} not found")))
        }
    }

    /// Unpin a generation.
    pub fn unpin(&mut self, number: u64) -> Result<(), ExtosError> {
        if let Some(found) = self.generations.iter_mut().find(|g| g.number == number) {
            found.pinned = false;
            self.save()
        } else {
            Err(ExtosError::Snapshot(format!("generation {number} not found")))
        }
    }

    /// Find generations eligible for GC.
    ///
    /// Keeps the latest `keep` generations + all pinned ones.
    pub fn gc_candidates(&self, keep: usize) -> Vec<u64> {
        let mut sorted: Vec<&Generation> = self.generations.iter().collect();
        sorted.sort_by(|a, b| b.number.cmp(&a.number));

        sorted
            .iter()
            .skip(keep)
            .filter(|g| !g.pinned)
            .map(|g| g.number)
            .collect()
    }

    /// Remove a generation record (after snapshot deletion).
    pub fn remove(&mut self, number: u64) -> Result<(), ExtosError> {
        self.generations.retain(|g| g.number != number);
        self.save()
    }

    fn save(&self) -> Result<(), ExtosError> {
        // Serialize as JSON
        let entries: Vec<serde_json::Value> = self.generations.iter().map(|g| {
            serde_json::json!({
                "number": g.number,
                "timestamp": g.timestamp,
                "lockfile_hash": g.lockfile_hash,
                "description": g.description,
                "pinned": g.pinned,
            })
        }).collect();

        let content = serde_json::to_string_pretty(&entries)
            .map_err(|e| ExtosError::Serialization(e.to_string()))?;

        if let Some(parent) = self.meta_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.meta_path, content)?;
        Ok(())
    }
}

/// One Boot Loader Specification entry (`<entries>/gen-<n>.conf`).
///
/// Follows the [BLS spec](https://uapi-group.org/specifications/specs/boot_loader_specification/):
/// one `key value` pair per line, `title` first, `initrd` repeatable. Paths are
/// emitted verbatim, so pass boot-partition-relative paths (`/vmlinuz-gen-7`)
/// or whatever the bootloader expects — nothing here resolves a rootfs layout.
#[derive(Debug, Clone)]
pub struct BlsEntry {
    /// `title` — human readable menu label.
    pub title: String,
    /// `version` — kernel version string.
    pub version: String,
    /// `machine-id` — optional, ties the entry to a machine.
    pub machine_id: Option<String>,
    /// `sort-key` — optional, controls menu ordering.
    pub sort_key: Option<String>,
    /// `linux` — kernel image path.
    pub linux: PathBuf,
    /// `initrd` — one or more initramfs images (may be empty).
    pub initrd: Vec<PathBuf>,
    /// `options` — kernel command line.
    pub options: Option<String>,
}

impl BlsEntry {
    /// File name of the entry for a generation: `gen-<n>.conf`.
    pub fn file_name(generation: u64) -> String {
        format!("gen-{generation}.conf")
    }

    /// Render the entry as BLS text.
    ///
    /// Control characters in values are folded to spaces so a stray newline in
    /// a description cannot inject extra fields.
    pub fn render(&self) -> String {
        fn one_line(value: &str) -> String {
            value
                .chars()
                .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
                .collect()
        }

        let mut out = String::new();
        out.push_str(&format!("title {}\n", one_line(&self.title)));
        out.push_str(&format!("version {}\n", one_line(&self.version)));
        if let Some(sort_key) = &self.sort_key {
            out.push_str(&format!("sort-key {}\n", one_line(sort_key)));
        }
        if let Some(machine_id) = &self.machine_id {
            out.push_str(&format!("machine-id {}\n", one_line(machine_id)));
        }
        out.push_str(&format!("linux {}\n", one_line(&self.linux.to_string_lossy())));
        for initrd in &self.initrd {
            out.push_str(&format!("initrd {}\n", one_line(&initrd.to_string_lossy())));
        }
        if let Some(options) = &self.options {
            out.push_str(&format!("options {}\n", one_line(options)));
        }
        out
    }

    /// Write the entry to `entries_dir/gen-<n>.conf` atomically.
    ///
    /// The file is written under a temporary name and `rename(2)`d into place,
    /// so a bootloader scanning the directory never sees a half-written entry.
    /// Returns the final path.
    pub fn write(&self, entries_dir: &Path, generation: u64) -> Result<PathBuf, ExtosError> {
        fs::create_dir_all(entries_dir)?;
        let final_path = entries_dir.join(Self::file_name(generation));
        let tmp_path = entries_dir.join(format!(
            ".{}.tmp-{}",
            Self::file_name(generation),
            std::process::id()
        ));

        fs::write(&tmp_path, self.render())?;
        if let Err(e) = fs::rename(&tmp_path, &final_path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(ExtosError::from(e));
        }
        Ok(final_path)
    }
}

/// Everything [`advance`] needs to create and announce a new generation.
#[derive(Debug, Clone)]
pub struct AdvanceOptions {
    /// Tree to snapshot. `None` creates an empty generation (for a first
    /// weave), `Some(path)` snapshots an existing tree.
    pub source: Option<PathBuf>,
    /// Request a read-only snapshot (Btrfs backend only).
    pub readonly: bool,
    /// Lockfile hash recorded with the generation.
    pub lockfile_hash: Option<String>,
    /// Human readable description recorded with the generation.
    pub description: String,
    /// BLS `title`; defaults to `ExtOS Generation <n>`.
    pub title: Option<String>,
    /// BLS `version`; defaults to the generation number.
    pub version: Option<String>,
    /// BLS `linux` — kernel image path.
    pub linux: PathBuf,
    /// BLS `initrd` entries.
    pub initrd: Vec<PathBuf>,
    /// BLS `options` — kernel command line.
    pub options: Option<String>,
    /// BLS `sort-key`.
    pub sort_key: Option<String>,
}

impl AdvanceOptions {
    /// Options for a generation booting `linux`, with every other field at its
    /// default. Fields are public, so callers tweak what they need.
    pub fn new(linux: impl Into<PathBuf>) -> Self {
        Self {
            source: None,
            readonly: false,
            lockfile_hash: None,
            description: String::new(),
            title: None,
            version: None,
            linux: linux.into(),
            initrd: Vec::new(),
            options: None,
            sort_key: None,
        }
    }
}

/// Result of [`advance`]: the new generation, its snapshot and its BLS entry.
#[derive(Debug, Clone)]
pub struct AdvancedGeneration {
    /// The recorded generation metadata.
    pub generation: Generation,
    /// The snapshot that holds the generation's tree.
    pub snapshot: SnapshotInfo,
    /// Path of the written BLS entry.
    pub entry: PathBuf,
    /// Path of the `current` symlink that now points at this generation.
    pub current: PathBuf,
}

/// Create generation `next_number()`, write its BLS entry and switch to it.
///
/// Steps, all path-parameterised:
/// 1. pick the number (`max(tracker.next_number(), newest on disk + 1)`);
/// 2. snapshot `opts.source` (or create an empty generation);
/// 3. atomically write `<entries_dir>/gen-<n>.conf`;
/// 4. record the generation in the tracker (persisted as JSON);
/// 5. atomically repoint `<engine root>/current` at the new generation.
///
/// If step 3 fails the freshly created snapshot is removed again, so a failed
/// advance leaves no orphan generation behind. Failures after that point
/// (tracker write, symlink switch) leave the snapshot and record in place:
/// the tree is complete and the mismatch is recoverable, whereas deleting it
/// would discard a perfectly good generation.
pub fn advance(
    engine: &SnapshotEngine,
    tracker: &mut GenerationTracker,
    entries_dir: &Path,
    opts: &AdvanceOptions,
) -> Result<AdvancedGeneration, ExtosError> {
    if opts.linux.as_os_str().is_empty() {
        return Err(ExtosError::Snapshot(
            "generation advance needs a linux image path for the BLS entry".into(),
        ));
    }

    let from_tracker = tracker.next_number();
    let from_disk = engine
        .list()?
        .iter()
        .map(|g| g.generation)
        .max()
        .map(|n| n + 1)
        .unwrap_or(1);
    let number = from_tracker.max(from_disk);

    let snapshot = match &opts.source {
        Some(source) => engine.create_snapshot_with(source, number, opts.readonly)?,
        None => engine.create_empty(number)?,
    };

    let entry = BlsEntry {
        title: opts
            .title
            .clone()
            .unwrap_or_else(|| format!("ExtOS Generation {number}")),
        version: opts.version.clone().unwrap_or_else(|| number.to_string()),
        machine_id: None,
        sort_key: opts.sort_key.clone(),
        linux: opts.linux.clone(),
        initrd: opts.initrd.clone(),
        options: opts.options.clone(),
    };

    let entry_path = match entry.write(entries_dir, number) {
        Ok(path) => path,
        Err(e) => {
            rollback(engine, number);
            return Err(e);
        }
    };

    let generation = tracker
        .record(number, opts.lockfile_hash.clone(), &opts.description)?
        .clone();

    // If the symlink switch fails, the generation stays on disk and recorded:
    // the tree is complete, only activation failed, and `current` still points
    // at the previous generation. Deleting it would throw away a good snapshot.
    engine.switch_to(number)?;

    Ok(AdvancedGeneration {
        generation,
        snapshot,
        entry: entry_path,
        current: engine.root().join("current"),
    })
}

fn rollback(engine: &SnapshotEngine, number: u64) {
    if let Err(e) = engine.delete(number) {
        tracing::warn!(
            target: "extos::snapshot",
            "could not roll back generation {number} after a failed advance: {e}"
        );
    }
}

/// Delete all but the newest `keep` generations (PLAN 2.6.5).
///
/// Uses [`GenerationTracker::gc_candidates`], so pinned generations are never
/// collected, and additionally never deletes the generation `current` points
/// at. Both the snapshot and its generation record are removed; BLS entries are
/// left to the caller — see [`gc_with_entries`] to remove them too.
///
/// Returns the deleted generation numbers in ascending order.
pub fn gc(
    engine: &SnapshotEngine,
    tracker: &mut GenerationTracker,
    keep: usize,
) -> Result<Vec<u64>, ExtosError> {
    gc_with_entries(engine, tracker, keep, None)
}

/// Like [`gc`], but also removes `<entries_dir>/gen-<n>.conf` for every
/// collected generation.
pub fn gc_with_entries(
    engine: &SnapshotEngine,
    tracker: &mut GenerationTracker,
    keep: usize,
    entries_dir: Option<&Path>,
) -> Result<Vec<u64>, ExtosError> {
    let current = engine.current_generation()?;
    let mut removed = Vec::new();

    for number in tracker.gc_candidates(keep) {
        if current == Some(number) {
            continue;
        }
        if engine.gen_path(number).symlink_metadata().is_ok() {
            engine.delete(number)?;
        }
        tracker.remove(number)?;
        if let Some(dir) = entries_dir {
            remove_entry(dir, number)?;
        }
        removed.push(number);
    }

    removed.sort_unstable();
    Ok(removed)
}

/// Path of the BLS entry for `number`.
pub fn entry_path(entries_dir: &Path, number: u64) -> std::path::PathBuf {
    entries_dir.join(BlsEntry::file_name(number))
}

/// Remove the BLS entry for `number`. Missing entries are not an error.
pub fn remove_entry(entries_dir: &Path, number: u64) -> Result<(), ExtosError> {
    let path = entry_path(entries_dir, number);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(ExtosError::from(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_list() {
        let tmp = tempfile::tempdir().unwrap();
        let mut tracker = GenerationTracker::open(tmp.path()).unwrap();

        tracker.record(1, Some("abc123".into()), "initial install").unwrap();
        tracker.record(2, Some("def456".into()), "added htop").unwrap();

        assert_eq!(tracker.list().len(), 2);
        assert_eq!(tracker.latest(), Some(2));
        assert_eq!(tracker.next_number(), 3);
    }

    #[test]
    fn test_pin_and_gc() {
        let tmp = tempfile::tempdir().unwrap();
        let mut tracker = GenerationTracker::open(tmp.path()).unwrap();

        for i in 1..=5 {
            tracker.record(i, None, &format!("gen {i}")).unwrap();
        }
        tracker.pin(2).unwrap();

        // Keep latest 2 (4, 5), pin protects 2 → candidates are 1, 3
        let candidates = tracker.gc_candidates(2);
        assert!(candidates.contains(&1));
        assert!(candidates.contains(&3));
        assert!(!candidates.contains(&2)); // pinned
        assert!(!candidates.contains(&4)); // kept
        assert!(!candidates.contains(&5)); // kept
    }

    #[test]
    fn test_persistence() {
        let tmp = tempfile::tempdir().unwrap();

        {
            let mut tracker = GenerationTracker::open(tmp.path()).unwrap();
            tracker.record(1, None, "test").unwrap();
        }

        // Re-open
        let tracker = GenerationTracker::open(tmp.path()).unwrap();
        assert_eq!(tracker.list().len(), 1);
        assert_eq!(tracker.latest(), Some(1));
    }

    #[test]
    fn test_remove() {
        let tmp = tempfile::tempdir().unwrap();
        let mut tracker = GenerationTracker::open(tmp.path()).unwrap();

        tracker.record(1, None, "gen 1").unwrap();
        tracker.record(2, None, "gen 2").unwrap();
        tracker.remove(1).unwrap();

        assert_eq!(tracker.list().len(), 1);
        assert!(tracker.get(1).is_none());
        assert!(tracker.get(2).is_some());
    }

    // ---- BLS entries -----------------------------------------------------

    #[test]
    fn test_bls_entry_rendering() {
        let entry = BlsEntry {
            title: "ExtOS Generation 7".into(),
            version: "7".into(),
            machine_id: None,
            sort_key: Some("extos".into()),
            linux: PathBuf::from("/vmlinuz-gen-7"),
            initrd: vec![
                PathBuf::from("/initramfs-gen-7.img"),
                PathBuf::from("/ucode.img"),
            ],
            options: Some("root=PARTUUID=abc ro quiet".into()),
        };

        let rendered = entry.render();
        assert_eq!(
            rendered,
            "title ExtOS Generation 7\n\
             version 7\n\
             sort-key extos\n\
             linux /vmlinuz-gen-7\n\
             initrd /initramfs-gen-7.img\n\
             initrd /ucode.img\n\
             options root=PARTUUID=abc ro quiet\n"
        );
        assert!(!rendered.contains("machine-id"));

        // Newlines in values must not be able to inject extra BLS fields.
        let sneaky = BlsEntry {
            title: "evil\nlinux /pwned".into(),
            ..entry.clone()
        };
        let rendered = sneaky.render();
        assert_eq!(rendered.matches("\nlinux ").count(), 1, "{rendered}");
        assert!(rendered.starts_with("title evil linux /pwned\n"));
    }

    #[test]
    fn test_bls_entry_write_is_atomic_and_overwrites() {
        let tmp = tempfile::tempdir().unwrap();
        let entries = tmp.path().join("boot/loader/entries");

        let entry = BlsEntry {
            title: "first".into(),
            version: "1".into(),
            machine_id: None,
            sort_key: None,
            linux: PathBuf::from("/vmlinuz"),
            initrd: Vec::new(),
            options: None,
        };
        let path = entry.write(&entries, 1).unwrap();
        assert_eq!(path, entries.join("gen-1.conf"));
        assert!(fs::read_to_string(&path).unwrap().contains("title first"));

        let entry = BlsEntry {
            title: "second".into(),
            ..entry
        };
        entry.write(&entries, 1).unwrap();
        assert!(fs::read_to_string(&path).unwrap().contains("title second"));
        // The temporary file is gone.
        let leftovers: Vec<_> = fs::read_dir(&entries)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with('.'))
            .collect();
        assert!(leftovers.is_empty());
        assert_eq!(BlsEntry::file_name(42), "gen-42.conf");
    }

    // ---- generation::advance ---------------------------------------------

    #[test]
    fn test_advance_from_source() {
        let tmp = tempfile::tempdir().unwrap();
        let engine = SnapshotEngine::open(tmp.path().join("system")).unwrap();
        let mut tracker = GenerationTracker::open(engine.root()).unwrap();
        let entries = tmp.path().join("boot/loader/entries");

        let source = tmp.path().join("woven");
        fs::create_dir_all(source.join("usr/bin")).unwrap();
        fs::write(source.join("usr/bin/sh"), b"#!/bin/sh\n").unwrap();

        let mut opts = AdvanceOptions::new("/vmlinuz-gen-1");
        opts.source = Some(source.clone());
        opts.initrd = vec![PathBuf::from("/initramfs-gen-1.img")];
        opts.options = Some("root=PARTUUID=test ro".into());
        opts.description = "initial install".into();
        opts.lockfile_hash = Some("abc123".into());

        let advanced = advance(&engine, &mut tracker, &entries, &opts).unwrap();
        assert_eq!(advanced.generation.number, 1);
        assert_eq!(advanced.generation.description, "initial install");
        assert_eq!(advanced.generation.lockfile_hash.as_deref(), Some("abc123"));
        assert_eq!(advanced.snapshot.generation, 1);
        assert_eq!(
            fs::read(advanced.snapshot.path.join("usr/bin/sh")).unwrap(),
            b"#!/bin/sh\n"
        );

        // BLS entry is present with the expected fields.
        let conf = fs::read_to_string(&advanced.entry).unwrap();
        assert!(conf.contains("title ExtOS Generation 1\n"), "{conf}");
        assert!(conf.contains("version 1\n"), "{conf}");
        assert!(conf.contains("linux /vmlinuz-gen-1\n"), "{conf}");
        assert!(conf.contains("initrd /initramfs-gen-1.img\n"), "{conf}");
        assert!(conf.contains("options root=PARTUUID=test ro\n"), "{conf}");

        // `current` points at the new generation, the tracker remembers it.
        assert_eq!(engine.current_generation().unwrap(), Some(1));
        assert_eq!(tracker.latest(), Some(1));
        assert!(advanced.current.symlink_metadata().is_ok());

        // The persisted tracker survives a reopen.
        let reopened = GenerationTracker::open(engine.root()).unwrap();
        assert_eq!(reopened.latest(), Some(1));
    }

    #[test]
    fn test_advance_empty_generation_and_numbering() {
        let tmp = tempfile::tempdir().unwrap();
        let engine = SnapshotEngine::open(tmp.path().join("system")).unwrap();
        let mut tracker = GenerationTracker::open(engine.root()).unwrap();
        let entries = tmp.path().join("entries");

        let advanced = advance(&engine, &mut tracker, &entries, &AdvanceOptions::new("/vmlinuz")).unwrap();
        assert_eq!(advanced.generation.number, 1);
        assert!(advanced.snapshot.path.is_dir());

        let advanced = advance(&engine, &mut tracker, &entries, &AdvanceOptions::new("/vmlinuz")).unwrap();
        assert_eq!(advanced.generation.number, 2);
        assert_eq!(engine.current_generation().unwrap(), Some(2));
        assert!(entries.join("gen-1.conf").exists());
        assert!(entries.join("gen-2.conf").exists());

        // An untracked generation already on disk bumps the number too.
        let engine2 = SnapshotEngine::open(tmp.path().join("system")).unwrap();
        engine2.create_empty(7).unwrap();
        let advanced = advance(&engine, &mut tracker, &entries, &AdvanceOptions::new("/vmlinuz")).unwrap();
        assert_eq!(advanced.generation.number, 8);
    }

    #[test]
    fn test_advance_rejects_missing_linux_and_cleans_up_on_entry_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let engine = SnapshotEngine::open(tmp.path().join("system")).unwrap();
        let mut tracker = GenerationTracker::open(engine.root()).unwrap();
        let entries = tmp.path().join("entries");

        let err = advance(&engine, &mut tracker, &entries, &AdvanceOptions::new("")).unwrap_err();
        assert!(err.to_string().contains("linux image"), "{err}");
        assert!(engine.list().unwrap().is_empty());

        // entries_dir is a file ⇒ entry write fails ⇒ snapshot is rolled back.
        fs::write(tmp.path().join("blocked"), b"x").unwrap();
        let opts = AdvanceOptions::new("/vmlinuz");
        let err = advance(&engine, &mut tracker, &tmp.path().join("blocked"), &opts).unwrap_err();
        assert!(matches!(err, ExtosError::Io(_)), "unexpected: {err}");
        assert!(engine.list().unwrap().is_empty(), "snapshot must be rolled back");
        assert_eq!(tracker.latest(), None);
    }

    #[test]
    fn test_advance_custom_title_and_version() {
        let tmp = tempfile::tempdir().unwrap();
        let engine = SnapshotEngine::open(tmp.path().join("system")).unwrap();
        let mut tracker = GenerationTracker::open(engine.root()).unwrap();
        let entries = tmp.path().join("entries");

        let mut opts = AdvanceOptions::new("/vmlinuz-gen-1");
        opts.title = Some("ExtOS 1.0 (linux)".into());
        opts.version = Some("1.0.0".into());
        opts.sort_key = Some("extos".into());

        let advanced = advance(&engine, &mut tracker, &entries, &opts).unwrap();
        let conf = fs::read_to_string(&advanced.entry).unwrap();
        assert!(conf.contains("title ExtOS 1.0 (linux)\n"), "{conf}");
        assert!(conf.contains("version 1.0.0\n"), "{conf}");
        assert!(conf.contains("sort-key extos\n"), "{conf}");
    }

    // ---- generation::gc --------------------------------------------------

    #[test]
    fn test_gc_keeps_newest_and_removes_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let engine = SnapshotEngine::open(tmp.path().join("system")).unwrap();
        let mut tracker = GenerationTracker::open(engine.root()).unwrap();
        let entries = tmp.path().join("entries");

        for _ in 0..4 {
            advance(&engine, &mut tracker, &entries, &AdvanceOptions::new("/vmlinuz")).unwrap();
        }
        assert_eq!(tracker.list().len(), 4);

        let removed = gc_with_entries(&engine, &mut tracker, 2, Some(&entries)).unwrap();
        assert_eq!(removed, vec![1, 2]);
        assert_eq!(tracker.latest(), Some(4));
        assert_eq!(tracker.list().len(), 2);
        assert!(!engine.gen_path(1).exists());
        assert!(!engine.gen_path(2).exists());
        assert!(engine.gen_path(3).exists());
        assert!(engine.gen_path(4).exists());
        assert!(!entries.join("gen-1.conf").exists());
        assert!(entries.join("gen-3.conf").exists());

        // Idempotent: nothing left to collect.
        assert!(gc(&engine, &mut tracker, 2).unwrap().is_empty());
        assert_eq!(engine.current_generation().unwrap(), Some(4));
    }

    #[test]
    fn test_gc_respects_pins_and_current() {
        let tmp = tempfile::tempdir().unwrap();
        let engine = SnapshotEngine::open(tmp.path().join("system")).unwrap();
        let mut tracker = GenerationTracker::open(engine.root()).unwrap();

        for n in 1..=4 {
            engine.create_empty(n).unwrap();
            tracker.record(n, None, &format!("gen {n}")).unwrap();
        }
        tracker.pin(2).unwrap();
        // `current` points at an old, unpinned generation: it must survive.
        engine.switch_to(1).unwrap();

        let removed = gc(&engine, &mut tracker, 1).unwrap();
        assert_eq!(removed, vec![3]);
        let mut left: Vec<u64> = tracker.list().iter().map(|g| g.number).collect();
        left.sort_unstable();
        assert_eq!(left, vec![1, 2, 4]);
        assert!(engine.gen_path(1).exists());
        assert!(engine.gen_path(2).exists());
        assert!(!engine.gen_path(3).exists());
        assert_eq!(engine.current_generation().unwrap(), Some(1));
    }

    #[test]
    fn test_gc_handles_record_without_snapshot_and_remove_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let engine = SnapshotEngine::open(tmp.path().join("system")).unwrap();
        let mut tracker = GenerationTracker::open(engine.root()).unwrap();
        let entries = tmp.path().join("entries");

        // A record whose snapshot is already gone must not abort GC.
        tracker.record(1, None, "orphan").unwrap();
        tracker.record(2, None, "orphan").unwrap();
        engine.create_empty(3).unwrap();
        tracker.record(3, None, "live").unwrap();
        fs::create_dir_all(&entries).unwrap();
        fs::write(entries.join("gen-1.conf"), b"title old\n").unwrap();

        let removed = gc_with_entries(&engine, &mut tracker, 1, Some(&entries)).unwrap();
        assert_eq!(removed, vec![1, 2]);
        assert!(tracker.get(1).is_none());
        assert!(!entries.join("gen-1.conf").exists());

        // Removing a missing entry is a no-op.
        remove_entry(&entries, 99).unwrap();
        assert_eq!(entry_path(&entries, 5), entries.join("gen-5.conf"));
    }
}
