//! Collision resolution protocol (M6.5).
//!
//! When two packages claim the same path, the collision protocol decides:
//! 1. **Priority**: Higher-priority origin wins (configurable)
//! 2. **Tier 3 wrapper**: Generate a shim binary that selects at runtime
//! 3. **Tier 4 escalation**: Isolate into separate containers
//!
//! This module handles cases 1 and 2 (Tier 4 is deferred to M10).

use std::collections::HashMap;
use std::path::PathBuf;

use crate::weaver::vfs::Collision;

/// How a collision was resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollisionResolution {
    /// Higher-priority origin wins; loser is dropped
    PriorityWin {
        winner: String,
        loser: String,
    },
    /// Both kept via Tier 3 wrapper shim
    Tier3Wrapper {
        wrapper_path: PathBuf,
        alternatives: Vec<String>,
    },
    /// Deferred to Tier 4 container isolation
    Tier4Deferred {
        path: PathBuf,
        claimants: Vec<String>,
    },
    /// Identical content (same hash) — no real conflict
    IdenticalContent,
}

/// Resolved collision record.
#[derive(Debug, Clone)]
pub struct ResolvedCollision {
    pub path: PathBuf,
    pub resolution: CollisionResolution,
}

/// Origin priority map: lower number = higher priority.
///
/// Default priorities:
/// - `pkt` (native ExtOS): 0
/// - `archlinux`: 10
/// - `debian`: 20
/// - `alpine`: 30
/// - everything else: 50
#[derive(Debug, Clone)]
pub struct OriginPriority {
    priorities: HashMap<String, u32>,
    default_priority: u32,
}

impl OriginPriority {
    pub fn new() -> Self {
        let mut priorities = HashMap::new();
        priorities.insert("pkt".into(), 0);
        priorities.insert("scratch".into(), 0);
        priorities.insert("archlinux".into(), 10);
        priorities.insert("arch".into(), 10);
        priorities.insert("debian".into(), 20);
        priorities.insert("ubuntu".into(), 20);
        priorities.insert("alpine".into(), 30);
        Self {
            priorities,
            default_priority: 50,
        }
    }

    /// Set priority for an origin (lower = higher priority).
    pub fn set(&mut self, origin: &str, priority: u32) {
        self.priorities.insert(origin.to_string(), priority);
    }

    /// Get priority for an origin.
    pub fn get(&self, origin: &str) -> u32 {
        // Extract origin from "origin/name" format
        let origin_part = origin.split('/').next().unwrap_or(origin);
        *self.priorities.get(origin_part).unwrap_or(&self.default_priority)
    }

    /// Compare two providers: returns the winner (lower priority number).
    pub fn winner<'a>(&self, a: &'a str, b: &'a str) -> &'a str {
        if self.get(a) <= self.get(b) { a } else { b }
    }
}

impl Default for OriginPriority {
    fn default() -> Self {
        Self::new()
    }
}

/// Collision resolver using the priority protocol.
pub struct CollisionResolver {
    priority: OriginPriority,
    /// Whether to generate Tier 3 wrappers for same-priority collisions
    enable_tier3: bool,
}

impl CollisionResolver {
    pub fn new(priority: OriginPriority) -> Self {
        Self {
            priority,
            enable_tier3: true,
        }
    }

    /// Disable Tier 3 wrapper generation (priority-only mode).
    pub fn priority_only(mut self) -> Self {
        self.enable_tier3 = false;
        self
    }

    /// Resolve all collisions in a VirtualFhs.
    pub fn resolve_all(&self, collisions: &[Collision]) -> Vec<ResolvedCollision> {
        collisions.iter().map(|c| self.resolve_one(c)).collect()
    }

    /// Resolve a single collision.
    fn resolve_one(&self, collision: &Collision) -> ResolvedCollision {
        let pri_a = self.priority.get(&collision.claimant_a);
        let pri_b = self.priority.get(&collision.claimant_b);

        let resolution = if pri_a != pri_b {
            // Different priorities: higher priority wins
            let (winner, loser) = if pri_a < pri_b {
                (collision.claimant_a.clone(), collision.claimant_b.clone())
            } else {
                (collision.claimant_b.clone(), collision.claimant_a.clone())
            };
            CollisionResolution::PriorityWin { winner, loser }
        } else if self.enable_tier3 {
            // Same priority: Tier 3 wrapper
            let wrapper_path = collision.path.with_extension("extos-wrapper");
            CollisionResolution::Tier3Wrapper {
                wrapper_path,
                alternatives: vec![
                    collision.claimant_a.clone(),
                    collision.claimant_b.clone(),
                ],
            }
        } else {
            // Tier 3 disabled: defer to container isolation
            CollisionResolution::Tier4Deferred {
                path: collision.path.clone(),
                claimants: vec![
                    collision.claimant_a.clone(),
                    collision.claimant_b.clone(),
                ],
            }
        };

        ResolvedCollision {
            path: collision.path.clone(),
            resolution,
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn collision(path: &str, a: &str, b: &str) -> Collision {
        Collision {
            path: PathBuf::from(path),
            claimant_a: a.into(),
            claimant_b: b.into(),
        }
    }

    #[test]
    fn test_priority_win() {
        let resolver = CollisionResolver::new(OriginPriority::new());
        let c = collision("usr/lib/libfoo.so", "archlinux/foo", "debian/foo");
        let resolved = resolver.resolve_all(&[c]);
        assert_eq!(resolved.len(), 1);
        match &resolved[0].resolution {
            CollisionResolution::PriorityWin { winner, loser } => {
                assert_eq!(winner, "archlinux/foo"); // arch=10 < debian=20
                assert_eq!(loser, "debian/foo");
            }
            _ => panic!("expected PriorityWin"),
        }
    }

    #[test]
    fn test_native_always_wins() {
        let resolver = CollisionResolver::new(OriginPriority::new());
        let c = collision("usr/bin/tool", "pkt/tool", "archlinux/tool");
        let resolved = resolver.resolve_all(&[c]);
        match &resolved[0].resolution {
            CollisionResolution::PriorityWin { winner, .. } => {
                assert_eq!(winner, "pkt/tool"); // pkt=0 < arch=10
            }
            _ => panic!("expected PriorityWin"),
        }
    }

    #[test]
    fn test_same_priority_tier3() {
        let mut prio = OriginPriority::new();
        prio.set("distro-a", 10);
        prio.set("distro-b", 10);
        let resolver = CollisionResolver::new(prio);
        let c = collision("usr/bin/tool", "distro-a/pkg", "distro-b/pkg");
        let resolved = resolver.resolve_all(&[c]);
        assert!(matches!(
            &resolved[0].resolution,
            CollisionResolution::Tier3Wrapper { .. }
        ));
    }

    #[test]
    fn test_priority_only_defers() {
        let mut prio = OriginPriority::new();
        prio.set("distro-a", 10);
        prio.set("distro-b", 10);
        let resolver = CollisionResolver::new(prio).priority_only();
        let c = collision("usr/bin/tool", "distro-a/pkg", "distro-b/pkg");
        let resolved = resolver.resolve_all(&[c]);
        assert!(matches!(
            &resolved[0].resolution,
            CollisionResolution::Tier4Deferred { .. }
        ));
    }

    #[test]
    fn test_custom_priority() {
        let mut prio = OriginPriority::new();
        prio.set("debian", 5); // promote debian above arch
        let resolver = CollisionResolver::new(prio);
        let c = collision("usr/lib/libfoo.so", "archlinux/foo", "debian/foo");
        let resolved = resolver.resolve_all(&[c]);
        match &resolved[0].resolution {
            CollisionResolution::PriorityWin { winner, .. } => {
                assert_eq!(winner, "debian/foo"); // debian=5 < arch=10
            }
            _ => panic!("expected PriorityWin"),
        }
    }
}
