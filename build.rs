// libextos build script -- Phase 3 FFI link glue (PLAN sub-phases 3.1/3.2/3.4).
//
// Concurrency discipline: each Phase-3 lane may edit ONLY the region between
// its own markers; regions stay semantically empty until populated. Empty
// region == no contribution, which is legitimate for runtime-dlopen FFI
// designs that need no compile-time linking at all.
fn main() {
    // === LANE31-BEGIN === (libexpr-extos / Nix evaluator link args)
    // === LANE31-END ===
    // === LANE32-BEGIN === (libalpm link args)
    // === LANE32-END ===
    // === LANE34-BEGIN === (librpm link args)
    // Intentionally empty: PLAN 3.4 loads the librpm-extos C bridge at run
    // time with `libloading` (`src/fetcher/rpm/bridge.rs`), so `cargo build`
    // must not depend on librpm headers or libraries being installed. Build
    // the bridge with `inherited/librpm-extos/extos/build-bridge.sh` and point
    // `EXTOS_RPM_BRIDGE` (or LD_LIBRARY_PATH) at the resulting
    // `libextos-rpm-bridge.so`.
    // === LANE34-END ===
}
