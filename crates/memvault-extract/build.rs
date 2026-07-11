use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

/// One guest WASM module to build and embed.
struct GuestSpec {
    /// Crate directory name under `<workspace>/crates/`.
    crate_dir: &'static str,
    /// Rust target triple. The text guest needs no WASI; media guests use
    /// wasip1 for file access (models), clocks, and randomness.
    target: &'static str,
    /// Env var consumed by `include_bytes!(env!(...))` in src/lib.rs.
    env_var: &'static str,
    /// Additional override env var honored for backwards compatibility.
    legacy_override: Option<&'static str>,
    /// Cargo feature (upper-snake, as in `CARGO_FEATURE_*`) gating this
    /// guest. None = always built.
    feature: Option<&'static str>,
}

const GUESTS: &[GuestSpec] = &[
    GuestSpec {
        crate_dir: "memvault-extract-guest-text",
        target: "wasm32-unknown-unknown",
        env_var: "MEMVAULT_EXTRACT_GUEST_TEXT_WASM",
        legacy_override: Some("MEMVAULT_EXTRACT_GUEST_WASM"),
        feature: None,
    },
    GuestSpec {
        crate_dir: "memvault-extract-guest-pdfrender",
        target: "wasm32-wasip1",
        env_var: "MEMVAULT_EXTRACT_GUEST_PDFRENDER_WASM",
        legacy_override: None,
        feature: Some("MEDIA_PLUGINS"),
    },
    GuestSpec {
        crate_dir: "memvault-extract-guest-ocr",
        target: "wasm32-wasip1",
        env_var: "MEMVAULT_EXTRACT_GUEST_OCR_WASM",
        legacy_override: None,
        feature: Some("MEDIA_PLUGINS"),
    },
    GuestSpec {
        crate_dir: "memvault-extract-guest-audio",
        target: "wasm32-wasip1",
        env_var: "MEMVAULT_EXTRACT_GUEST_AUDIO_WASM",
        legacy_override: None,
        feature: Some("MEDIA_PLUGINS"),
    },
];

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    // Sibling crates (the guest crates, memvault-extract-abi) live next to
    // this crate at `<workspace>/crates/<name>`. That holds in both layouts
    // memvault ships in:
    //   - standalone memvault repo: `<workspace>/crates/memvault-extract`
    //   - mac-mgmt monorepo:        `<workspace>/memvault/crates/memvault-extract`
    // Use the parent of the manifest dir (`crates/`) as the anchor and
    // resolve the workspace root by walking up to the nearest Cargo.toml
    // that declares a `[workspace]`, which gives the right target dir in
    // both cases.
    let crates_dir = manifest_dir
        .parent()
        .expect("memvault-extract should live under <workspace>/crates")
        .to_path_buf();
    let workspace_root = find_workspace_root(&crates_dir);

    for guest in GUESTS {
        build_guest(guest, &crates_dir, &workspace_root);
    }
}

fn build_guest(guest: &GuestSpec, crates_dir: &Path, workspace_root: &Path) {
    if let Some(feature) = guest.feature {
        if env::var_os(format!("CARGO_FEATURE_{feature}")).is_none() {
            return;
        }
    }

    // Env override: use a prebuilt guest artifact instead of a nested build.
    println!("cargo:rerun-if-env-changed={}", guest.env_var);
    let mut overrides = vec![guest.env_var];
    if let Some(legacy) = guest.legacy_override {
        println!("cargo:rerun-if-env-changed={legacy}");
        overrides.push(legacy);
    }
    for var in overrides {
        if let Some(path) = env::var_os(var) {
            let path = PathBuf::from(path);
            assert_wasm_exists(guest, &path);
            println!("cargo:rustc-env={}={}", guest.env_var, path.display());
            return;
        }
    }

    let guest_dir = crates_dir.join(guest.crate_dir);
    let guest_manifest = guest_dir.join("Cargo.toml");
    let guest_src = guest_dir.join("src");
    let abi_src = crates_dir.join("memvault-extract-abi/src");
    let mut inputs = vec![guest_manifest.clone(), guest_src, abi_src];
    let guest_lock = guest_dir.join("Cargo.lock");
    if guest_lock.exists() {
        inputs.push(guest_lock);
    }
    for input in &inputs {
        emit_rerun_if_changed(input);
    }

    // Build the guest WASM in its OWN target directory under
    // `<workspace>/target/<crate_dir>/`, NOT the workspace-root `target/`.
    // Using the same target dir as the outer build deadlocks when this
    // build.rs runs while that outer build is still holding its `target/`
    // lock — the nested `cargo build` blocks on the same lock forever
    // (observed in NixOS sandbox builds; see the sync NixOS test). A
    // dedicated sub-target per guest sidesteps the race (and per-guest
    // dirs avoid lock contention between the nested builds themselves).
    let target_dir = workspace_root.join("target").join(guest.crate_dir);
    let artifact = format!("{}.wasm", guest.crate_dir.replace('-', "_"));
    let wasm_path = target_dir.join(guest.target).join("release").join(artifact);

    let input_refs: Vec<&PathBuf> = inputs.iter().collect();
    if should_rebuild_wasm(&wasm_path, &input_refs) {
        let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let status = Command::new(cargo)
            .arg("build")
            .arg("--manifest-path")
            .arg(&guest_manifest)
            .arg("--target")
            .arg(guest.target)
            .arg("--release")
            .env("CARGO_TARGET_DIR", &target_dir)
            .status()
            .unwrap_or_else(|e| {
                panic!(
                    "failed to spawn cargo to build {} WASM: {e}",
                    guest.crate_dir
                )
            });

        if !status.success() {
            panic!(
                "failed to build {} WASM at {} (status: {status})",
                guest.crate_dir,
                wasm_path.display()
            );
        }
    }

    assert_wasm_exists(guest, &wasm_path);
    println!("cargo:rustc-env={}={}", guest.env_var, wasm_path.display());
}

/// Walk upward from `start` until we find a Cargo.toml containing
/// `[workspace]`. Falls back to `start` if nothing is found (e.g. when
/// build.rs runs from an exotic CARGO_MANIFEST_DIR with no workspace).
fn find_workspace_root(start: &Path) -> PathBuf {
    let mut current = start.to_path_buf();
    loop {
        let manifest = current.join("Cargo.toml");
        if manifest.is_file() {
            if let Ok(content) = fs::read_to_string(&manifest) {
                if content.contains("[workspace]") {
                    return current;
                }
            }
        }
        if !current.pop() {
            return start.to_path_buf();
        }
    }
}

fn assert_wasm_exists(guest: &GuestSpec, path: &Path) {
    if !path.exists() {
        panic!(
            "{} guest WASM not found at {}; set {} or build {} for {}",
            guest.crate_dir,
            path.display(),
            guest.env_var,
            guest.crate_dir,
            guest.target
        );
    }
}

fn should_rebuild_wasm(wasm_path: &Path, inputs: &[&PathBuf]) -> bool {
    let Ok(wasm_meta) = fs::metadata(wasm_path) else {
        return true;
    };
    let wasm_mtime = wasm_meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    inputs
        .iter()
        .filter_map(|path| newest_mtime(path))
        .any(|mtime| mtime > wasm_mtime)
}

fn emit_rerun_if_changed(path: &Path) {
    println!("cargo:rerun-if-changed={}", path.display());
    if path.is_dir() {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                emit_rerun_if_changed(&entry.path());
            }
        }
    }
}

fn newest_mtime(path: &Path) -> Option<SystemTime> {
    let meta = fs::metadata(path).ok()?;
    let mut newest = meta.modified().ok();
    if meta.is_dir() {
        for entry in fs::read_dir(path).ok()?.flatten() {
            if let Some(child_mtime) = newest_mtime(&entry.path()) {
                newest = Some(match newest {
                    Some(current) => current.max(child_mtime),
                    None => child_mtime,
                });
            }
        }
    }
    newest
}
