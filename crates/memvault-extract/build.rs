use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

fn main() {
    println!("cargo:rerun-if-env-changed=MEMVAULT_EXTRACT_GUEST_WASM");

    if let Some(path) = env::var_os("MEMVAULT_EXTRACT_GUEST_WASM") {
        let path = PathBuf::from(path);
        assert_wasm_exists(&path);
        println!(
            "cargo:rustc-env=MEMVAULT_EXTRACT_GUEST_WASM={}",
            path.display()
        );
        return;
    }

    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    // Sibling crates (memvault-extract-guest, memvault-extract-abi) live
    // next to this crate at `<workspace>/crates/<name>`. That holds in
    // both layouts memvault ships in:
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
    let guest_manifest = crates_dir.join("memvault-extract-guest/Cargo.toml");
    let guest_lock = crates_dir.join("memvault-extract-guest/Cargo.lock");
    let guest_src = crates_dir.join("memvault-extract-guest/src");
    let abi_src = crates_dir.join("memvault-extract-abi/src");
    let inputs = [&guest_manifest, &guest_lock, &guest_src, &abi_src];
    for input in inputs {
        emit_rerun_if_changed(input);
    }

    // Always use the workspace-root target dir for the guest WASM,
    // ignoring CARGO_TARGET_DIR. The Procfile sets per-node target dirs
    // (e.g. target/node_a, target/node_b) to avoid lock conflicts, but
    // the guest WASM is a shared prebuilt artifact in the default target/.
    let target_dir = workspace_root.join("target");
    let wasm_path = target_dir.join("wasm32-unknown-unknown/release/memvault_extract_guest.wasm");

    if should_rebuild_wasm(&wasm_path, &inputs) {
        let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let status = Command::new(cargo)
            .arg("build")
            .arg("--manifest-path")
            .arg(&guest_manifest)
            .arg("--target")
            .arg("wasm32-unknown-unknown")
            .arg("--release")
            .env("CARGO_TARGET_DIR", &target_dir)
            .status()
            .expect("failed to spawn cargo to build memvault-extract-guest WASM");

        if !status.success() {
            panic!(
                "failed to build memvault-extract-guest WASM at {} (status: {status})",
                wasm_path.display()
            );
        }
    }

    assert_wasm_exists(&wasm_path);
    println!(
        "cargo:rustc-env=MEMVAULT_EXTRACT_GUEST_WASM={}",
        wasm_path.display()
    );
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

fn assert_wasm_exists(path: &Path) {
    if !path.exists() {
        panic!(
            "memvault-extract guest WASM not found at {}; set MEMVAULT_EXTRACT_GUEST_WASM or build memvault-extract-guest for wasm32-unknown-unknown",
            path.display()
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
