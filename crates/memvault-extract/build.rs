use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=MEMVAULT_EXTRACT_GUEST_WASM");
    println!("cargo:rerun-if-changed=../memvault-extract-guest/Cargo.toml");
    println!("cargo:rerun-if-changed=../memvault-extract-guest/Cargo.lock");
    println!("cargo:rerun-if-changed=../memvault-extract-guest/src");
    println!("cargo:rerun-if-changed=../memvault-extract-abi/src");

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
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .expect("memvault-extract should live under memvault/crates")
        .to_path_buf();
    let guest_manifest = workspace_root.join("memvault/crates/memvault-extract-guest/Cargo.toml");

    // Always use the workspace-root target dir for the guest WASM,
    // ignoring CARGO_TARGET_DIR. The Procfile sets per-node target dirs
    // (e.g. target/node_a, target/node_b) to avoid lock conflicts, but
    // the guest WASM is a shared prebuilt artifact in the default target/.
    let target_dir = workspace_root.join("target");
    let wasm_path = target_dir.join("wasm32-unknown-unknown/release/memvault_extract_guest.wasm");

    if !wasm_path.exists() {
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

fn assert_wasm_exists(path: &Path) {
    if !path.exists() {
        panic!(
            "memvault-extract guest WASM not found at {}; set MEMVAULT_EXTRACT_GUEST_WASM or build memvault-extract-guest for wasm32-unknown-unknown",
            path.display()
        );
    }
}
