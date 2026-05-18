use std::path::Path;
use std::process::Command;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let manifest = Path::new(&manifest_dir);

    let status = Command::new("npm")
        .args(["run", "tailwind:build"])
        .current_dir(manifest)
        .status();

    match status {
        Ok(s) if s.success() => {}
        Ok(s) => panic!("npm run tailwind:build exited with {s}"),
        Err(e) => panic!("failed to run npm: {e}"),
    }
}
