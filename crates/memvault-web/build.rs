use std::fs;
use std::path::Path;

fn main() {
    // Ensure public/tailwind.css exists so the asset!() macro doesn't fail
    // during `cargo test` or other builds where Tailwind hasn't run yet.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let css = Path::new(&manifest_dir).join("public/tailwind.css");
    println!("cargo:rerun-if-changed=public/tailwind.css");
    if !css.exists() {
        let _ = fs::create_dir_all(css.parent().unwrap());
        let _ = fs::write(&css, "/* placeholder — replaced by tailwind build */\n");
    }
}
