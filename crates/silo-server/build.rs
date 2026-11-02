//! Embeds the built admin console (`ui/dist`) into the server binary.
//!
//! The console is a Vite build that lives outside the Rust tree, so a plain
//! `cargo build` on a machine without Node must still succeed. When
//! `ui/dist` does not exist this generates a one-page placeholder that says
//! how to build it, instead of failing the build. `SILO_UI_DIST` points the
//! embed at a different directory.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=SILO_UI_DIST");
    println!("cargo:rerun-if-changed=build.rs");

    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let dist = std::env::var_os("SILO_UI_DIST")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.join("../../ui/dist"));
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    let mut files = Vec::new();
    if dist.join("index.html").is_file() {
        // Watching the directory re-runs this when a rebuild changes any
        // asset; watching only a missing path re-runs it until one exists.
        println!("cargo:rerun-if-changed={}", dist.display());
        collect(&dist, &dist, &mut files);
    } else {
        println!(
            "cargo:rerun-if-changed={}",
            dist.join("index.html").display()
        );
        let placeholder = out.join("ui-placeholder.html");
        std::fs::write(&placeholder, PLACEHOLDER).unwrap();
        files.push(("index.html".to_string(), placeholder));
    }
    files.sort();

    let mut generated = String::from("pub static ASSETS: &[(&str, &[u8])] = &[\n");
    for (name, path) in &files {
        writeln!(
            generated,
            "    ({name:?}, include_bytes!({:?})),",
            path.display().to_string()
        )
        .unwrap();
    }
    generated.push_str("];\n");
    std::fs::write(out.join("ui_assets.rs"), generated).unwrap();
}

fn collect(root: &Path, dir: &Path, files: &mut Vec<(String, PathBuf)>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect(root, &path, files);
        } else {
            let name = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            files.push((name, path.canonicalize().unwrap()));
        }
    }
}

const PLACEHOLDER: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>silo admin</title></head>
<body style="font-family: sans-serif; max-width: 40rem; margin: 4rem auto">
<h1>The admin console is not built into this binary</h1>
<p>Build it with <code>npm ci &amp;&amp; npm run build</code> in <code>ui/</code>,
then rebuild <code>silo-server</code>.</p>
</body></html>
"#;
