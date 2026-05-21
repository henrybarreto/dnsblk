#![allow(missing_docs)]

use std::{
    env,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn main() {
    println!("cargo:rerun-if-changed=ebpf/Cargo.toml");
    println!("cargo:rerun-if-changed=ebpf/Cargo.lock");
    println!("cargo:rerun-if-changed=ebpf/rust-toolchain.toml");
    println!("cargo:rerun-if-changed=ebpf/src/lib.rs");

    if let Err(message) = build_ebpf() {
        panic!("{message}");
    }
}

fn build_ebpf() -> Result<(), String> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").map_err(|err| {
        format!("Failed to read CARGO_MANIFEST_DIR for eBPF build: {err}")
    })?);
    let out_dir = PathBuf::from(
        env::var("OUT_DIR").map_err(|err| format!("Failed to read OUT_DIR for eBPF build: {err}"))?,
    );
    let target_dir = out_dir.join("ebpf-target");
    fs::create_dir_all(&target_dir)
        .map_err(|err| format!("Failed to create eBPF target dir {}: {err}", target_dir.display()))?;

    let ebpf_manifest = manifest_dir.join("ebpf/Cargo.toml");
    let mut command = Command::new("cargo");
    command
        .arg("build")
        .arg("--release")
        .arg("--target")
        .arg("bpfel-unknown-none")
        .arg("-Z")
        .arg("build-std=core")
        .arg("--locked")
        .arg("--manifest-path")
        .arg(&ebpf_manifest)
        .arg("--target-dir")
        .arg(&target_dir)
        .env_remove("CARGO")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTC")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("RUSTDOC")
        .env_remove("RUSTFLAGS");

    let status = command
        .status()
        .map_err(|err| format!("Failed to spawn cargo for eBPF build: {err}"))?;

    if !status.success() {
        return Err(format!(
            "eBPF build failed: cargo build --manifest-path {}",
            ebpf_manifest.display()
        ));
    }

    let built_object = target_dir
        .join("bpfel-unknown-none")
        .join("release")
        .join("libdnsblk_ebpf.so");
    let packaged_object = out_dir.join("libdnsblk_ebpf.so");
    copy_file(&built_object, &packaged_object)?;

    Ok(())
}

fn copy_file(from: &Path, to: &Path) -> Result<(), String> {
    fs::copy(from, to).map_err(|err| {
        format!(
            "Failed to copy eBPF object from {} to {}: {err}",
            from.display(),
            to.display()
        )
    })?;
    Ok(())
}
