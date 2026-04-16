fn main() {
    // Only build/embed eBPF programs when compiling for Linux.
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "linux" {
        build_ebpf();
    }
}

fn build_ebpf() {
    use std::{env, path::PathBuf, process::Command};

    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let dst = out_dir.join("rustinel-ebpf");

    // Re-run when eBPF source or its manifest changes.
    println!("cargo:rerun-if-changed=ebpf/src");
    println!("cargo:rerun-if-changed=ebpf/Cargo.toml");
    // Re-run if the pre-built artifact changes too.
    println!("cargo:rerun-if-changed=ebpf/rustinel-ebpf.o");

    // If a pre-built artifact already exists (produced by a prior local build
    // or downloaded from CI), use it directly so that a full nightly +
    // bpf-linker toolchain is not required for every build.
    let pre_built = manifest_dir.join("ebpf/rustinel-ebpf.o");
    if pre_built.exists() {
        std::fs::copy(&pre_built, &dst)
            .unwrap_or_else(|e| panic!("failed to copy pre-built eBPF artifact: {e}"));
        return;
    }

    // No pre-built artifact — compile from source using the nightly toolchain.
    let ebpf_dir = manifest_dir.join("ebpf");
    let status = Command::new("cargo")
        .args(["+nightly", "build", "--release", "--bin", "rustinel-ebpf"])
        .current_dir(&ebpf_dir)
        // The parent stable-cargo process exports CARGO pointing to the
        // stable rustc. If that propagates into the nightly sub-build,
        // Cargo uses the stable compiler for eBPF dependencies
        // (bpfel-unknown-none), which fails. Drop it so the nightly toolchain
        // sets its own CARGO path.
        .env_remove("CARGO")
        // Cargo also sets RUSTC to the stable rustc binary. Nightly cargo
        // honours RUSTC when locating the compiler and sysroot (for
        // build-std), so leaving it set causes `rustc --print sysroot` to
        // return the stable sysroot — which has no rust-src.
        .env_remove("RUSTC")
        // Cargo sets RUSTUP_TOOLCHAIN to the active stable toolchain when
        // running build scripts. That overrides the +nightly argument above,
        // causing cargo to look for rust-src in the stable sysroot (which
        // doesn't have it) instead of the nightly one.
        .env_remove("RUSTUP_TOOLCHAIN")
        .status()
        .expect(
            "failed to invoke cargo for eBPF build — \
             install the nightly toolchain or run scripts/build-ebpf.sh first",
        );

    assert!(
        status.success(),
        "eBPF program build failed — see output above"
    );

    let src = ebpf_dir.join("target/bpfel-unknown-none/release/rustinel-ebpf");
    std::fs::copy(&src, &dst)
        .unwrap_or_else(|e| panic!("failed to copy compiled eBPF artifact from {src:?}: {e}"));
}
