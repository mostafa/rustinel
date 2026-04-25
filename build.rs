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

    // RUSTINEL_EBPF_STUB=1 skips the full nightly/bpf-linker build and writes
    // a bare ELF64 LE/BPF header instead.  Use this for cargo check / clippy /
    // unit tests in environments where the nightly toolchain is unavailable.
    if env::var("RUSTINEL_EBPF_STUB").as_deref() == Ok("1") {
        write_ebpf_stub(&dst);
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

/// Write a minimal valid ELF64 LE/BPF header to `dst`.
///
/// The resulting file satisfies `aya::include_bytes_aligned!` at compile time
/// but contains no programs — it must never be loaded by a live kernel.
/// Only used when `RUSTINEL_EBPF_STUB=1`.
fn write_ebpf_stub(dst: &std::path::Path) {
    use std::io::Write;

    // ELF64 little-endian, eBPF machine (0xf7), no sections or segments.
    #[rustfmt::skip]
    let header: [u8; 64] = [
        // e_ident: magic, class=64-bit, data=LE, version=1, OS/ABI=0, padding
        0x7f, b'E', b'L', b'F', 2, 1, 1, 0,  0, 0, 0, 0, 0, 0, 0, 0,
        // e_type=ET_EXEC(2), e_machine=EM_BPF(0xf7), e_version=1
        2, 0,  0xf7, 0,  1, 0, 0, 0,
        // e_entry, e_phoff, e_shoff (all zero)
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        // e_flags=0, e_ehsize=64, e_phentsize=56, e_phnum=0
        0, 0, 0, 0,  64, 0,  56, 0,  0, 0,
        // e_shentsize=64, e_shnum=0, e_shstrndx=0
        64, 0,  0, 0,  0, 0,
    ];

    let mut f = std::fs::File::create(dst)
        .unwrap_or_else(|e| panic!("failed to create eBPF stub at {dst:?}: {e}"));
    f.write_all(&header)
        .unwrap_or_else(|e| panic!("failed to write eBPF stub: {e}"));
}
