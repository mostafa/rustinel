// Target binary for YARA memory-scan integration tests.
//
// Allocates RUSTINEL_TEST_MARKER on the heap so it lands in private memory
// (readable with include_private=true, no image-region scan needed).
// Prints "READY:{pid}" then loops until killed.
//
// Build:  cargo build --example memory_target
// Run:    target\debug\examples\memory_target.exe   (killed by test or Ctrl+C)
use std::{hint::black_box, io::Write, thread, time::Duration};

fn main() {
    // Heap-allocate so the marker lives in private memory.
    let marker: Vec<u8> = b"RUSTINEL_TEST_MARKER".to_vec();

    // Announce readiness; flush so the parent process can synchronise.
    println!("READY:{}", std::process::id());
    std::io::stdout().flush().ok();

    loop {
        thread::sleep(Duration::from_secs(1));
        // Prevent the compiler from optimising marker away.
        black_box(&marker);
    }
}
