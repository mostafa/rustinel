//! Process memory reader for YARA memory scanning.
//!
//! Reads selected memory regions from a live process into byte chunks that
//! can then be passed to `Scanner::scan_bytes`. All I/O failures are treated
//! as non-fatal — callers receive whatever chunks were successfully read.

use anyhow::Result;

/// Per-scan limits and region-type filters.
#[derive(Debug, Clone)]
pub struct MemoryScanConfig {
    /// Stop reading a process once this many bytes have been accumulated.
    pub max_process_bytes: usize,
    /// Clamp each region read to this many bytes.
    pub max_region_bytes: usize,
    pub include_private: bool,
    pub include_image: bool,
    pub include_mapped: bool,
    /// Milliseconds to wait before scanning (gives packers time to unpack).
    pub delay_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryRegionKind {
    Private,
    Image,
    Mapped,
    Other,
}

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base: u64,
    pub size: usize,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub kind: MemoryRegionKind,
}

#[derive(Debug)]
pub struct MemoryChunk {
    pub base: u64,
    pub bytes: Vec<u8>,
    pub region: MemoryRegion,
}

/// Read selected memory regions from `pid` according to `cfg`.
/// Returns whatever chunks could be read; individual region failures are silently skipped.
pub fn read_process_memory_chunks(pid: u32, cfg: &MemoryScanConfig) -> Result<Vec<MemoryChunk>> {
    platform::read_process_memory_chunks(pid, cfg)
}

// ── Windows implementation ────────────────────────────────────────────────────

#[cfg(windows)]
mod platform {
    use super::{MemoryChunk, MemoryRegion, MemoryRegionKind, MemoryScanConfig};
    use anyhow::Result;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE,
        PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
        PAGE_GUARD, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE,
        PAGE_WRITECOPY,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
    };

    fn is_readable(protect: PAGE_PROTECTION_FLAGS) -> bool {
        matches!(
            protect,
            PAGE_READONLY
                | PAGE_READWRITE
                | PAGE_WRITECOPY
                | PAGE_EXECUTE_READ
                | PAGE_EXECUTE_READWRITE
                | PAGE_EXECUTE_WRITECOPY
        )
    }

    fn is_writable(protect: PAGE_PROTECTION_FLAGS) -> bool {
        matches!(
            protect,
            PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        )
    }

    fn is_executable(protect: PAGE_PROTECTION_FLAGS) -> bool {
        matches!(
            protect,
            PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        )
    }

    pub fn read_process_memory_chunks(
        pid: u32,
        cfg: &MemoryScanConfig,
    ) -> Result<Vec<MemoryChunk>> {
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                false,
                pid,
            )
        };

        let handle = match handle {
            Ok(h) if !h.is_invalid() => h,
            Ok(_) | Err(_) => {
                tracing::trace!(
                    target: "scanner",
                    pid = pid,
                    "YARA memory: OpenProcess failed (process may have exited)"
                );
                return Ok(Vec::new());
            }
        };

        let mut chunks = Vec::new();
        let mut address: usize = 0;
        let mut total_bytes: usize = 0;

        loop {
            if total_bytes >= cfg.max_process_bytes {
                break;
            }

            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let written = unsafe {
                VirtualQueryEx(
                    handle,
                    Some(address as *const _),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };

            if written == 0 {
                break;
            }

            let region_base = mbi.BaseAddress as usize;
            let region_size = mbi.RegionSize;

            // Advance cursor regardless of whether we read this region.
            address = match region_base.checked_add(region_size) {
                Some(next) => next,
                None => break,
            };

            // Only scan committed pages.
            if mbi.State != MEM_COMMIT {
                continue;
            }

            let protect = mbi.Protect;

            // Skip inaccessible and guard pages.
            if protect == PAGE_NOACCESS || protect.contains(PAGE_GUARD) {
                continue;
            }

            if !is_readable(protect) {
                continue;
            }

            let kind = if mbi.Type == MEM_PRIVATE {
                MemoryRegionKind::Private
            } else if mbi.Type == MEM_IMAGE {
                MemoryRegionKind::Image
            } else if mbi.Type == MEM_MAPPED {
                MemoryRegionKind::Mapped
            } else {
                MemoryRegionKind::Other
            };

            let include = match kind {
                MemoryRegionKind::Private => cfg.include_private,
                MemoryRegionKind::Image => cfg.include_image,
                MemoryRegionKind::Mapped => cfg.include_mapped,
                MemoryRegionKind::Other => false,
            };

            if !include {
                continue;
            }

            let read_size = region_size
                .min(cfg.max_region_bytes)
                .min(cfg.max_process_bytes - total_bytes);

            let mut buf = vec![0u8; read_size];
            let mut bytes_read: usize = 0;

            let ok = unsafe {
                ReadProcessMemory(
                    handle,
                    region_base as *const _,
                    buf.as_mut_ptr() as *mut _,
                    read_size,
                    Some(&mut bytes_read),
                )
            };

            if ok.is_err() || bytes_read == 0 {
                tracing::trace!(
                    target: "scanner",
                    pid = pid,
                    base = format_args!("0x{:x}", region_base),
                    "YARA memory: ReadProcessMemory failed (normal for guard/exited process)"
                );
                continue;
            }

            buf.truncate(bytes_read);
            total_bytes += bytes_read;

            let region = MemoryRegion {
                base: region_base as u64,
                size: region_size,
                readable: true,
                writable: is_writable(protect),
                executable: is_executable(protect),
                kind,
            };

            chunks.push(MemoryChunk {
                base: region_base as u64,
                bytes: buf,
                region,
            });
        }

        unsafe {
            let _ = CloseHandle(handle);
        }

        Ok(chunks)
    }
}

// ── Linux implementation ──────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod platform {
    use super::{MemoryChunk, MemoryRegion, MemoryRegionKind, MemoryScanConfig};
    use anyhow::Result;
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};

    struct MapsEntry {
        start: u64,
        end: u64,
        readable: bool,
        writable: bool,
        executable: bool,
        private: bool,
        path: Option<String>,
    }

    fn parse_maps_line(line: &str) -> Option<MapsEntry> {
        let mut parts = line.splitn(6, ' ');
        let addr_range = parts.next()?;
        let perms = parts.next()?;
        let _offset = parts.next()?;
        let _device = parts.next()?;
        let _inode = parts.next()?;
        let path = parts
            .next()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let (start_str, end_str) = addr_range.split_once('-')?;
        let start = u64::from_str_radix(start_str, 16).ok()?;
        let end = u64::from_str_radix(end_str, 16).ok()?;

        let readable = perms.starts_with('r');
        let writable = perms.len() > 1 && perms.chars().nth(1) == Some('w');
        let executable = perms.len() > 2 && perms.chars().nth(2) == Some('x');
        let private = perms.len() > 3 && perms.chars().nth(3) == Some('p');

        Some(MapsEntry {
            start,
            end,
            readable,
            writable,
            executable,
            private,
            path,
        })
    }

    fn classify_region(path: Option<&str>) -> MemoryRegionKind {
        match path {
            None | Some("") => MemoryRegionKind::Private,
            Some(p) if p.starts_with('[') => MemoryRegionKind::Other,
            Some(_) => MemoryRegionKind::Mapped,
        }
    }

    pub fn read_process_memory_chunks(
        pid: u32,
        cfg: &MemoryScanConfig,
    ) -> Result<Vec<MemoryChunk>> {
        let maps_path = format!("/proc/{}/maps", pid);
        let mem_path = format!("/proc/{}/mem", pid);

        let maps_content = match std::fs::read_to_string(&maps_path) {
            Ok(s) => s,
            Err(err) => {
                tracing::trace!(
                    target: "scanner",
                    pid = pid,
                    error = %err,
                    "YARA memory: cannot read /proc/<pid>/maps"
                );
                return Ok(Vec::new());
            }
        };

        let mut mem_file = match File::open(&mem_path) {
            Ok(f) => f,
            Err(err) => {
                tracing::trace!(
                    target: "scanner",
                    pid = pid,
                    error = %err,
                    "YARA memory: cannot open /proc/<pid>/mem"
                );
                return Ok(Vec::new());
            }
        };

        let mut chunks = Vec::new();
        let mut total_bytes: usize = 0;

        for line in maps_content.lines() {
            if total_bytes >= cfg.max_process_bytes {
                break;
            }

            let entry = match parse_maps_line(line) {
                Some(e) => e,
                None => continue,
            };

            if !entry.readable {
                continue;
            }

            let path_ref = entry.path.as_deref();

            // Skip special kernel-mapped regions.
            if let Some(p) = path_ref {
                if matches!(p, "[vvar]" | "[vdso]" | "[vsyscall]") {
                    continue;
                }
            }

            let kind = if entry.private && entry.path.is_none() {
                MemoryRegionKind::Private
            } else {
                classify_region(path_ref)
            };

            let include = match kind {
                MemoryRegionKind::Private => cfg.include_private,
                MemoryRegionKind::Image => cfg.include_image,
                MemoryRegionKind::Mapped => cfg.include_mapped,
                MemoryRegionKind::Other => false,
            };

            if !include {
                continue;
            }

            let region_size = (entry.end - entry.start) as usize;
            let read_size = region_size
                .min(cfg.max_region_bytes)
                .min(cfg.max_process_bytes - total_bytes);

            if read_size == 0 {
                break;
            }

            if mem_file.seek(SeekFrom::Start(entry.start)).is_err() {
                continue;
            }

            let mut buf = vec![0u8; read_size];
            let bytes_read = match mem_file.read(&mut buf) {
                Ok(n) => n,
                Err(err) => {
                    tracing::trace!(
                        target: "scanner",
                        pid = pid,
                        base = format_args!("0x{:x}", entry.start),
                        error = %err,
                        "Unable to read memory region"
                    );
                    continue;
                }
            };

            if bytes_read == 0 {
                continue;
            }

            buf.truncate(bytes_read);
            total_bytes += bytes_read;

            let region = MemoryRegion {
                base: entry.start,
                size: region_size,
                readable: true,
                writable: entry.writable,
                executable: entry.executable,
                kind,
            };

            chunks.push(MemoryChunk {
                base: entry.start,
                bytes: buf,
                region,
            });
        }

        Ok(chunks)
    }
}

// Stub for unsupported platforms so the crate still compiles.
#[cfg(not(any(windows, target_os = "linux")))]
mod platform {
    use super::{MemoryChunk, MemoryScanConfig};
    use anyhow::Result;

    pub fn read_process_memory_chunks(
        _pid: u32,
        _cfg: &MemoryScanConfig,
    ) -> Result<Vec<MemoryChunk>> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_scan_config_fields() {
        let cfg = MemoryScanConfig {
            max_process_bytes: 64 * 1024 * 1024,
            max_region_bytes: 8 * 1024 * 1024,
            include_private: true,
            include_image: false,
            include_mapped: false,
            delay_ms: 750,
        };
        assert_eq!(cfg.max_process_bytes, 64 * 1024 * 1024);
        assert_eq!(cfg.max_region_bytes, 8 * 1024 * 1024);
        assert!(cfg.include_private);
        assert!(!cfg.include_image);
        assert!(!cfg.include_mapped);
    }

    #[test]
    fn test_memory_region_kind_variants() {
        assert_ne!(MemoryRegionKind::Private, MemoryRegionKind::Image);
        assert_ne!(MemoryRegionKind::Mapped, MemoryRegionKind::Other);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_read_nonexistent_pid_returns_empty() {
        let cfg = MemoryScanConfig {
            max_process_bytes: 1024,
            max_region_bytes: 512,
            include_private: true,
            include_image: true,
            include_mapped: true,
            delay_ms: 0,
        };
        // PID 99999999 should not exist; expect Ok(empty).
        let result = read_process_memory_chunks(99_999_999, &cfg);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}
