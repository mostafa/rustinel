//! Network connection eBPF program.
//!
//! Attaches to `syscalls/sys_enter_connect`. Fires when a process calls
//! `connect(2)`, covering both TCP and UDP outbound connections. Reading the
//! sockaddr at the syscall entry point gives us the destination before the
//! kernel acts on it, while still running in full task context so
//! `bpf_get_current_pid_tgid()` is valid.
//!
//! sys_enter_connect tracepoint format (x86_64, 64-bit ABI):
//!   offset  0: common_type         (u16)
//!   offset  2: common_flags        (u8)
//!   offset  3: common_preempt_count(u8)
//!   offset  4: common_pid          (i32)
//!   offset  8: __syscall_nr        (i32)
//!   offset 12: _padding            (4 bytes)
//!   offset 16: fd                  (i64)
//!   offset 24: uservaddr           (u64 — pointer to user-space sockaddr)
//!   offset 32: addrlen             (i32)

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_user},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};

use crate::events::NetworkEvent;

/// AF_INET (IPv4).
const AF_INET: u16 = 2;
/// AF_INET6 (IPv6).
const AF_INET6: u16 = 10;

/// IPv4 socket address as laid out by the C ABI.
#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn {
    family: u16,
    port: u16,     // network byte order
    addr: [u8; 4], // network byte order
    _pad: [u8; 8],
}

/// IPv6 socket address as laid out by the C ABI.
#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn6 {
    family: u16,
    port: u16, // network byte order
    flowinfo: u32,
    addr: [u8; 16],
    scope_id: u32,
}

/// Ring buffer shared with the userspace loader for network events.
#[map]
pub static NETWORK_RING: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Tracepoint handler for `syscalls/sys_enter_connect`.
#[tracepoint]
pub fn handle_connect(ctx: TracePointContext) -> u32 {
    unsafe { try_handle_connect(&ctx) }.unwrap_or(1)
}

#[inline(always)]
unsafe fn try_handle_connect(ctx: &TracePointContext) -> Result<u32, i64> {
    // pid_tgid: high 32 bits = TGID (POSIX PID), low 32 bits = kernel thread ID.
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let fd = ctx.read_at::<i64>(16)? as i32;

    // Read pointer to user-space sockaddr structure.
    let uservaddr: u64 = ctx.read_at::<u64>(24)?;
    if uservaddr == 0 {
        return Ok(0);
    }

    // Probe the address family (first 2 bytes of any sockaddr).
    let family: u16 = bpf_probe_read_user(uservaddr as *const u16)?;

    let mut daddr = [0u8; 16];
    let dport: u16;
    let sport: u16 = 0; // source port not yet assigned at connect() entry

    match family {
        AF_INET => {
            let sa = bpf_probe_read_user::<SockAddrIn>(uservaddr as *const _)?;
            dport = u16::from_be(sa.port);
            daddr[..4].copy_from_slice(&sa.addr);
        }
        AF_INET6 => {
            let sa = bpf_probe_read_user::<SockAddrIn6>(uservaddr as *const _)?;
            dport = u16::from_be(sa.port);
            daddr.copy_from_slice(&sa.addr);
        }
        // Skip non-IP address families (AF_UNIX, AF_NETLINK, etc.).
        _ => return Ok(0),
    }

    // Skip loopback-only connects to reduce noise (127.0.0.0/8).
    if family == AF_INET && daddr[0] == 127 {
        return Ok(0);
    }

    if let Some(mut entry) = NETWORK_RING.reserve::<NetworkEvent>(0) {
        entry.write(NetworkEvent {
            pid,
            uid,
            fd,
            _pad0: 0,
            dport,
            sport,
            af: family,
            _pad1: 0,
            daddr,
            saddr: [0u8; 16],
        });
        entry.submit(0);
    }

    Ok(0)
}
