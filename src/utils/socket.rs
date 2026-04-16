//! Linux socket inspection helpers.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SocketMetadata {
    pub source_ip: Option<String>,
    pub source_port: Option<u16>,
    pub destination_ip: Option<String>,
    pub destination_port: Option<u16>,
    pub protocol: Option<String>,
}

/// Query socket metadata for a file descriptor owned by `pid`.
///
/// Works for any pid, including the current process. Uses `readlink` on
/// `/proc/{pid}/fd/{fd}` to get the socket inode, then looks it up in
/// `/proc/net/tcp{,6}` and `/proc/net/udp{,6}`. This avoids `open(2)` on
/// the procfs fd symlink, which returns `ENXIO` for sockets.
pub fn query_socket_metadata(pid: u32, fd: i32) -> Option<SocketMetadata> {
    if pid == 0 || fd < 0 {
        return None;
    }

    let inode = read_socket_inode(pid, fd)?;

    lookup_proc_net("/proc/net/tcp", inode, "tcp", false)
        .or_else(|| lookup_proc_net("/proc/net/tcp6", inode, "tcp", true))
        .or_else(|| lookup_proc_net("/proc/net/udp", inode, "udp", false))
        .or_else(|| lookup_proc_net("/proc/net/udp6", inode, "udp", true))
}

/// Resolve the socket inode from `/proc/{pid}/fd/{fd}`.
///
/// The symlink target is `"socket:[inode]"` for socket fds.
fn read_socket_inode(pid: u32, fd: i32) -> Option<u64> {
    let link = fs::read_link(format!("/proc/{pid}/fd/{fd}")).ok()?;
    let s = link.to_string_lossy();
    let inner = s.strip_prefix("socket:[")?;
    inner.strip_suffix(']')?.parse().ok()
}

/// Scan a `/proc/net/{tcp,tcp6,udp,udp6}` file for a matching inode and
/// return its local and remote address as `SocketMetadata`.
///
/// Field layout (whitespace-separated, 0-indexed, header skipped):
///   0: sl   1: local_addr   2: rem_addr   3: state   …   9: inode
///
/// Addresses are printed as `XXXXXXXX:PPPP` (IPv4) or
/// `XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:PPPP` (IPv6) in host byte order.
fn lookup_proc_net(path: &str, inode: u64, protocol: &str, ipv6: bool) -> Option<SocketMetadata> {
    let content = fs::read_to_string(path).ok()?;

    for line in content.lines().skip(1) {
        let mut iter = line.split_whitespace();
        let _sl = iter.next()?;
        let local = iter.next()?;
        let remote = iter.next()?;
        let _state = iter.next()?;
        // tx_queue:rx_queue, tr:tm, retrnsmt, uid, timeout
        for _ in 0..5 {
            iter.next()?;
        }
        let line_inode: u64 = match iter.next()?.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        if line_inode != inode {
            continue;
        }

        let (src_ip, src_port) = parse_addr(local, ipv6)?;
        let (dst_ip, dst_port) = parse_addr(remote, ipv6)?;

        return Some(SocketMetadata {
            source_ip: Some(src_ip.to_string()),
            source_port: Some(src_port),
            destination_ip: Some(dst_ip.to_string()),
            destination_port: Some(dst_port),
            protocol: Some(protocol.to_string()),
        });
    }

    None
}

fn parse_addr(s: &str, ipv6: bool) -> Option<(IpAddr, u16)> {
    let (ip_hex, port_hex) = s.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let ip = if ipv6 {
        parse_ipv6_hex(ip_hex)?
    } else {
        parse_ipv4_hex(ip_hex)?
    };
    Some((ip, port))
}

/// Parse a hex IPv4 address from `/proc/net/tcp`.
///
/// The kernel prints the raw `__be32` with `%08X`, which on a little-endian
/// host produces a byte-reversed hex string. `n.to_be()` undoes that reversal
/// on LE and is a no-op on BE, yielding a u32 in network byte order suitable
/// for `Ipv4Addr::from`.
fn parse_ipv4_hex(s: &str) -> Option<IpAddr> {
    let n = u32::from_str_radix(s, 16).ok()?;
    Some(IpAddr::V4(Ipv4Addr::from(n.to_be())))
}

/// Parse a 32-hex-char IPv6 address from `/proc/net/tcp6`.
///
/// The address is four consecutive native-endian u32 words. Each word is
/// byte-swapped independently to produce the 16-byte network-order address.
fn parse_ipv6_hex(s: &str) -> Option<IpAddr> {
    if s.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let word = u32::from_str_radix(&s[i * 8..(i + 1) * 8], 16).ok()?;
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be().to_be_bytes());
    }
    Some(IpAddr::V6(Ipv6Addr::from(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::AsRawFd;

    #[test]
    fn query_socket_metadata_reads_connected_tcp_socket() {
        let listener = match TcpListener::bind(("127.0.0.1", 0)) {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("listener bind: {err}"),
        };
        let listener_addr = listener.local_addr().expect("listener addr");

        let client = TcpStream::connect(listener_addr).expect("client connect");
        let (_server, _) = listener.accept().expect("accept");

        let client_fd = client.as_raw_fd();
        let metadata = query_socket_metadata(std::process::id(), client_fd)
            .expect("connected client socket should resolve");

        assert_eq!(metadata.protocol.as_deref(), Some("tcp"));
        assert_eq!(metadata.destination_ip.as_deref(), Some("127.0.0.1"));
        assert_eq!(metadata.destination_port, Some(listener_addr.port()));
        assert_eq!(metadata.source_ip.as_deref(), Some("127.0.0.1"));
        assert_eq!(
            metadata.source_port,
            Some(client.local_addr().expect("client addr").port())
        );
    }
}
