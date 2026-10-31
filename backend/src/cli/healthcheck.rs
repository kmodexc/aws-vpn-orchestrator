//! `healthcheck`: a tiny HTTP/1.1 probe for the container healthcheck (the distroless image
//! has no curl). Needs no configuration except an optional `BIND_ADDR`.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::Duration;

use crate::config::DEFAULT_BIND_ADDR;

/// Returns the process exit code: 0 if `/healthz` answered 200, else 1.
pub fn run() -> i32 {
    let bind = std::env::var("BIND_ADDR")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_BIND_ADDR.to_string());
    let Ok(bind) = bind.parse::<SocketAddr>() else {
        eprintln!("healthcheck: BIND_ADDR is not a valid socket address");
        return 1;
    };
    match probe(target_addr(bind)) {
        Ok(true) => 0,
        Ok(false) => {
            eprintln!("healthcheck: unhealthy response");
            1
        }
        Err(e) => {
            eprintln!("healthcheck: {e}");
            1
        }
    }
}

fn target_addr(bind: SocketAddr) -> SocketAddr {
    let ip = match bind.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, bind.port())
}

fn probe(addr: SocketAddr) -> std::io::Result<bool> {
    let timeout = Duration::from_secs(3);
    let mut stream = TcpStream::connect_timeout(&addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut buf = [0u8; 64];
    let mut read = 0;
    while read < buf.len() {
        let n = stream.read(&mut buf[read..])?;
        if n == 0 {
            break;
        }
        read += n;
        if buf[..read].contains(&b'\n') {
            break;
        }
    }
    let status_line = String::from_utf8_lossy(&buf[..read]);
    Ok(status_line.starts_with("HTTP/1.1 200 ") || status_line.starts_with("HTTP/1.0 200 "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unspecified_bind_maps_to_loopback() {
        assert_eq!(
            target_addr("0.0.0.0:8080".parse().unwrap()),
            "127.0.0.1:8080".parse().unwrap()
        );
        assert_eq!(
            target_addr("[::]:9000".parse().unwrap()),
            "[::1]:9000".parse().unwrap()
        );
    }
}
