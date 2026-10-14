//! The address a request comes from, for limits per client.

use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;

use crate::AppState;

/// A reverse proxy on another machine whose client address header is
/// believed: one address (`10.0.0.5`) or a network (`10.0.0.0/24`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedProxy {
    net: IpAddr,
    prefix: u8,
}

impl TrustedProxy {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.net, unmap(ip)) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.prefix)).unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX.checked_shl(128 - u32::from(self.prefix)).unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

impl std::str::FromStr for TrustedProxy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, prefix) = s.trim().split_once('/').map_or((s.trim(), None), |(a, p)| (a, Some(p)));
        let net = unmap(addr.parse::<IpAddr>().map_err(|_| format!("not an IP address: {addr}"))?);
        let max = if net.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => max,
            Some(p) => p.parse::<u8>().ok().filter(|p| *p <= max).ok_or_else(|| format!("bad prefix length: {p}"))?,
        };
        Ok(TrustedProxy { net, prefix })
    }
}

impl std::fmt::Display for TrustedProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.net, self.prefix)
    }
}

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// The client's address as a limiter key. IPv6 addresses count per /64,
/// which is what one household or server usually gets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientIp(pub String);

impl ClientIp {
    pub fn from_parts(peer: Option<IpAddr>, header: Option<&str>, trusted: &[TrustedProxy]) -> Self {
        // A header is only believed when a proxy on this machine (Caddy,
        // cloudflared) or a trusted one sent the request; otherwise anyone
        // could set it.
        let forwarded = peer
            .filter(|ip| ip.is_loopback() || unmap(*ip).is_loopback() || trusted.iter().any(|t| t.contains(*ip)))
            .and(header)
            // X-Forwarded-For: the last entry is the one our proxy added.
            .and_then(|h| h.rsplit(',').next())
            .and_then(|ip| ip.trim().parse::<IpAddr>().ok());
        match forwarded.or(peer) {
            Some(IpAddr::V6(v6)) if v6.to_ipv4_mapped().is_none() => {
                let s = v6.segments();
                ClientIp(format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3]))
            }
            Some(IpAddr::V6(v6)) => ClientIp(v6.to_ipv4_mapped().map(|v4| v4.to_string()).unwrap_or_default()),
            Some(ip) => ClientIp(ip.to_string()),
            None => ClientIp("unknown".into()),
        }
    }
}

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let peer = parts.extensions.get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip());
        let header = state
            .config
            .client_ip_header
            .as_deref()
            .and_then(|name| parts.headers.get(name))
            .and_then(|v| v.to_str().ok());
        Ok(ClientIp::from_parts(peer, header, &state.config.trusted_proxies))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    #[test]
    fn trusts_headers_only_from_local_proxies() {
        assert_eq!(ClientIp::from_parts(ip("127.0.0.1"), Some("203.0.113.7"), &[]).0, "203.0.113.7");
        assert_eq!(ClientIp::from_parts(ip("::1"), Some("203.0.113.7"), &[]).0, "203.0.113.7");
        // A client sending the header itself is ignored.
        assert_eq!(ClientIp::from_parts(ip("198.51.100.1"), Some("203.0.113.7"), &[]).0, "198.51.100.1");
        // X-Forwarded-For: the proxy appends the real address.
        assert_eq!(ClientIp::from_parts(ip("127.0.0.1"), Some("10.9.9.9, 203.0.113.7"), &[]).0, "203.0.113.7");
        assert_eq!(ClientIp::from_parts(ip("127.0.0.1"), Some("garbage"), &[]).0, "127.0.0.1");
        assert_eq!(ClientIp::from_parts(ip("127.0.0.1"), None, &[]).0, "127.0.0.1");
        assert_eq!(ClientIp::from_parts(None, Some("203.0.113.7"), &[]).0, "unknown");
    }

    #[test]
    fn trusts_headers_from_trusted_proxies() {
        let trusted: Vec<TrustedProxy> =
            ["10.0.0.5", "192.168.1.0/24", "fd00::/64"].iter().map(|s| s.parse().unwrap()).collect();
        let from = |peer: &str| ClientIp::from_parts(ip(peer), Some("203.0.113.7"), &trusted).0;
        assert_eq!(from("10.0.0.5"), "203.0.113.7");
        assert_eq!(from("::ffff:10.0.0.5"), "203.0.113.7");
        assert_eq!(from("192.168.1.77"), "203.0.113.7");
        assert_eq!(from("fd00::1:2"), "203.0.113.7");
        // Anyone else's header is ignored.
        assert_eq!(from("10.0.0.6"), "10.0.0.6");
        assert_eq!(from("192.168.2.1"), "192.168.2.1");
        assert_eq!(from("fd00:0:0:1::1"), "fd00:0:0:1::/64");
    }

    #[test]
    fn parses_trusted_proxies() {
        let p = |s: &str| s.parse::<TrustedProxy>();
        assert_eq!(p("10.0.0.5").unwrap().to_string(), "10.0.0.5/32");
        assert_eq!(p(" 10.0.0.0/8 ").unwrap().to_string(), "10.0.0.0/8");
        assert_eq!(p("::ffff:10.0.0.5").unwrap().to_string(), "10.0.0.5/32");
        assert_eq!(p("fd00::/64").unwrap().to_string(), "fd00::/64");
        assert!(p("0.0.0.0/0").unwrap().contains("198.51.100.1".parse().unwrap()));
        assert!(p("10.0.0.0/33").is_err());
        assert!(p("cloudflared").is_err());
    }

    #[test]
    fn ipv6_counts_per_64() {
        let a = ClientIp::from_parts(ip("2001:db8:1:2:aaaa::1"), None, &[]);
        let b = ClientIp::from_parts(ip("2001:db8:1:2:bbbb::9"), None, &[]);
        assert_eq!(a, b);
        assert_eq!(a.0, "2001:db8:1:2::/64");
        assert_ne!(a, ClientIp::from_parts(ip("2001:db8:1:3::1"), None, &[]));
        assert_eq!(ClientIp::from_parts(ip("::ffff:192.0.2.1"), None, &[]).0, "192.0.2.1");
    }
}
