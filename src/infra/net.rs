//! Network helpers for extracting client IPs.

use axum::http::HeaderMap;
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};

/// Extract the client IP address from request headers or socket address.
///
/// Proxy headers are consulted only when `trust_proxy_headers` is set *and*
/// the socket peer is itself within a trusted network, so an arbitrary host
/// can never assert its own address.
///
/// Within `x-forwarded-for`, the chain is walked from the **right**. The header
/// grows left-to-right -- each proxy appends the address it received from -- so
/// only the rightmost entries are attested by infrastructure we trust, while
/// the leftmost is simply whatever the original client claimed. Reading the
/// leftmost entry would let any external client choose the address this service
/// attributes the request to, which in turn drives the admin IP allowlist, the
/// public-registration rate limiter, and audit records. Trusted hops are
/// skipped so a proxy chain resolves to the first address no trusted proxy
/// vouched for; if every hop is trusted there is no external client and the
/// socket peer is used.
pub fn extract_client_ip(
    headers: &HeaderMap,
    remote_addr: SocketAddr,
    trust_proxy_headers: bool,
) -> Option<IpAddr> {
    if trust_proxy_headers && is_remote_addr_trusted(remote_addr.ip()) {
        if let Some(ip) = extract_forwarded_ip(headers) {
            return Some(ip);
        }
    }

    Some(remote_addr.ip())
}

fn is_remote_addr_trusted(ip: IpAddr) -> bool {
    trusted_proxy_networks()
        .iter()
        .any(|network| network.contains(&ip))
}

fn trusted_proxy_networks() -> Vec<IpNet> {
    let configured = std::env::var("TRUST_PROXY_ALLOWLIST").ok().map(|raw| {
        raw.split(',')
            .filter_map(|token| parse_proxy_entry(token.trim()))
            .collect::<Vec<_>>()
    });

    match configured {
        Some(networks) if !networks.is_empty() => networks,
        _ => default_trusted_proxy_networks(),
    }
}

fn default_trusted_proxy_networks() -> Vec<IpNet> {
    [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    ]
    .into_iter()
    .filter_map(|net| net.parse::<IpNet>().ok())
    .collect()
}

fn parse_proxy_entry(entry: &str) -> Option<IpNet> {
    if entry.is_empty() {
        return None;
    }

    if let Ok(network) = entry.parse::<IpNet>() {
        return Some(network);
    }

    let parsed_ip = entry.parse::<IpAddr>().ok()?;
    let cidr = match parsed_ip {
        IpAddr::V4(addr) => IpNet::new(IpAddr::V4(addr), 32).ok()?,
        IpAddr::V6(addr) => IpNet::new(IpAddr::V6(addr), 128).ok()?,
    };

    Some(cidr)
}

fn extract_forwarded_ip(headers: &HeaderMap) -> Option<IpAddr> {
    // Walk right-to-left and return the first hop no trusted proxy vouched for.
    // Entries to the left of it are client-supplied and must not be believed.
    // `get_all` because a chain may append separate header lines rather than
    // extending one; joining them preserves the overall left-to-right order.
    let forwarded_for: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    if !forwarded_for.is_empty() {
        let chain = forwarded_for.join(",");
        if let Some(ip) = chain
            .split(',')
            .filter_map(|entry| parse_ip(entry.trim()))
            .rev()
            .find(|ip| !is_remote_addr_trusted(*ip))
        {
            return Some(ip);
        }
        // Every hop was trusted: no external client to attribute this to.
        return None;
    }

    // Single-valued headers set by the proxy. Take the *last* value, since a
    // client-supplied one arrives first and a proxy that appends rather than
    // replaces would leave the trustworthy value at the end.
    if let Some(ip) = headers
        .get_all("x-real-ip")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|v| parse_ip(v.trim()))
        .next_back()
    {
        return Some(ip);
    }

    if let Some(forwarded) = headers
        .get_all("forwarded")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .next_back()
    {
        for part in forwarded.split(';') {
            let part = part.trim();
            if let Some(value) = part.strip_prefix("for=") {
                if let Some(ip) = parse_ip(value) {
                    return Some(ip);
                }
            }
        }
    }

    None
}

fn parse_ip(value: &str) -> Option<IpAddr> {
    let trimmed = value.trim().trim_matches('"');

    if let Ok(sock) = trimmed.parse::<SocketAddr>() {
        return Some(sock.ip());
    }

    let trimmed = trimmed.trim_matches('[').trim_matches(']');
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Some(ip);
    }

    if let Some((ip_part, port_part)) = trimmed.rsplit_once(':') {
        if port_part.parse::<u16>().is_ok() {
            if let Ok(ip) = ip_part.parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn parses_forwarded_for_ipv4() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.10, 198.51.100.1"),
        );
        let ip = extract_forwarded_ip(&headers).unwrap();
        // The rightmost hop, 198.51.100.1, is the address a trusted proxy
        // actually received the request from. 203.0.113.10 to its left is only
        // what that host claimed, and is not evidence of anything.
        assert_eq!(ip, "198.51.100.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parses_forwarded_for_ipv6_bracketed() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "forwarded",
            HeaderValue::from_static("for=\"[2001:db8::1]:8443\";proto=https"),
        );
        let ip = extract_forwarded_ip(&headers).unwrap();
        assert_eq!(ip, "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    /// `X-Forwarded-For` grows left-to-right: each proxy *appends* the address
    /// it received from, so the leftmost entry is whatever the client claimed
    /// and only the rightmost entries are attested by trusted infrastructure.
    ///
    /// Trusting the leftmost entry lets any external client choose the IP this
    /// service attributes the request to -- which drives the admin IP
    /// allowlist, the registration rate limiter, and audit records.
    #[test]
    fn spoofed_leading_forwarded_entry_cannot_choose_the_client_ip() {
        let mut headers = HeaderMap::new();
        // Attacker at 203.0.113.9 sent `X-Forwarded-For: 10.0.0.1`;
        // the trusted ingress appended the real peer.
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("10.0.0.1, 203.0.113.9"),
        );
        let ingress = SocketAddr::from(([10, 0, 0, 5], 443));

        let ip = extract_client_ip(&headers, ingress, true).unwrap();

        assert_eq!(
            ip,
            "203.0.113.9".parse::<IpAddr>().unwrap(),
            "must attribute the request to the real peer, not the spoofed hop"
        );
    }

    /// A chain of trusted proxies is skipped over to reach the first address
    /// that trusted infrastructure did not vouch for.
    #[test]
    fn trusted_proxy_chain_resolves_to_the_first_untrusted_hop() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.10, 10.0.0.7, 10.0.0.8"),
        );
        let ingress = SocketAddr::from(([10, 0, 0, 9], 443));

        let ip = extract_client_ip(&headers, ingress, true).unwrap();

        assert_eq!(ip, "203.0.113.10".parse::<IpAddr>().unwrap());
    }

    /// Every hop internal: there is no external client, so fall back to the
    /// socket peer rather than inventing one from the header.
    #[test]
    fn all_trusted_forwarded_chain_falls_back_to_socket_peer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("10.0.0.1, 10.0.0.2"),
        );
        let ingress = SocketAddr::from(([10, 0, 0, 5], 443));

        let ip = extract_client_ip(&headers, ingress, true).unwrap();

        assert_eq!(ip, "10.0.0.5".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn extract_client_ip_ignores_proxy_headers_without_trust() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.10, 198.51.100.1"),
        );

        let remote_addr = SocketAddr::from(([198, 51, 100, 2], 12345));
        let ip = extract_client_ip(&headers, remote_addr, true).unwrap();

        assert_eq!(ip, "198.51.100.2".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn extract_client_ip_uses_proxy_headers_for_trusted_remote() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.10, 198.51.100.1"),
        );

        let remote_addr = SocketAddr::from(([127, 0, 0, 1], 12345));
        let ip = extract_client_ip(&headers, remote_addr, true).unwrap();

        // Proxy headers are consulted (the peer is trusted), but the value
        // taken is the rightmost untrusted hop. This assertion previously
        // expected 203.0.113.10 -- the leftmost, client-supplied entry --
        // which is precisely the value an attacker gets to choose.
        assert_eq!(ip, "198.51.100.1".parse::<IpAddr>().unwrap());
    }
}
