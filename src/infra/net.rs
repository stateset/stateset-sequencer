//! Network helpers for extracting client IPs.

use axum::http::HeaderMap;
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};

/// Extract the client IP address from request headers or socket address.
///
/// When `trust_proxy_headers` is true, uses common proxy headers in priority order:
/// `x-forwarded-for`, `x-real-ip`, and `forwarded`.
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
        IpAddr::V4(addr) => IpNet::new_v4(addr, 32).ok()?,
        IpAddr::V6(addr) => IpNet::new_v6(addr, 128).ok()?,
    };

    Some(cidr)
}

fn extract_forwarded_ip(headers: &HeaderMap) -> Option<IpAddr> {
    if let Some(forwarded) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = forwarded.split(',').next() {
            if let Some(ip) = parse_ip(first.trim()) {
                return Some(ip);
            }
        }
    }

    if let Some(real_ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        if let Some(ip) = parse_ip(real_ip.trim()) {
            return Some(ip);
        }
    }

    if let Some(forwarded) = headers.get("forwarded").and_then(|v| v.to_str().ok()) {
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
        assert_eq!(ip, "203.0.113.10".parse::<IpAddr>().unwrap());
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

        assert_eq!(ip, "203.0.113.10".parse::<IpAddr>().unwrap());
    }
}
