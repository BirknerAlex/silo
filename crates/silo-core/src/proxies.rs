//! Which peers may vouch for a client address via `X-Forwarded-For`.

use std::net::IpAddr;
use std::str::FromStr;

/// A set of IP networks, parsed from `a.b.c.d` / `a.b.c.d/len` / IPv6
/// equivalents. A bare address is a single-host network.
#[derive(Debug, Clone, Default)]
pub struct TrustedProxies {
    nets: Vec<(IpAddr, u8)>,
}

impl TrustedProxies {
    pub fn parse<S: AsRef<str>>(entries: &[S]) -> anyhow::Result<Self> {
        let mut nets = Vec::with_capacity(entries.len());
        for entry in entries {
            let entry = entry.as_ref().trim();
            let (addr, len) = match entry.split_once('/') {
                Some((a, l)) => (a, Some(l)),
                None => (entry, None),
            };
            let ip = IpAddr::from_str(addr)
                .map_err(|_| anyhow::anyhow!("`{entry}` is not an IP address or CIDR range"))?;
            let max = if ip.is_ipv4() { 32 } else { 128 };
            let len = match len {
                Some(l) => l
                    .parse::<u8>()
                    .ok()
                    .filter(|l| *l <= max)
                    .ok_or_else(|| anyhow::anyhow!("`{entry}` has an invalid prefix length"))?,
                None => max,
            };
            nets.push((ip, len));
        }
        Ok(Self { nets })
    }

    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = unmap(ip);
        self.nets.iter().any(|(net, len)| match (unmap(*net), ip) {
            (IpAddr::V4(n), IpAddr::V4(i)) => {
                prefix_eq(&n.octets(), &i.octets(), v4_len(*net, *len))
            }
            (IpAddr::V6(n), IpAddr::V6(i)) => prefix_eq(&n.octets(), &i.octets(), *len),
            _ => false,
        })
    }

    /// The client address for a request from `peer` carrying the given
    /// `X-Forwarded-For` values. Only a trusted peer is believed; the chain
    /// is read right to left, skipping further trusted hops, and the first
    /// address that is not trusted is the client. `None` means "keep the
    /// peer address".
    pub fn client_ip<'a>(
        &self,
        peer: IpAddr,
        forwarded_for: impl Iterator<Item = &'a str>,
    ) -> Option<IpAddr> {
        if !self.contains(peer) {
            return None;
        }
        let chain: Vec<&str> = forwarded_for.flat_map(|v| v.split(',')).collect();
        for hop in chain.iter().rev() {
            // An unparseable hop ends the chain we can vouch for.
            let ip = IpAddr::from_str(hop.trim()).ok()?;
            if !self.contains(ip) {
                return Some(ip);
            }
        }
        None
    }
}

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

/// Prefix length in v4 terms for a network that may have been written as a
/// v4-mapped v6 range.
fn v4_len(original: IpAddr, len: u8) -> u8 {
    match original {
        IpAddr::V6(_) => len.saturating_sub(96),
        IpAddr::V4(_) => len,
    }
}

fn prefix_eq(a: &[u8], b: &[u8], bits: u8) -> bool {
    let full = (bits / 8) as usize;
    if a[..full] != b[..full] {
        return false;
    }
    let rem = bits % 8;
    rem == 0 || (a[full] ^ b[full]) >> (8 - rem) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn cidr_and_single_hosts() {
        let t = TrustedProxies::parse(&["10.0.0.0/8", "192.168.1.5", "fd00::/8"]).unwrap();
        assert!(t.contains(ip("10.200.1.1")));
        assert!(t.contains(ip("192.168.1.5")));
        assert!(!t.contains(ip("192.168.1.6")));
        assert!(t.contains(ip("fd12::1")));
        assert!(!t.contains(ip("2001:db8::1")));
        assert!(t.contains(ip("::ffff:10.1.2.3")));
    }

    #[test]
    fn rejects_garbage() {
        assert!(TrustedProxies::parse(&["nope"]).is_err());
        assert!(TrustedProxies::parse(&["10.0.0.0/33"]).is_err());
    }

    #[test]
    fn untrusted_peer_cannot_spoof() {
        let t = TrustedProxies::parse(&["10.0.0.0/8"]).unwrap();
        assert_eq!(
            t.client_ip(ip("203.0.113.9"), ["1.2.3.4"].into_iter()),
            None
        );
    }

    #[test]
    fn rightmost_untrusted_hop_wins() {
        let t = TrustedProxies::parse(&["10.0.0.0/8"]).unwrap();
        // A client-supplied "6.6.6.6" sits left of the address the proxy saw.
        let got = t.client_ip(
            ip("10.0.0.1"),
            ["6.6.6.6, 198.51.100.7, 10.0.0.2"].into_iter(),
        );
        assert_eq!(got, Some(ip("198.51.100.7")));
        assert_eq!(t.client_ip(ip("10.0.0.1"), std::iter::empty()), None);
        assert_eq!(t.client_ip(ip("10.0.0.1"), ["garbage"].into_iter()), None);
        // An empty hop (a non-text header field) ends the walk too.
        assert_eq!(
            t.client_ip(ip("10.0.0.1"), ["6.6.6.6", ""].into_iter()),
            None
        );
    }

    #[test]
    fn all_trusted_chain_keeps_the_peer() {
        let t = TrustedProxies::parse(&["10.0.0.0/8"]).unwrap();
        assert_eq!(
            t.client_ip(ip("10.0.0.1"), ["10.1.1.1, 10.2.2.2"].into_iter()),
            None
        );
    }
}
