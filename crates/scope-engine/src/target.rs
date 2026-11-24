use std::net::{IpAddr, Ipv6Addr};

use domain::TargetKind;
use ipnet::IpNet;
use url::{Host, Url};

#[derive(Debug, Eq, PartialEq)]
pub(super) enum Target {
    Domain(String),
    Url(WebTarget),
    Network(IpNet),
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct WebTarget {
    url: Url,
    host: Box<Target>,
}

#[derive(Debug)]
pub(super) enum Matcher {
    Domain(String),
    Wildcard(String),
    UrlPrefix(WebTarget),
    Network(IpNet),
}

impl Target {
    pub(super) fn parse(raw: &str) -> Option<Self> {
        if raw.contains("://") {
            return WebTarget::parse(raw).map(Self::Url);
        }
        if raw.contains('/') {
            return network(raw).map(Self::Network);
        }
        host(raw)
    }

    fn host(&self) -> &Self {
        match self {
            Self::Url(web) => &web.host,
            _ => self,
        }
    }

    pub(super) fn canonical(&self) -> String {
        match self {
            Self::Domain(name) => name.clone(),
            Self::Url(web) => web.url.to_string(),
            Self::Network(net) if net.prefix_len() == net.max_prefix_len() => {
                net.addr().to_string()
            }
            Self::Network(net) => net.to_string(),
        }
    }
}

impl WebTarget {
    fn parse(raw: &str) -> Option<Self> {
        // Validate the spelling before WHATWG URL normalization can rewrite it.
        if raw.contains(['#', '\\']) || raw.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return None;
        }
        let (scheme, rest) = raw.split_once("://")?;
        if !scheme.eq_ignore_ascii_case("https") && !scheme.eq_ignore_ascii_case("http") {
            return None;
        }
        let boundary = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, suffix) = rest.split_at(boundary);
        let path = suffix.split('?').next()?;
        if path.contains("//")
            || path.split('/').any(|segment| matches!(segment, "." | ".."))
            || !path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/-._~".contains(&b))
        {
            return None;
        }
        let (raw_host, raw_port) = if let Some(bracketed) = authority.strip_prefix('[') {
            bracketed.split_once(']')?
        } else {
            match authority.split_once(':') {
                Some((host, _)) => (host, &authority[host.len()..]),
                None => (authority, ""),
            }
        };
        if !raw_port.is_empty() {
            let port = raw_port.strip_prefix(':')?;
            if !port.bytes().all(|b| b.is_ascii_digit()) || port.parse::<u16>().ok()? == 0 {
                return None;
            }
        }
        let host = host(raw_host)?;
        let mut url = Url::parse(raw).ok()?;
        let parsed_host = match url.host()? {
            Host::Domain(value) => Target::Domain(domain(value)?),
            Host::Ipv4(value) => Target::Network(IpAddr::V4(value).into()),
            Host::Ipv6(value) => Target::Network(IpAddr::V6(value).to_canonical().into()),
        };
        if parsed_host != host {
            return None;
        }
        url.set_host(Some(&match &host {
            Target::Network(net) if net.addr().is_ipv6() => format!("[{}]", net.addr()),
            _ => host.canonical(),
        }))
        .ok()?;
        Some(Self {
            url,
            host: Box::new(host),
        })
    }
}

impl Matcher {
    pub(super) fn compile(kind: TargetKind, raw: &str) -> Option<Self> {
        match kind {
            TargetKind::Domain => domain(raw).map(Self::Domain),
            TargetKind::Wildcard => domain(raw.strip_prefix("*.")?).map(Self::Wildcard),
            TargetKind::UrlPrefix => {
                let web = WebTarget::parse(raw)?;
                web.url.query().is_none().then_some(Self::UrlPrefix(web))
            }
            TargetKind::Ip => Some(Self::Network(
                raw.parse::<IpAddr>().ok()?.to_canonical().into(),
            )),
            TargetKind::Cidr => network(raw).map(Self::Network),
        }
    }

    pub(super) fn matches(&self, target: &Target, is_deny: bool) -> bool {
        match (self, target.host()) {
            (Self::Domain(rule), Target::Domain(host)) => rule == host,
            (Self::Wildcard(rule), Target::Domain(host)) => host
                .strip_suffix(rule)
                .is_some_and(|prefix| prefix.ends_with('.')),
            (Self::Network(rule), Target::Network(net)) => {
                rule.contains(net) || (is_deny && net.contains(rule))
            }
            (Self::UrlPrefix(rule), _) => match target {
                Target::Url(web) => {
                    rule.host == web.host
                        && rule.url.scheme() == web.url.scheme()
                        && rule.url.port() == web.url.port()
                        && path_prefix(rule.url.path(), web.url.path())
                }
                _ => false,
            },
            _ => false,
        }
    }
}

fn path_prefix(prefix: &str, path: &str) -> bool {
    path.strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || prefix.ends_with('/') || rest.starts_with('/'))
}

fn host(raw: &str) -> Option<Target> {
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Some(Target::Network(ip.to_canonical().into()));
    }
    domain(raw).map(Target::Domain)
}

fn domain(raw: &str) -> Option<String> {
    let unrooted = raw
        .strip_suffix(['.', '\u{3002}', '\u{ff0e}', '\u{ff61}'])
        .unwrap_or(raw);
    let name = idna::domain_to_ascii_strict(unrooted).ok()?;
    if name.len() > 253
        || name.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return None;
    }
    // A numeric final label may denote legacy IPv4 syntax in HTTP clients.
    let last = name.rsplit('.').next()?;
    if last.bytes().all(|b| b.is_ascii_digit())
        || last
            .strip_prefix("0x")
            .is_some_and(|value| value.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return None;
    }
    Some(name)
}

fn network(raw: &str) -> Option<IpNet> {
    let parsed: IpNet = raw.parse().ok()?;
    if parsed.addr() != parsed.network() {
        return None;
    }
    match parsed {
        IpNet::V6(v6) => {
            if let Some(ip) = v6.addr().to_ipv4_mapped() {
                let len = v6.prefix_len().checked_sub(96)?;
                return IpNet::new(ip.into(), len).ok();
            }
            // A supernet spanning the mapped address space has two address families.
            let mapped = Ipv6Addr::from(0x0000_0000_0000_0000_0000_ffff_0000_0000_u128);
            (!v6.contains(&mapped)).then_some(parsed)
        }
        _ => Some(parsed),
    }
}
