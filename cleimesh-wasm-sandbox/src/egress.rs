//! Network egress for sandboxed tools, decided on the connection rather than
//! on the argument (S19).
//!
//! A tool never opens a socket. It asks the host to fetch a URL, and the host
//! makes every decision on what is actually reached:
//!
//! - each hop, the first request and every redirect, must name a granted host;
//!   redirects are followed by the host, never by a client the tool controls;
//! - the name is resolved once per hop and the connection goes to that
//!   address, so a second lookup cannot rebind it;
//! - private, loopback, link-local and other non-public addresses are refused
//!   unless the grant allows them, whatever name led there;
//! - an IP literal, in any notation the URL parser accepts (`0x7f.1`,
//!   `2130706433`, `[::ffff:127.0.0.1]`), is only reached if that address is
//!   itself granted.
//!
//! Every hop is recorded, refused or not, for the receipt.
//!
//! Not covered: several names served from one address (a CDN). The grant
//! fixes the name the request carries and the address it reaches, not which
//! site the server picks behind that address.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use url::{Host, Url};

/// Turns a name into addresses. The default asks the system resolver;
/// tests swap in one that answers differently on each call.
pub type Resolver = Arc<dyn Fn(&str, u16) -> io::Result<Vec<IpAddr>> + Send + Sync>;

/// What a tool may reach.
#[derive(Clone)]
pub struct Egress {
    /// Granted hosts: a name (compared without case or a trailing dot) or an
    /// IP literal, either alone (any port) or with `:port` (`[v6]:port`).
    pub hosts: Vec<String>,
    /// Reach private, loopback and link-local addresses. Off unless the grant
    /// says so: it is what turns a fetch tool into a probe of the network the
    /// node sits in (cloud metadata at 169.254.169.254, admin panels).
    pub allow_private: bool,
    pub max_redirects: usize,
    pub max_body_bytes: usize,
    pub timeout: Duration,
    pub resolver: Resolver,
}

impl std::fmt::Debug for Egress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Egress")
            .field("hosts", &self.hosts)
            .field("allow_private", &self.allow_private)
            .field("max_redirects", &self.max_redirects)
            .field("max_body_bytes", &self.max_body_bytes)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl Egress {
    pub fn new(hosts: Vec<String>) -> Self {
        Self {
            hosts,
            allow_private: false,
            max_redirects: 5,
            max_body_bytes: 1 << 20,
            timeout: Duration::from_secs(10),
            resolver: Arc::new(system_resolve),
        }
    }
}

fn system_resolve(host: &str, port: u16) -> io::Result<Vec<IpAddr>> {
    Ok((host, port).to_socket_addrs()?.map(|a| a.ip()).collect())
}

/// What the tool asks for.
#[derive(Debug, Clone, Deserialize)]
pub struct Request {
    #[serde(default = "get")]
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub body: Option<String>,
}

fn get() -> String {
    "GET".into()
}

/// What the tool gets back.
#[derive(Debug, Clone, Serialize)]
pub struct Response {
    pub status: u16,
    pub url: String,
    pub body: String,
}

/// One hop, as the receipt states it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Hop {
    pub url: String,
    /// The address connected to; `None` when refused before connecting.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<SocketAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refused: Option<String>,
}

/// A refusal or failure, with the hops made up to it.
#[derive(Debug)]
pub struct Refused {
    pub reason: String,
    pub hops: Vec<Hop>,
}

/// Where one hop may connect, once its URL passed the grant.
#[derive(Debug, PartialEq, Eq)]
pub struct Target {
    pub url: Url,
    /// The name to pin, or `None` for an IP literal.
    pub name: Option<String>,
    pub addr: SocketAddr,
}

/// Headers the tool may not set: they would let it pick a site behind the
/// granted address other than the one the URL names, or smuggle a second
/// request through the first.
const FORBIDDEN_HEADERS: &[&str] = &["host", "connection", "transfer-encoding", "content-length", "upgrade", "proxy-authorization", "te", "trailer"];

/// A granted host entry as `(host, port)`: the host lowercased, without a
/// trailing dot or IPv6 brackets; `None` for the port means any port.
/// `None` overall for an entry that is not a bare name or address with an
/// optional port (a URL, credentials, a path, a wildcard).
pub fn parse_grant_host(entry: &str) -> Option<(String, Option<u16>)> {
    if entry.is_empty() || entry.contains(['/', '@', '*', '?', '#', ' ']) {
        return None;
    }
    let (host, port) = if let Some(rest) = entry.strip_prefix('[') {
        let (v6, after) = rest.split_once(']')?;
        v6.parse::<Ipv6Addr>().ok()?;
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':')?.parse::<u16>().ok()?),
        };
        (v6.to_string(), port)
    } else if entry.parse::<IpAddr>().is_ok() {
        (entry.to_string(), None)
    } else if let Some((host, port)) = entry.rsplit_once(':') {
        (host.to_string(), Some(port.parse::<u16>().ok()?))
    } else {
        (entry.to_string(), None)
    };
    if host.is_empty() || host.contains(':') && host.parse::<Ipv6Addr>().is_err() {
        return None;
    }
    Some((host.trim_end_matches('.').to_ascii_lowercase(), port))
}

/// Whether grant entry `parent` covers `child`: same host, and the parent
/// either allows any port or the same one. What narrowing checks.
pub fn grant_covers(parent: &str, child: &str) -> bool {
    match (parse_grant_host(parent), parse_grant_host(child)) {
        (Some((ph, pp)), Some((ch, cp))) => ph == ch && (pp.is_none() || pp == cp),
        _ => false,
    }
}

impl Egress {
    fn granted(&self, host: &str, port: u16) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.hosts.iter().filter_map(|h| parse_grant_host(h)).any(|(h, p)| h == host && p.is_none_or(|p| p == port))
    }

    fn address_allowed(&self, ip: IpAddr) -> Result<(), String> {
        if self.allow_private || is_public(ip) {
            Ok(())
        } else {
            Err(format!("{ip} is not a public address"))
        }
    }

    /// Checks one hop's URL against the grant and resolves it, once.
    pub fn target(&self, raw: &str) -> Result<Target, String> {
        let url = Url::parse(raw).map_err(|e| format!("not a URL: {e}"))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(format!("scheme {} is not http or https", url.scheme()));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err("credentials in the URL are refused".into());
        }
        let port = url.port_or_known_default().ok_or("no port")?;
        let (name, ip) = match url.host() {
            None => return Err("no host".into()),
            Some(Host::Ipv4(v4)) => (None, IpAddr::V4(v4)),
            Some(Host::Ipv6(v6)) => (None, IpAddr::V6(v6)),
            Some(Host::Domain(d)) => (Some(d.to_ascii_lowercase()), IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        };
        match name {
            None => {
                // The parser has already normalised alternative notations, so
                // this compares the address the socket would reach.
                let granted = self.hosts.iter().filter_map(|h| parse_grant_host(h)).any(|(h, p)| h.parse::<IpAddr>().ok() == Some(ip) && p.is_none_or(|p| p == port));
                if !granted {
                    return Err(format!("address {} is not a granted host", SocketAddr::new(ip, port)));
                }
                self.address_allowed(ip)?;
                Ok(Target { url, name: None, addr: SocketAddr::new(ip, port) })
            }
            Some(name) => {
                if !self.granted(&name, port) {
                    let any_port = self.granted(&name, 0) || self.hosts.iter().filter_map(|h| parse_grant_host(h)).any(|(h, _)| h == name.trim_end_matches('.'));
                    return Err(if any_port { format!("host {name} port {port} is not granted") } else { format!("host {name} is not granted") });
                }
                let addrs = (self.resolver)(&name, port).map_err(|e| format!("cannot resolve {name}: {e}"))?;
                let first = *addrs.first().ok_or_else(|| format!("{name} has no address"))?;
                // Every answer must pass, not just the one used: a name that
                // also points inside the network is not one to trust.
                for ip in &addrs {
                    self.address_allowed(*ip).map_err(|e| format!("{name} resolves to {e}"))?;
                }
                Ok(Target { url, name: Some(name), addr: SocketAddr::new(first, port) })
            }
        }
    }

    /// Fetches `req`, following redirects itself and checking each hop.
    pub async fn fetch(&self, req: &Request) -> Result<(Response, Vec<Hop>), Refused> {
        let mut hops = Vec::new();
        let refuse = |reason: String, hops: Vec<Hop>| Refused { reason, hops };
        if let Some((h, _)) = req.headers.iter().find(|(h, _)| FORBIDDEN_HEADERS.contains(&h.to_ascii_lowercase().as_str())) {
            return Err(refuse(format!("header {h} may not be set by the tool"), hops));
        }
        let mut method = reqwest::Method::from_bytes(req.method.to_ascii_uppercase().as_bytes())
            .map_err(|_| refuse(format!("bad method {}", req.method), Vec::new()))?;
        let mut body = req.body.clone();
        let mut url = req.url.clone();

        for _ in 0..=self.max_redirects {
            let target = match self.target(&url) {
                Ok(t) => t,
                Err(reason) => {
                    hops.push(Hop { url, addr: None, status: None, refused: Some(reason.clone()) });
                    return Err(refuse(reason, hops));
                }
            };
            let mut client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .timeout(self.timeout);
            if let Some(name) = &target.name {
                client = client.resolve(name, target.addr);
            }
            let client = client.build().map_err(|e| refuse(format!("client: {e}"), hops.clone()))?;
            let mut request = client.request(method.clone(), target.url.clone());
            for (h, v) in &req.headers {
                request = request.header(h, v);
            }
            if let Some(b) = &body {
                request = request.body(b.clone());
            }
            let response = match request.send().await {
                Ok(r) => r,
                Err(e) => {
                    let reason = format!("request to {} failed: {e}", target.url);
                    hops.push(Hop { url: target.url.to_string(), addr: Some(target.addr), status: None, refused: Some(reason.clone()) });
                    return Err(refuse(reason, hops));
                }
            };
            let status = response.status();
            hops.push(Hop { url: target.url.to_string(), addr: Some(target.addr), status: Some(status.as_u16()), refused: None });

            if status.is_redirection() {
                if let Some(location) = response.headers().get(reqwest::header::LOCATION) {
                    let location = location.to_str().map_err(|_| refuse("redirect location is not text".into(), hops.clone()))?;
                    url = target.url.join(location).map_err(|e| refuse(format!("bad redirect location: {e}"), hops.clone()))?.to_string();
                    // 301/302/303 turn into a GET without the body (RFC 9110 15.4).
                    if !matches!(status.as_u16(), 307 | 308) {
                        method = reqwest::Method::GET;
                        body = None;
                    }
                    continue;
                }
            }

            let mut out = Vec::new();
            let mut response = response;
            loop {
                match response.chunk().await {
                    Ok(Some(chunk)) => {
                        if out.len() + chunk.len() > self.max_body_bytes {
                            return Err(refuse(format!("response body over {} bytes", self.max_body_bytes), hops));
                        }
                        out.extend_from_slice(&chunk);
                    }
                    Ok(None) => break,
                    Err(e) => return Err(refuse(format!("reading the response failed: {e}"), hops)),
                }
            }
            let body = String::from_utf8_lossy(&out).into_owned();
            return Ok((Response { status: status.as_u16(), url: target.url.to_string(), body }, hops));
        }
        Err(refuse(format!("more than {} redirects", self.max_redirects), hops))
    }
}

/// Adds `cleimesh.http_fetch(ptr, len) -> u64` to `linker`, guest ABI v1:
/// the guest passes a JSON [`Request`]; the host answers `{"ok": Response}`
/// or `{"error": reason}` in a buffer from the guest's `cleimesh_alloc`,
/// packed as `ptr << 32 | len`. Calls without an egress grant are refused,
/// so the function can sit in every module's linker.
pub fn add_to_linker(linker: &mut wasmtime::Linker<crate::SandboxData>) -> anyhow::Result<()> {
    use wasmtime::{Caller, Extern};
    linker
        .func_wrap_async("cleimesh", "http_fetch", |mut caller: Caller<'_, crate::SandboxData>, (ptr, len): (u32, u32)| {
            Box::new(async move {
                let Some(Extern::Memory(memory)) = caller.get_export("memory") else {
                    wasmtime::bail!("module does not export 'memory'");
                };
                let mut raw = vec![0u8; len as usize];
                memory.read(&caller, ptr as usize, &mut raw)?;
                let reply = match (caller.data().config.egress.clone(), serde_json::from_slice::<Request>(&raw)) {
                    (None, _) => serde_json::json!({"error": "network not granted"}),
                    (Some(_), Err(e)) => serde_json::json!({"error": format!("bad request: {e}")}),
                    (Some(egress), Ok(request)) => match egress.fetch(&request).await {
                        Ok((response, hops)) => {
                            caller.data_mut().fs.note_egress(hops);
                            serde_json::json!({"ok": response})
                        }
                        Err(refused) => {
                            caller.data_mut().fs.note_egress(refused.hops);
                            serde_json::json!({"error": refused.reason})
                        }
                    },
                };
                let out = serde_json::to_vec(&reply)?;
                let Some(Extern::Func(alloc)) = caller.get_export("cleimesh_alloc") else {
                    wasmtime::bail!("module does not export 'cleimesh_alloc'");
                };
                let alloc = alloc.typed::<u32, u32>(&caller)?;
                let out_ptr = alloc.call_async(&mut caller, out.len() as u32).await?;
                memory.write(&mut caller, out_ptr as usize, &out)?;
                Ok(((out_ptr as u64) << 32) | out.len() as u64)
            })
        })
        .map_err(anyhow::Error::from)?;
    Ok(())
}

/// Whether `ip` is routable on the public internet. Conservative: anything
/// special-purpose counts as not public.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_v4(v4);
            }
            let s = v6.segments();
            let nat64 = s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0];
            if nat64 {
                let o = v6.octets();
                return is_public_v4(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
            }
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // unique local
                || (s[0] & 0xffc0) == 0xfe80 // link-local
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                || s[0..6] == [0, 0, 0, 0, 0, 0] // IPv4-compatible, deprecated
                || v6 == Ipv6Addr::LOCALHOST)
        }
    }
}

fn is_public_v4(v4: Ipv4Addr) -> bool {
    let [a, b, c, _] = v4.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..128).contains(&b)) // shared address space (CGNAT)
        || (a == 169 && b == 254) // link-local, cloud metadata
        || (a == 172 && (16..32).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn fixed(ip: &str) -> Resolver {
        let ip: IpAddr = ip.parse().unwrap();
        Arc::new(move |_, _| Ok(vec![ip]))
    }

    fn egress(hosts: &[&str], resolver: Resolver) -> Egress {
        Egress { resolver, ..Egress::new(hosts.iter().map(|h| h.to_string()).collect()) }
    }

    #[test]
    fn a_granted_name_resolving_to_a_public_address_passes() {
        let e = egress(&["api.example.com"], fixed("93.184.216.34"));
        let t = e.target("https://API.example.com./v1?q=1").unwrap();
        assert_eq!(t.addr, "93.184.216.34:443".parse().unwrap());
        assert_eq!(t.name.as_deref(), Some("api.example.com."));
    }

    #[test]
    fn a_name_not_granted_is_refused_before_any_lookup() {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let e = egress(&["api.example.com"], Arc::new(move |_, _| {
            seen.fetch_add(1, Ordering::SeqCst);
            Ok(vec!["93.184.216.34".parse().unwrap()])
        }));
        for url in ["https://evil.example/", "https://api.example.com.evil.example/", "https://api.example.com@evil.example/"] {
            assert!(e.target(url).is_err(), "{url}");
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_granted_name_pointing_inside_the_network_is_refused() {
        for inside in ["169.254.169.254", "127.0.0.1", "10.0.0.5", "192.168.1.1", "::1", "fd00::1", "::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe"] {
            let e = egress(&["api.example.com"], fixed(inside));
            let err = e.target("http://api.example.com/").unwrap_err();
            assert!(err.contains("not a public address"), "{inside}: {err}");
        }
    }

    #[test]
    fn one_private_answer_among_public_ones_refuses_the_name() {
        let e = egress(&["api.example.com"], Arc::new(|_, _| Ok(vec!["93.184.216.34".parse().unwrap(), "169.254.169.254".parse().unwrap()])));
        assert!(e.target("http://api.example.com/").is_err());
    }

    #[test]
    fn ip_literals_in_any_notation_are_refused_unless_granted() {
        let e = egress(&["api.example.com"], fixed("93.184.216.34"));
        for url in [
            "http://127.0.0.1/",
            "http://0x7f.1/",
            "http://2130706433/",
            "http://0177.0.0.1/",
            "http://127.1/",
            "http://[::ffff:127.0.0.1]/",
            "http://169.254.169.254/latest/meta-data/",
            "http://0xa9fea9fe/",
            "http://93.184.216.34/",
        ] {
            let err = e.target(url).unwrap_err();
            assert!(err.contains("is not a granted host"), "{url}: {err}");
        }
    }

    #[test]
    fn a_granted_literal_still_needs_a_public_address() {
        let e = egress(&["127.0.0.1", "93.184.216.34"], fixed("93.184.216.34"));
        assert!(e.target("http://0x7f.1/").unwrap_err().contains("not a public address"));
        assert_eq!(e.target("http://93.184.216.34:8080/").unwrap().addr, "93.184.216.34:8080".parse().unwrap());
    }

    #[test]
    fn other_schemes_and_credentials_are_refused() {
        let e = egress(&["api.example.com"], fixed("93.184.216.34"));
        for url in ["file:///etc/passwd", "ftp://api.example.com/", "gopher://api.example.com/", "https://user:pw@api.example.com/"] {
            assert!(e.target(url).is_err(), "{url}");
        }
    }

    #[test]
    fn a_granted_port_pins_the_service() {
        let e = egress(&["api.example.com:8443", "127.0.0.1:9000", "[::1]:9001"], fixed("93.184.216.34"));
        assert_eq!(e.target("https://api.example.com:8443/").unwrap().addr.port(), 8443);
        assert!(e.target("https://api.example.com/").unwrap_err().contains("port 443 is not granted"));
        let private = Egress { allow_private: true, ..e };
        assert!(private.target("http://127.0.0.1:9000/").is_ok());
        assert!(private.target("http://127.0.0.1:9002/").unwrap_err().contains("127.0.0.1:9002 is not a granted host"));
        assert!(private.target("http://[::1]:9001/").is_ok());
    }

    #[test]
    fn grant_entries_parse_and_narrow() {
        assert_eq!(parse_grant_host("API.Example.com."), Some(("api.example.com".into(), None)));
        assert_eq!(parse_grant_host("api.example.com:8080"), Some(("api.example.com".into(), Some(8080))));
        assert_eq!(parse_grant_host("::1"), Some(("::1".into(), None)));
        assert_eq!(parse_grant_host("[::1]:80"), Some(("::1".into(), Some(80))));
        for bad in ["", "https://a.example/", "u@a.example", "*.example", "a.example:x", "a:b:c", "[::1]x", "a.example/p"] {
            assert_eq!(parse_grant_host(bad), None, "{bad}");
        }
        assert!(grant_covers("api.example.com", "api.example.com:8080"));
        assert!(grant_covers("api.example.com:8080", "API.example.com.:8080"));
        assert!(!grant_covers("api.example.com:8080", "api.example.com"));
        assert!(!grant_covers("api.example.com:8080", "api.example.com:8081"));
    }

    #[test]
    fn special_addresses_are_not_public() {
        for ip in ["0.0.0.0", "100.64.0.1", "172.31.255.255", "192.0.0.8", "198.18.0.1", "224.0.0.1", "255.255.255.255", "fe80::1", "ff02::1", "2001:db8::1", "::"] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["93.184.216.34", "1.1.1.1", "2606:4700:4700::1111", "172.32.0.1"] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
    }
}
