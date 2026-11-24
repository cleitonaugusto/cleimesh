//! Egress decided on the connection (S19), against real sockets: a granted
//! server that redirects elsewhere, a resolver that changes its answer, and a
//! tool that tries to name another site behind the granted address.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use cleimesh_wasm_sandbox::egress::{Egress, Request, Resolver};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A server that answers every request with `response` and counts connections.
async fn server(response: String) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else { return };
            counted.fetch_add(1, Ordering::SeqCst);
            let response = response.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = socket.read(&mut buf).await;
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (addr, hits)
}

fn redirect(to: &str) -> String {
    format!("HTTP/1.1 302 Found\r\nLocation: {to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

fn ok(body: &str) -> String {
    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
}

/// Every name resolves to loopback, where the test servers listen.
fn loopback() -> Resolver {
    Arc::new(|_, _| Ok(vec![IpAddr::from([127, 0, 0, 1])]))
}

/// Loopback is private, so these tests grant private addresses; what they
/// check is the grant on names and hops.
fn egress(hosts: &[&str], resolver: Resolver) -> Egress {
    Egress { allow_private: true, resolver, ..Egress::new(hosts.iter().map(|h| h.to_string()).collect()) }
}

fn get(url: String) -> Request {
    Request { method: "GET".into(), url, headers: Vec::new(), body: None }
}

#[tokio::test]
async fn a_granted_host_is_fetched() {
    let (addr, _) = server(ok("hello")).await;
    let e = egress(&["api.test"], loopback());
    let (response, hops) = e.fetch(&get(format!("http://api.test:{}/x", addr.port()))).await.unwrap();
    assert_eq!((response.status, response.body.as_str()), (200, "hello"));
    assert_eq!(hops.len(), 1);
    assert_eq!(hops[0].addr, Some(addr));
}

#[tokio::test]
async fn a_redirect_to_a_host_not_granted_is_refused_before_connecting() {
    let (evil, evil_hits) = server(ok("secret")).await;
    let (api, _) = server(redirect(&format!("http://evil.test:{}/collect", evil.port()))).await;
    let e = egress(&["api.test"], loopback());

    let refused = e.fetch(&get(format!("http://api.test:{}/start", api.port()))).await.unwrap_err();
    assert!(refused.reason.contains("host evil.test is not granted"), "{}", refused.reason);
    assert_eq!(refused.hops.len(), 2);
    assert_eq!(refused.hops[0].status, Some(302));
    assert_eq!(refused.hops[1].addr, None);
    assert_eq!(evil_hits.load(Ordering::SeqCst), 0, "the forbidden server was never reached");
}

#[tokio::test]
async fn a_redirect_to_an_ip_literal_is_refused() {
    let (evil, evil_hits) = server(ok("secret")).await;
    for location in [format!("http://127.0.0.1:{}/", evil.port()), format!("http://0x7f.1:{}/", evil.port()), format!("http://2130706433:{}/", evil.port())] {
        let (api, _) = server(redirect(&location)).await;
        let e = egress(&["api.test"], loopback());
        let refused = e.fetch(&get(format!("http://api.test:{}/", api.port()))).await.unwrap_err();
        assert!(refused.reason.contains("is not a granted host"), "{location}: {}", refused.reason);
    }
    assert_eq!(evil_hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_redirect_within_the_grant_is_followed_and_recorded() {
    let (end, _) = server(ok("done")).await;
    let (start, _) = server(redirect(&format!("http://cdn.test:{}/file", end.port()))).await;
    let e = egress(&["api.test", "cdn.test"], loopback());
    let (response, hops) = e.fetch(&get(format!("http://api.test:{}/", start.port()))).await.unwrap();
    assert_eq!(response.body, "done");
    assert_eq!(hops.iter().map(|h| h.status).collect::<Vec<_>>(), vec![Some(302), Some(200)]);
}

#[tokio::test]
async fn the_name_is_looked_up_once_and_the_connection_goes_there() {
    // Rebinding: the first answer passes the check, every later one points
    // at the cloud metadata address. A client that looked the name up again
    // to connect would follow the second answer.
    let (addr, hits) = server(ok("pinned")).await;
    let lookups = Arc::new(AtomicUsize::new(0));
    let seen = lookups.clone();
    let rebinding: Resolver = Arc::new(move |_, _| -> io::Result<Vec<IpAddr>> {
        Ok(vec![if seen.fetch_add(1, Ordering::SeqCst) == 0 { IpAddr::from([127, 0, 0, 1]) } else { IpAddr::from([169, 254, 169, 254]) }])
    });
    let e = egress(&["api.test"], rebinding);
    let (response, hops) = e.fetch(&get(format!("http://api.test:{}/", addr.port()))).await.unwrap();
    assert_eq!(response.body, "pinned");
    assert_eq!(lookups.load(Ordering::SeqCst), 1);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert_eq!(hops[0].addr, Some(addr));
}

#[tokio::test]
async fn without_the_private_grant_a_name_rebound_inside_is_refused() {
    let (addr, hits) = server(ok("internal")).await;
    let e = Egress { resolver: loopback(), ..Egress::new(vec!["api.test".into()]) };
    let refused = e.fetch(&get(format!("http://api.test:{}/", addr.port()))).await.unwrap_err();
    assert!(refused.reason.contains("not a public address"), "{}", refused.reason);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn the_tool_cannot_name_another_site_behind_the_address() {
    let (addr, hits) = server(ok("x")).await;
    let e = egress(&["api.test"], loopback());
    let mut req = get(format!("http://api.test:{}/", addr.port()));
    req.headers.push(("Host".into(), "admin.internal".into()));
    let refused = e.fetch(&req).await.unwrap_err();
    assert!(refused.reason.contains("header Host"), "{}", refused.reason);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_redirect_loop_ends() {
    let listener_port = {
        let (a, _) = server(redirect("/again")).await;
        a.port()
    };
    let e = Egress { max_redirects: 3, ..egress(&["api.test"], loopback()) };
    let refused = e.fetch(&get(format!("http://api.test:{listener_port}/"))).await.unwrap_err();
    assert!(refused.reason.contains("more than 3 redirects"), "{}", refused.reason);
    assert_eq!(refused.hops.len(), 4);
}

/// A guest that fetches `request` through the host and returns the host's
/// answer as its own output: `{"ok": ...}` or `{"error": ...}`.
fn fetching_guest(request: &serde_json::Value) -> Vec<u8> {
    let json = request.to_string();
    let escaped = json.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        r#"(module
  (import "cleimesh" "http_fetch" (func $fetch (param i32 i32) (result i64)))
  (memory (export "memory") 2)
  (global $next (mut i32) (i32.const 8192))
  (data (i32.const 0) "{escaped}")
  (func (export "cleimesh_alloc") (param $len i32) (result i32) (local $p i32)
    global.get $next local.set $p
    global.get $next local.get $len i32.add global.set $next
    local.get $p)
  (func (export "cleimesh_execute") (param i32 i32) (result i64)
    i32.const 0 i32.const {len} call $fetch))"#,
        len = json.len()
    )
    .into_bytes()
}

async fn run_guest(request: serde_json::Value, egress: Option<Egress>) -> (Result<serde_json::Value, String>, Vec<cleimesh_wasm_sandbox::egress::Hop>) {
    use cleimesh_wasm_sandbox::{SandboxConfig, WasmSandbox};
    let config = SandboxConfig { max_execution_time: std::time::Duration::from_secs(10), egress, ..Default::default() };
    let sandbox = WasmSandbox::new(SandboxConfig::default()).unwrap();
    sandbox.register_wasm_module("fetch", fetching_guest(&request)).unwrap();
    let payload = cleimesh_core::ToolPayload { tool_name: "fetch".into(), arguments: serde_json::json!({}), timeout_ms: Some(10_000) };
    let (result, observed) = sandbox.execute_observed("fetch", payload, &config).await;
    (result.map(|r| r.output).map_err(|e| format!("{e:?}")), observed.egress)
}

#[tokio::test]
async fn a_sandboxed_tool_fetches_a_granted_host_and_the_hop_is_observed() {
    let (addr, _) = server(ok("from the host")).await;
    let request = serde_json::json!({"url": format!("http://api.test:{}/v1", addr.port())});
    let (output, hops) = run_guest(request, Some(egress(&["api.test"], loopback()))).await;
    let output = output.unwrap();
    assert_eq!(output["status"], 200);
    assert_eq!(output["body"], "from the host");
    assert_eq!(hops.len(), 1);
    assert_eq!(hops[0].addr, Some(addr));
}

#[tokio::test]
async fn a_sandboxed_tool_without_an_egress_grant_reaches_nothing() {
    let (addr, hits) = server(ok("x")).await;
    let request = serde_json::json!({"url": format!("http://api.test:{}/", addr.port())});
    let (output, hops) = run_guest(request, None).await;
    let err = output.unwrap_err();
    assert!(err.contains("network not granted"), "{err}");
    assert!(hops.is_empty());
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_sandboxed_tool_redirected_off_the_grant_is_refused_and_both_hops_are_observed() {
    let (evil, evil_hits) = server(ok("secret")).await;
    let (api, _) = server(redirect(&format!("http://evil.test:{}/", evil.port()))).await;
    let request = serde_json::json!({"url": format!("http://api.test:{}/", api.port())});
    let (output, hops) = run_guest(request, Some(egress(&["api.test"], loopback()))).await;
    assert!(output.unwrap_err().contains("host evil.test is not granted"));
    assert_eq!(hops.len(), 2);
    assert_eq!(hops[1].refused.as_deref(), Some("host evil.test is not granted"));
    assert_eq!(evil_hits.load(Ordering::SeqCst), 0);
}

/// The built-in `fetch_url`, as a deployed tool runs it.
async fn run_builtin(arguments: serde_json::Value, egress: Option<Egress>) -> (Result<serde_json::Value, String>, Vec<cleimesh_wasm_sandbox::egress::Hop>) {
    use cleimesh_wasm_sandbox::{SandboxConfig, WasmSandbox};
    let config = SandboxConfig { max_execution_time: std::time::Duration::from_secs(10), egress, ..Default::default() };
    let sandbox = WasmSandbox::new(SandboxConfig::default()).unwrap();
    sandbox.register_wasm_module("fetch_url", include_bytes!("../../wasm-tools/builtins.wasm").to_vec()).unwrap();
    let payload = cleimesh_core::ToolPayload { tool_name: "fetch_url".into(), arguments, timeout_ms: Some(10_000) };
    let (result, observed) = sandbox.execute_observed("fetch_url", payload, &config).await;
    (result.map(|r| r.output).map_err(|e| format!("{e:?}")), observed.egress)
}

#[tokio::test]
async fn builtin_fetch_url_reads_a_granted_api() {
    let (api, _) = server(ok(r#"{"temp": 21}"#)).await;
    let (output, hops) = run_builtin(serde_json::json!({"url": format!("http://api.test:{}/weather", api.port())}), Some(egress(&["api.test"], loopback()))).await;
    let output = output.unwrap();
    assert_eq!(output["status"], 200);
    assert_eq!(output["body"], r#"{"temp": 21}"#);
    assert_eq!(hops.len(), 1);
}

#[tokio::test]
async fn builtin_fetch_url_cannot_carry_a_secret_off_the_grant_through_a_redirect() {
    // The exfiltration step of the 2026 agent incidents: injected text makes
    // the agent fetch a granted URL that answers with a redirect to the
    // attacker, the secret riding in the query. The attacker never sees a
    // connection, and the refusal is on record.
    let (attacker, attacker_hits) = server(ok("thanks")).await;
    let (api, _) = server(redirect(&format!("http://collect.attacker.test:{}/c?d=SECRET-TOKEN", attacker.port()))).await;
    let (output, hops) = run_builtin(serde_json::json!({"url": format!("http://api.test:{}/open-redirect", api.port())}), Some(egress(&["api.test"], loopback()))).await;
    let err = output.unwrap_err();
    assert!(err.contains("host collect.attacker.test is not granted"), "{err}");
    assert_eq!(attacker_hits.load(Ordering::SeqCst), 0);
    assert_eq!(hops.len(), 2);
    assert!(hops[1].refused.is_some());
}
