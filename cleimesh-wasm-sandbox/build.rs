// Exposes the wasmtime version this crate links as WASMTIME_VERSION:
// receipts record it, since replaying a call needs the same engine.
fn main() {
    let lock = std::fs::read_to_string("../Cargo.lock").unwrap_or_default();
    let version = lock
        .split("[[package]]")
        .find(|p| p.contains("\nname = \"wasmtime\"\n"))
        .and_then(|p| p.lines().find_map(|l| l.strip_prefix("version = \"")))
        .map(|v| v.trim_end_matches('"').to_string())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=WASMTIME_VERSION={}", version);
    println!("cargo:rerun-if-changed=../Cargo.lock");
}
