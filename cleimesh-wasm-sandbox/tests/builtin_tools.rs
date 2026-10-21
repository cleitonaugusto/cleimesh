//! End-to-end checks for the built-in tools running inside the sandbox,
//! including the permission boundaries the product promises.

use cleimesh_core::ToolPayload;
use cleimesh_wasm_sandbox::{SandboxConfig, WasmSandbox};
use serde_json::{json, Value};

const BUILTINS: &[u8] = include_bytes!("../../wasm-tools/builtins.wasm");

fn sandbox(config: SandboxConfig) -> WasmSandbox {
    let sandbox = WasmSandbox::new(config).unwrap();
    for name in ["echo", "file_read", "file_write", "json_transform"] {
        sandbox.register_wasm_module(name, BUILTINS.to_vec()).unwrap();
    }
    sandbox
}

fn with_dir(dir: &std::path::Path, write: bool) -> SandboxConfig {
    SandboxConfig {
        allow_filesystem_read: true,
        allow_filesystem_write: write,
        allowed_paths: vec![dir.canonicalize().unwrap().to_string_lossy().into_owned()],
        ..Default::default()
    }
}

async fn run(sandbox: &WasmSandbox, tool: &str, arguments: Value) -> Result<Value, String> {
    let payload = ToolPayload { tool_name: tool.into(), arguments, timeout_ms: Some(5000) };
    sandbox.execute_in_sandbox(tool, payload).await.map(|r| r.output).map_err(|e| format!("{e:?}"))
}

#[tokio::test]
async fn echo_returns_message() {
    let out = run(&sandbox(SandboxConfig::default()), "echo", json!({"message": "hi"})).await.unwrap();
    assert_eq!(out, json!({"message": "hi"}));
}

#[tokio::test]
async fn json_transform_maps_arrays() {
    let args = json!({"input": {"a": [{"b": 1}, {"b": 2}]}, "filter": "a[].b"});
    let out = run(&sandbox(SandboxConfig::default()), "json_transform", args).await.unwrap();
    assert_eq!(out, json!([1, 2]));
}

#[tokio::test]
async fn file_read_is_denied_without_permission() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().canonicalize().unwrap().join("secret.txt");
    std::fs::write(&file, "secret").unwrap();
    let err = run(&sandbox(SandboxConfig::default()), "file_read", json!({"path": file})).await.unwrap_err();
    assert!(err.contains("cannot read"), "{err}");
}

#[tokio::test]
async fn file_read_works_inside_allowed_dir() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().canonicalize().unwrap().join("data.txt");
    std::fs::write(&file, "hello").unwrap();
    let out = run(&sandbox(with_dir(dir.path(), false)), "file_read", json!({"path": file})).await.unwrap();
    assert_eq!(out, json!({"content": "hello"}));
}

#[tokio::test]
async fn read_permission_does_not_allow_writes() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().canonicalize().unwrap().join("out.txt");
    let err = run(&sandbox(with_dir(dir.path(), false)), "file_write", json!({"path": file, "content": "x"}))
        .await
        .unwrap_err();
    assert!(err.contains("cannot write"), "{err}");
    assert!(!file.exists());
}

#[tokio::test]
async fn write_permission_allows_writes() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().canonicalize().unwrap().join("out.txt");
    run(&sandbox(with_dir(dir.path(), true)), "file_write", json!({"path": file, "content": "x"})).await.unwrap();
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "x");
}

#[tokio::test]
async fn paths_outside_allowed_dir_are_blocked() {
    let dir = tempfile::tempdir().unwrap();
    let sb = sandbox(with_dir(dir.path(), true));
    let escape = dir.path().canonicalize().unwrap().join("../../../../../../etc/passwd");
    for path in [json!("/etc/passwd"), json!(escape)] {
        let err = run(&sb, "file_read", json!({"path": path})).await.unwrap_err();
        assert!(err.contains("cannot read"), "{err}");
    }
}

/// A guest that never returns must be stopped by the wall-clock timeout.
#[tokio::test]
async fn infinite_loop_times_out() {
    let looping = r#"(module
        (memory (export "memory") 1)
        (func (export "cleimesh_alloc") (param i32) (result i32) i32.const 1024)
        (func (export "cleimesh_execute") (param i32 i32) (result i64) (loop $l (br $l)) i64.const 0))"#;
    let config = SandboxConfig { limits: cleimesh_wasm_sandbox::SandboxLimits { max_instructions: u64::MAX, ..Default::default() }, ..Default::default() };
    let sb = WasmSandbox::new(config).unwrap();
    sb.register_wasm_module("spin", looping.as_bytes().to_vec()).unwrap();
    let payload = ToolPayload { tool_name: "spin".into(), arguments: json!({}), timeout_ms: Some(200) };
    // The outer limit only turns a hang into a failure; host-side compile time under heavy
    // parallel load can take seconds, so it must not be read as the timeout's precision.
    let result = tokio::time::timeout(std::time::Duration::from_secs(60), sb.execute_in_sandbox("spin", payload))
        .await
        .expect("sandbox did not stop the infinite loop");
    let err = format!("{:?}", result.unwrap_err());
    assert!(err.contains("timed out"), "{err}");
}

/// A writable directory must not make the read-only ones writable too.
#[tokio::test]
async fn permissions_are_per_directory() {
    let read_only = tempfile::tempdir().unwrap();
    let writable = tempfile::tempdir().unwrap();
    let ro = read_only.path().canonicalize().unwrap();
    let rw = writable.path().canonicalize().unwrap();
    let config = SandboxConfig {
        allow_filesystem_read: true,
        allowed_paths: vec![ro.to_string_lossy().into_owned()],
        writable_paths: vec![rw.to_string_lossy().into_owned()],
        ..Default::default()
    };
    let sb = sandbox(config);

    run(&sb, "file_write", json!({"path": rw.join("ok.txt"), "content": "x"})).await.unwrap();
    let err = run(&sb, "file_write", json!({"path": ro.join("no.txt"), "content": "x"})).await.unwrap_err();
    assert!(err.contains("cannot write"), "{err}");
    assert!(!ro.join("no.txt").exists());
}

// R4: modules are compiled once and cached by the hash of their bytes, so
// replacing a tool's bytes under the same name runs the new code.
#[tokio::test]
async fn replaced_module_runs_its_new_bytes_not_the_cached_ones() {
    let fixed = r#"(module
        (memory (export "memory") 1)
        (data (i32.const 2048) "{\"ok\":\"replaced\"}")
        (func (export "cleimesh_alloc") (param i32) (result i32) i32.const 1024)
        (func (export "cleimesh_execute") (param i32 i32) (result i64) i64.const 8796093022225))"#;
    let sandbox = sandbox(SandboxConfig::default());
    sandbox.register_wasm_module("echo", include_bytes!("../../wasm-tools/builtins.wasm").to_vec()).unwrap();
    assert_eq!(run(&sandbox, "echo", json!({"message": "first"})).await.unwrap(), json!({"message": "first"}));
    sandbox.register_wasm_module("echo", fixed.as_bytes().to_vec()).unwrap();
    assert_eq!(run(&sandbox, "echo", json!({"message": "second"})).await.unwrap(), json!("replaced"));
}

/// Reads 4 random bytes and the wall clock through WASI and returns them as
/// `"dddd-c"`: 4 digits from the random bytes, the last digit of the clock's
/// seconds.
const READS_CLOCK_AND_RANDOM: &str = r#"(module
    (import "wasi_snapshot_preview1" "random_get" (func $rand (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "clock_time_get" (func $clock (param i32 i64 i32) (result i32)))
    (memory (export "memory") 1)
    (data (i32.const 2048) "{\"ok\":\"0000-0\"}")
    (func (export "cleimesh_alloc") (param i32) (result i32) i32.const 1024)
    (func $digit (param $from i32) (param $to i32)
        (i32.store8 (local.get $to) (i32.add (i32.rem_u (i32.load8_u (local.get $from)) (i32.const 10)) (i32.const 48))))
    (func (export "cleimesh_execute") (param i32 i32) (result i64)
        (drop (call $rand (i32.const 3000) (i32.const 4)))
        (drop (call $clock (i32.const 0) (i64.const 1) (i32.const 3104)))
        (call $digit (i32.const 3000) (i32.const 2055))
        (call $digit (i32.const 3001) (i32.const 2056))
        (call $digit (i32.const 3002) (i32.const 2057))
        (call $digit (i32.const 3003) (i32.const 2058))
        (i32.store8 (i32.const 2060)
            (i32.add (i32.wrap_i64 (i64.rem_u (i64.div_u (i64.load (i32.const 3104)) (i64.const 1000000000)) (i64.const 10))) (i32.const 48)))
        i64.const 8796093022223))"#;

async fn reads(determinism: Option<cleimesh_wasm_sandbox::Determinism>) -> String {
    let config = SandboxConfig { determinism, ..SandboxConfig::default() };
    let sandbox = sandbox(config.clone());
    sandbox.register_wasm_module("probe", READS_CLOCK_AND_RANDOM.as_bytes().to_vec()).unwrap();
    let payload = ToolPayload { tool_name: "probe".into(), arguments: json!({}), timeout_ms: Some(5000) };
    let out = sandbox.execute_with_config("probe", payload, &config).await.unwrap();
    out.output.as_str().unwrap().to_string()
}

// C4: with determinism the guest's clock and randomness come from the
// recorded values, so a replay sees exactly what the original run saw.
#[tokio::test]
async fn deterministic_runs_see_the_recorded_clock_and_seed() {
    use cleimesh_wasm_sandbox::Determinism;
    let a = Determinism { clock_ns: 1_800_000_007_000_000_000, seed: [7; 32] };
    let first = reads(Some(a)).await;
    assert_eq!(first, reads(Some(a)).await, "same seed and clock, different output");
    assert!(first.ends_with("-7"), "the guest did not see the frozen clock: {first}");

    let b = Determinism { seed: [8; 32], ..a };
    assert_ne!(first, reads(Some(b)).await, "another seed gave the same random bytes");
}

// C5: the sandbox notes which granted directories a call touched, per
// grant and in fd order, counting files without naming them, also when
// the tool fails.
#[tokio::test]
async fn execute_observed_notes_the_directories_touched() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().canonicalize().unwrap();
    let (data, out) = (base.join("data"), base.join("out"));
    std::fs::create_dir_all(data.join("docs/api")).unwrap();
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(data.join("docs/api/a.txt"), "hello").unwrap();
    let config = SandboxConfig {
        allow_filesystem_read: true,
        allowed_paths: vec![data.to_string_lossy().into_owned()],
        writable_paths: vec![out.to_string_lossy().into_owned()],
        ..Default::default()
    };
    let sandbox = sandbox(config.clone());
    let call = |tool: &str, arguments: Value| ToolPayload { tool_name: tool.into(), arguments, timeout_ms: Some(5000) };

    let (result, fs) = sandbox.execute_observed("file_read", call("file_read", json!({"path": data.join("docs/api/a.txt")})), &config).await;
    assert_eq!(result.unwrap().output, json!({"content": "hello"}));
    let grants: Vec<_> = fs.grants.iter().map(|g| g.grant.clone()).collect();
    assert_eq!(grants, vec![out.to_string_lossy().into_owned(), data.to_string_lossy().into_owned()], "writable first, as preopened");
    let read = &fs.grants[1];
    assert_eq!(read.read.iter().map(|c| c.join("/")).collect::<Vec<_>>(), vec!["docs/api"]);
    assert_eq!((read.files_read, read.files_written), (1, 0));
    assert!(fs.grants[0].read.is_empty() && fs.grants[0].write.is_empty());

    let (result, fs) = sandbox.execute_observed("file_write", call("file_write", json!({"path": out.join("r.txt"), "content": "x"})), &config).await;
    result.unwrap();
    assert_eq!((fs.grants[0].files_written, fs.grants[0].write.len()), (1, 1));

    let (result, fs) = sandbox.execute_observed("file_read", call("file_read", json!({"path": data.join("docs/missing.txt")})), &config).await;
    assert!(result.is_err());
    assert_eq!(fs.grants[1].read.iter().map(|c| c.join("/")).collect::<Vec<_>>(), vec!["docs"], "a failed call is observed too");
}
