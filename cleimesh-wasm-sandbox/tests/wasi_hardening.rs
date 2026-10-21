//! Regression checks for wasmtime-wasi advisories that hit what the product
//! promises (S12). The guest is hand-written WAT calling
//! WASI directly, as a malicious tool would, with the grants the sandbox
//! builds from a token (`create_wasi_p1_ctx`).

use cleimesh_wasm_sandbox::{create_wasi_p1_ctx, SandboxConfig};
use wasmtime::{Config, Engine, Linker, Module, Store};
use wasmtime_wasi::p1::{self, WasiP1Ctx};

// path_open(fd 3, "victim.txt", oflags TRUNC, rights FD_READ only): no
// write right is asked for, yet TRUNC empties the file.
const TRUNCATE: &str = r#"
(module
  (import "wasi_snapshot_preview1" "path_open"
    (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 16) "victim.txt")
  (func (export "truncate") (result i32)
    (call $path_open (i32.const 3) (i32.const 0) (i32.const 16) (i32.const 10)
      (i32.const 8) (i64.const 2) (i64.const 0) (i32.const 0) (i32.const 64))))
"#;

async fn truncate_under(write: bool) -> (i32, String) {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().canonicalize().unwrap();
    std::fs::write(base.join("victim.txt"), "keep me").unwrap();
    let config = SandboxConfig {
        allow_filesystem_read: true,
        allow_filesystem_write: write,
        allowed_paths: vec![base.to_string_lossy().into_owned()],
        ..Default::default()
    };

    let mut engine_config = Config::new();
    engine_config.async_support(true);
    let engine = Engine::new(&engine_config).unwrap();
    let mut linker: Linker<WasiP1Ctx> = Linker::new(&engine);
    p1::add_to_linker_async(&mut linker, |ctx| ctx).unwrap();
    let mut store = Store::new(&engine, create_wasi_p1_ctx(&config));
    let module = Module::new(&engine, TRUNCATE).unwrap();
    let instance = linker.instantiate_async(&mut store, &module).await.unwrap();
    let truncate = instance.get_typed_func::<(), i32>(&mut store, "truncate").unwrap();
    let errno = truncate.call_async(&mut store, ()).await.unwrap();
    (errno, std::fs::read_to_string(base.join("victim.txt")).unwrap())
}

// RUSTSEC-2026-0149 let path_open(TRUNC) through FilePerms::READ under
// DirPerms::all(); a read-only grant here is read-only for the directory too,
// so it was not exposed. Kept as a guard on how grants map to permissions.
#[tokio::test]
async fn a_read_only_grant_cannot_truncate_a_file() {
    let (errno, content) = truncate_under(false).await;
    assert_ne!(errno, 0, "path_open(TRUNC) must fail under a read-only grant");
    assert_eq!(content, "keep me");
}

// The control: with write access the same call truncates, so the test above
// would see a bypass.
#[tokio::test]
async fn a_writable_grant_can_truncate_a_file() {
    let (errno, content) = truncate_under(true).await;
    assert_eq!(errno, 0);
    assert_eq!(content, "");
}

// The tool links the read-only "target.txt" into its writable directory as
// "alias.txt", then opens the alias for writing with TRUNC. Grants: fd 3 is
// the writable directory, fd 4 the read-only one (writable ones come first).
const LINK_THEN_TRUNCATE: &str = r#"
(module
  (import "wasi_snapshot_preview1" "path_link"
    (func $path_link (param i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "path_open"
    (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 16) "target.txt")
  (data (i32.const 32) "alias.txt")
  (func (export "link") (result i32)
    (call $path_link (i32.const 4) (i32.const 0) (i32.const 16) (i32.const 10)
      (i32.const 3) (i32.const 32) (i32.const 9)))
  (func (export "truncate_alias") (result i32)
    (call $path_open (i32.const 3) (i32.const 0) (i32.const 32) (i32.const 9)
      (i32.const 8) (i64.const 64) (i64.const 0) (i32.const 0) (i32.const 64))))
"#;

// RUSTSEC-2026-0188: before 36.0.12 a hard link checked only directory
// permissions, so a file under FilePerms::READ in a mutable directory could
// be overwritten through a link in a writable one. A read-only grant here is
// read-only for the directory too, so it was not exposed; this guards the
// case the per-directory grants (--read A --write B) make possible.
#[tokio::test]
async fn a_hard_link_cannot_carry_a_read_only_file_into_a_writable_grant() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().canonicalize().unwrap();
    let (read_only, writable) = (base.join("a"), base.join("b"));
    std::fs::create_dir_all(&read_only).unwrap();
    std::fs::create_dir_all(&writable).unwrap();
    std::fs::write(read_only.join("target.txt"), "keep me").unwrap();
    let config = SandboxConfig {
        allow_filesystem_read: true,
        allowed_paths: vec![read_only.to_string_lossy().into_owned()],
        writable_paths: vec![writable.to_string_lossy().into_owned()],
        ..Default::default()
    };

    let mut engine_config = Config::new();
    engine_config.async_support(true);
    let engine = Engine::new(&engine_config).unwrap();
    let mut linker: Linker<WasiP1Ctx> = Linker::new(&engine);
    p1::add_to_linker_async(&mut linker, |ctx| ctx).unwrap();
    let mut store = Store::new(&engine, create_wasi_p1_ctx(&config));
    let module = Module::new(&engine, LINK_THEN_TRUNCATE).unwrap();
    let instance = linker.instantiate_async(&mut store, &module).await.unwrap();
    let link = instance.get_typed_func::<(), i32>(&mut store, "link").unwrap();
    let truncate = instance.get_typed_func::<(), i32>(&mut store, "truncate_alias").unwrap();
    let linked = link.call_async(&mut store, ()).await.unwrap();
    if linked == 0 {
        truncate.call_async(&mut store, ()).await.unwrap();
    }
    assert_eq!(std::fs::read_to_string(read_only.join("target.txt")).unwrap(), "keep me", "link errno {linked}");
    assert_ne!(linked, 0, "the link across grants with different permissions must be refused");
}
