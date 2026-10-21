//! C5 spike: can the host observe which paths a WASI preview1 guest opens,
//! by shadowing `path_open` in the linker and delegating to the original?

use wasmtime::*;
use wasmtime_wasi::p1::{self, WasiP1Ctx};

const BUILTINS: &[u8] = include_bytes!("../../wasm-tools/builtins.wasm");

struct Data {
    wasi: WasiP1Ctx,
    opened: Vec<(i32, String, i64, i32)>,
}

#[tokio::test]
async fn shadowed_path_open_sees_the_paths_and_delegates() {
    let dir = tempfile::tempdir().unwrap();
    let base_dir = dir.path().canonicalize().unwrap();
    std::fs::create_dir_all(base_dir.join("docs/api")).unwrap();
    std::fs::write(base_dir.join("docs/api/a.txt"), "hello").unwrap();

    let mut config = Config::new();
    config.async_support(true);
    let engine = Engine::new(&config).unwrap();

    let mut linker: Linker<Data> = Linker::new(&engine);
    p1::add_to_linker_async(&mut linker, |d: &mut Data| &mut d.wasi).unwrap();
    linker.allow_shadowing(true);
    // Same body as wiggle's generated glue, plus a look at the path first.
    linker
        .func_wrap_async(
            "wasi_snapshot_preview1",
            "path_open",
            |mut caller: Caller<'_, Data>,
             (fd, dirflags, ptr, len, oflags, rights, inheriting, fdflags, out): (i32, i32, i32, i32, i32, i64, i64, i32, i32)| {
                Box::new(async move {
                    let Some(Extern::Memory(memory)) = caller.get_export("memory") else {
                        wasmtime::bail!("missing required memory export");
                    };
                    let (bytes, data) = memory.data_and_store_mut(&mut caller);
                    let path = bytes
                        .get(ptr as u32 as usize..(ptr as u32 as usize).saturating_add(len as u32 as usize))
                        .map(|b| String::from_utf8_lossy(b).into_owned());
                    let mut mem = wiggle::GuestMemory::Unshared(bytes);
                    let errno = p1::wasi_snapshot_preview1::path_open(
                        &mut data.wasi, &mut mem, fd, dirflags, ptr, len, oflags, rights, inheriting, fdflags, out,
                    )
                    .await?;
                    data.opened.push((fd, path.unwrap_or_default(), rights, errno));
                    Ok(errno)
                })
            },
        )
        .unwrap();

    let wasi = wasmtime_wasi::WasiCtxBuilder::new()
        .preopened_dir(&base_dir, base_dir.to_str().unwrap(), wasmtime_wasi::FsPerms::ReadOnly)
        .unwrap()
        .build_p1();
    let mut store = Store::new(&engine, Data { wasi, opened: Vec::new() });
    let module = Module::new(&engine, BUILTINS).unwrap();
    let instance = linker.instantiate_async(&mut store, &module).await.unwrap();
    if let Ok(init) = instance.get_typed_func::<(), ()>(&mut store, "_initialize") {
        init.call_async(&mut store, ()).await.unwrap();
    }

    // Guest ABI v1: cleimesh_alloc(len) -> ptr; execute(ptr, len) -> (ptr << 32 | len) of the JSON result.
    let memory = instance.get_memory(&mut store, "memory").unwrap();
    let alloc = instance.get_typed_func::<u32, u32>(&mut store, "cleimesh_alloc").unwrap();
    let execute = instance.get_typed_func::<(u32, u32), u64>(&mut store, "cleimesh_execute").unwrap();
    for path in [base_dir.join("docs/api/a.txt"), base_dir.join("missing.txt")] {
        let input = serde_json::to_vec(&serde_json::json!({"tool": "file_read", "arguments": {"path": path}})).unwrap();
        let ptr = alloc.call_async(&mut store, input.len() as u32).await.unwrap();
        memory.write(&mut store, ptr as usize, &input).unwrap();
        let packed = execute.call_async(&mut store, (ptr, input.len() as u32)).await.unwrap();
        let (out_ptr, out_len) = ((packed >> 32) as usize, (packed & 0xffff_ffff) as usize);
        let mut out = vec![0u8; out_len];
        memory.read(&store, out_ptr, &mut out).unwrap();
        eprintln!("result: {}", String::from_utf8_lossy(&out));
    }
    eprintln!("observed: {:?}", store.data().opened);
    let opened = &store.data().opened;
    assert!(opened.iter().any(|(_, p, _, errno)| p == "docs/api/a.txt" && *errno == 0), "{opened:?}");
    assert!(opened.iter().any(|(_, p, _, errno)| p == "missing.txt" && *errno != 0), "{opened:?}");
}
