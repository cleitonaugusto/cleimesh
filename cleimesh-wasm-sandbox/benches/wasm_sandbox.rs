use cleimesh_wasm_sandbox::{WasmSandbox, SandboxConfig};
use cleimesh_core::ToolPayload;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use std::time::Duration;
use tokio::runtime::Runtime;

fn bench_cold_start(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    c.bench_function("wasm_sandbox_cold_start", |b| {
        b.iter_batched(
            || {
                let config = SandboxConfig {
                    max_execution_time: Duration::from_millis(100),
                    ..Default::default()
                };
                let sandbox = WasmSandbox::new(config).unwrap();
                let wasm_bytes = include_bytes!("../../wasm-tools/builtins.wasm");
                sandbox.register_wasm_module("bench_echo", wasm_bytes.to_vec()).unwrap();
                sandbox
            },
            |sandbox| {
                rt.block_on(async {
                    let payload = ToolPayload {
                        tool_name: "bench_echo".to_string(),
                        arguments: serde_json::json!({"message": "benchmark"}),
                        timeout_ms: Some(100),
                    };
                    sandbox.execute_in_sandbox("bench_echo", payload).await
                })
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_warm_start(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    // Pre-create sandbox
    let config = SandboxConfig {
        max_execution_time: Duration::from_millis(100),
        ..Default::default()
    };
    let sandbox = WasmSandbox::new(config).unwrap();
    let wasm_bytes = include_bytes!("../../wasm-tools/builtins.wasm");
    sandbox.register_wasm_module("bench_echo", wasm_bytes.to_vec()).unwrap();
    
    c.bench_function("wasm_sandbox_warm_start", |b| {
        b.iter(|| {
            rt.block_on(async {
                let payload = ToolPayload {
                    tool_name: "bench_echo".to_string(),
                    arguments: serde_json::json!({"message": "benchmark"}),
                    timeout_ms: Some(100),
                };
                sandbox.execute_in_sandbox("bench_echo", payload).await
            })
        });
    });
}

fn bench_module_compilation(c: &mut Criterion) {
    let wasm_bytes = include_bytes!("../../wasm-tools/builtins.wasm");
    
    c.bench_function("wasm_module_compilation", |b| {
        b.iter(|| {
            let config = SandboxConfig::default();
            let sandbox = WasmSandbox::new(config).unwrap();
            
            // This measures module compilation time
            let start = std::time::Instant::now();
            sandbox.register_wasm_module("bench_echo", wasm_bytes.to_vec()).unwrap();
            let elapsed = start.elapsed();
            black_box(elapsed)
        });
    });
}

criterion_group!(benches, bench_cold_start, bench_warm_start, bench_module_compilation);
criterion_main!(benches);