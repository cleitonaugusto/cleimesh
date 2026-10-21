//! Built-in CleiMesh tools, executed inside the WASM sandbox.
//!
//! Guest ABI v1 (see `cleimesh-wasm-sandbox/src/instance.rs` for the host side):
//! - `cleimesh_alloc(len) -> ptr`: the host asks the guest for an input buffer.
//! - `cleimesh_dealloc(ptr, len)`: releases a buffer returned by either side.
//! - `cleimesh_execute(ptr, len) -> u64`: input is `{"tool": name, "arguments": {...}}`,
//!   result is `(out_ptr << 32) | out_len` pointing to `{"ok": value}` or `{"error": "msg"}`.
//!
//! File access goes through WASI, so it only reaches directories the host preopened.

use serde_json::{json, Value};

#[no_mangle]
pub extern "C" fn cleimesh_alloc(len: u32) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(len as usize);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// # Safety
/// `ptr` and `len` must come from `cleimesh_alloc` or from `cleimesh_execute`'s result.
#[no_mangle]
pub unsafe extern "C" fn cleimesh_dealloc(ptr: *mut u8, len: u32) {
    drop(Vec::from_raw_parts(ptr, 0, len as usize));
}

/// # Safety
/// `ptr` must point to `len` readable bytes previously obtained from `cleimesh_alloc`.
#[no_mangle]
pub unsafe extern "C" fn cleimesh_execute(ptr: *const u8, len: u32) -> u64 {
    let input = std::slice::from_raw_parts(ptr, len as usize);
    let envelope = match dispatch(input) {
        Ok(value) => json!({ "ok": value }),
        Err(message) => json!({ "error": message }),
    };
    let mut out = serde_json::to_vec(&envelope).unwrap_or_else(|_| b"{\"error\":\"serialization failed\"}".to_vec());
    out.shrink_to_fit();
    let out_len = out.len() as u64;
    let out_ptr = out.as_mut_ptr() as u64;
    std::mem::forget(out);
    (out_ptr << 32) | out_len
}

fn dispatch(input: &[u8]) -> Result<Value, String> {
    let request: Value = serde_json::from_slice(input).map_err(|e| format!("invalid input JSON: {e}"))?;
    let tool = request.get("tool").and_then(Value::as_str).ok_or("missing 'tool'")?;
    let args = request.get("arguments").cloned().unwrap_or(Value::Null);
    match tool {
        "echo" => echo(&args),
        "file_read" => file_read(&args),
        "file_write" => file_write(&args),
        "json_transform" => json_transform(&args),
        other => Err(format!("unknown tool '{other}'")),
    }
}

fn str_arg<'a>(args: &'a Value, name: &str) -> Result<&'a str, String> {
    args.get(name).and_then(Value::as_str).ok_or_else(|| format!("missing string argument '{name}'"))
}

fn echo(args: &Value) -> Result<Value, String> {
    Ok(json!({ "message": str_arg(args, "message")? }))
}

fn file_read(args: &Value) -> Result<Value, String> {
    let path = str_arg(args, "path")?;
    let content = std::fs::read_to_string(path).map_err(|e| format!("cannot read '{path}': {e}"))?;
    Ok(json!({ "content": content }))
}

fn file_write(args: &Value) -> Result<Value, String> {
    let path = str_arg(args, "path")?;
    let content = str_arg(args, "content")?;
    std::fs::write(path, content).map_err(|e| format!("cannot write '{path}': {e}"))?;
    Ok(json!({ "written": content.len() }))
}

/// Minimal path filter: `a.b` selects keys, `a[].b` maps over an array.
fn json_transform(args: &Value) -> Result<Value, String> {
    let filter = str_arg(args, "filter")?;
    let mut result = args.get("input").cloned().unwrap_or(Value::Null);
    for part in filter.split('.').filter(|s| !s.is_empty()) {
        result = match part.strip_suffix("[]") {
            Some(key) => {
                let base = if key.is_empty() { result } else { result.get(key).cloned().unwrap_or(Value::Null) };
                match base {
                    Value::Array(items) => Value::Array(items),
                    other => return Err(format!("'{part}' expects an array, got {other}")),
                }
            }
            None => match result {
                Value::Array(items) => Value::Array(items.iter().map(|i| i.get(part).cloned().unwrap_or(Value::Null)).collect()),
                other => other.get(part).cloned().unwrap_or(Value::Null),
            },
        };
    }
    Ok(result)
}
