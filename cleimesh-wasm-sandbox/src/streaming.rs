use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use wasmtime::*;
use crate::{SandboxConfig, SandboxData, create_wasi_p1_ctx};

pub struct StreamHandle {
    memory: Memory,
    store: Store<SandboxData>,
    read_ptr: i32,
    read_len: i32,
    write_ptr: i32,
    write_len: i32,
    read_pos: usize,
    write_pos: usize,
    buffer_size: usize,
    closed: bool,
}

impl StreamHandle {
    pub fn new(mut store: Store<SandboxData>, instance: &Instance, buffer_size: usize) -> Result<Self> {
        let memory = instance.get_export(&mut store, "memory")
            .and_then(|e| e.into_memory())
            .context("no memory export found")?;

        let read_ptr = 0i32;
        let read_len = buffer_size as i32;
        let write_ptr = buffer_size as i32;
        let write_len = buffer_size as i32;

        let total_needed = (buffer_size * 2).div_ceil(65536);
        let current_pages = memory.size(&mut store);
        if current_pages < total_needed as u64 {
            memory.grow(&mut store, total_needed as u64 - current_pages)
                .map_err(anyhow::Error::from).context("failed to grow memory for streaming")?;
        }

        Ok(Self {
            memory,
            store,
            read_ptr,
            read_len,
            write_ptr,
            write_len,
            read_pos: 0,
            write_pos: 0,
            buffer_size,
            closed: false,
        })
    }

    pub fn write(&mut self, data: &[u8]) -> Result<usize> {
        if self.closed {
            return Err(anyhow::anyhow!("Stream closed"));
        }

        let available = self.buffer_size - self.write_pos;
        let to_write = data.len().min(available);
        
        if to_write > 0 {
            self.memory.write(&mut self.store, self.write_ptr as usize + self.write_pos, &data[..to_write])
                .context("failed to write to stream memory")?;
            self.write_pos += to_write;
        }

        Ok(to_write)
    }

    pub fn flush(&mut self) -> Result<()> {
        Ok(())
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let available = self.read_pos.min(buf.len());
        
        if available > 0 {
            self.memory.read(&self.store, self.read_ptr as usize, &mut buf[..available])
                .context("failed to read from stream memory")?;
            self.read_pos -= available;
        }

        Ok(available)
    }

    pub fn close(&mut self) {
        self.closed = true;
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn available_read(&self) -> usize {
        self.read_pos
    }

    pub fn available_write(&self) -> usize {
        self.buffer_size - self.write_pos
    }

    pub fn set_read_available(&mut self, len: usize) {
        self.read_pos = len.min(self.buffer_size);
    }

    async fn allocate_memory(&mut self, data: &[u8]) -> Result<i32> {
        let size = data.len();
        let pages_needed = size.div_ceil(65536);

        let current_pages = self.memory.size(&mut self.store);
        if current_pages < pages_needed as u64 {
            self.memory.grow(&mut self.store, pages_needed as u64 - current_pages)
                .map_err(anyhow::Error::from).context("failed to grow memory")?;
        }

        let ptr = 0i32;
        self.memory.write(&mut self.store, ptr as usize, data)
            .context("failed to write to memory")?;

        Ok(ptr)
    }
}

impl AsyncWrite for StreamHandle {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.write(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(e) => Poll::Ready(Err(std::io::Error::other(e))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<Result<(), std::io::Error>> {
        match self.flush() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(std::io::Error::other(e))),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<Result<(), std::io::Error>> {
        self.close();
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for StreamHandle {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let n = match self.read(buf.initialize_unfilled()) {
            Ok(n) => n,
            Err(e) => return Poll::Ready(Err(std::io::Error::other(e))),
        };
        buf.advance(n);
        Poll::Ready(Ok(()))
    }
}

pub struct StreamingSandbox {
    engine: Engine,
    config: SandboxConfig,
    linker: Linker<SandboxData>,
    stream_buffer_size: usize,
}

impl StreamingSandbox {
    pub fn new(config: SandboxConfig, stream_buffer_size: usize) -> Result<Self> {
        let mut config_builder = Config::new();
        config_builder
            .async_support(true)
            .consume_fuel(true)
            .epoch_interruption(true)
            .max_wasm_stack(512 * 1024);

        let engine = Engine::new(&config_builder)
            .map_err(anyhow::Error::from).context("failed to create wasmtime engine")?;
        crate::sandbox::spawn_epoch_ticker(&engine);

        let mut linker = Linker::new(&engine);
        wasmtime_wasi::p1::add_to_linker_async(&mut linker, |data: &mut SandboxData| &mut data.wasi_p1_ctx)
            .map_err(anyhow::Error::from).context("failed to add wasi to linker")?;

        Self::add_streaming_functions(&mut linker)?;

        Ok(Self { engine, config, linker, stream_buffer_size })
    }

    fn add_streaming_functions(linker: &mut Linker<SandboxData>) -> Result<()> {
        linker.func_wrap("cleimesh", "stream_read", |_caller: Caller<'_, SandboxData>, _ptr: i32, _len: i32| -> i32 {
            0
        })?;

        linker.func_wrap("cleimesh", "stream_write", |_caller: Caller<'_, SandboxData>, _ptr: i32, _len: i32| -> i32 {
            0
        })?;

        Ok(())
    }

    pub async fn execute_streaming<F, R, Fut>(&self, wasm_bytes: &[u8], f: F) -> Result<R>
    where
        F: FnOnce(Instance, StreamHandle) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<R>> + Send + 'static,
        R: Send + 'static,
    {
        let module = Module::new(&self.engine, wasm_bytes)
            .map_err(anyhow::Error::from).context("failed to compile module")?;

        let mut store = self.create_store()?;
        let instance = self.linker.instantiate_async(&mut store, &module).await
            .map_err(anyhow::Error::from).context("failed to instantiate module")?;

        let stream = StreamHandle::new(store, &instance, self.stream_buffer_size)?;

        let result = f(instance, stream).await?;

        Ok(result)
    }

    fn create_store(&self) -> Result<Store<SandboxData>> {
        let wasi_p1_ctx = create_wasi_p1_ctx(&self.config);
        
        let mut builder = Store::new(
            &self.engine,
            SandboxData::new(self.config.clone(), wasi_p1_ctx)
        );
        
        let _limits = wasmtime::StoreLimitsBuilder::new()
            .memory_size(self.config.max_memory_bytes)
            .table_elements(self.config.limits.max_table_elements as usize)
            .instances(10)
            .tables(10)
            .memories(10)
            .build();
        builder.limiter(|data| &mut data.limits);
        
        builder.set_fuel(self.config.limits.max_instructions)
            .map_err(anyhow::Error::from).context("failed to set fuel")?;
        builder.set_epoch_deadline(crate::sandbox::epoch_deadline_ticks(self.config.max_execution_time));

        Ok(builder)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamConfig {
    pub buffer_size: usize,
    pub chunk_size: usize,
    pub timeout_ms: u64,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            buffer_size: 64 * 1024,
            chunk_size: 4096,
            timeout_ms: 5000,
        }
    }
}

pub async fn stream_tool_output<F, Fut>(
    sandbox: &StreamingSandbox,
    wasm_bytes: &[u8],
    tool_name: String,
    arguments: serde_json::Value,
    mut on_chunk: F,
) -> Result<()>
where
    F: FnMut(&[u8]) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<()>> + Send + 'static,
{
    sandbox.execute_streaming(wasm_bytes, move |instance, mut stream| async move {
        let input = serde_json::json!({
            "tool": tool_name,
            "arguments": arguments,
            "streaming": true,
        });

        let input_json = serde_json::to_vec(&input)
            .context("failed to serialize tool input")?;

        let ptr = stream.allocate_memory(&input_json).await?;
        let input_len = input_json.len() as i32;

        let tool_func = instance.get_export(&mut stream.store, "execute_tool_streaming")
            .and_then(|e| e.into_func())
            .context("streaming tool function 'execute_tool_streaming' not found")?;

        let mut results = vec![Val::I32(0); 2];
        tool_func.call_async(&mut stream.store, &[Val::I32(ptr), Val::I32(input_len)], &mut results).await
            .map_err(anyhow::Error::from).context("streaming tool execution failed")?;

        loop {
            if stream.is_closed() {
                break;
            }

            let mut chunk = vec![0u8; stream.available_read()];
            let read = stream.read(&mut chunk)?;
            if read > 0 {
                on_chunk(&chunk).await?;
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }

        Ok(())
    }).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_stream_handle() {
    }
}