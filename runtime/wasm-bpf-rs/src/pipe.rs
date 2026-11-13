//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::{
    io::{self, Cursor, Write},
    sync::{Arc, RwLock},
};

use tokio::io::AsyncWrite;
use wasmtime_wasi::cli::{IsTerminal, StdoutStream};

/// This is a pipe that can be read from and written to.
/// The original wasmtime pipe is only writable when the wasm program is running.
pub struct ReadableWritePipe<W: Write + Send + Sync + 'static> {
    buf: Arc<RwLock<W>>,
}

impl<W: Write + Send + Sync + 'static> IsTerminal for ReadableWritePipe<W> {
    fn is_terminal(&self) -> bool {
        false
    }
}

impl<W: Write + Send + Sync + 'static> StdoutStream for ReadableWritePipe<W> {
    fn async_stream(&self) -> Box<dyn AsyncWrite + Send + Sync> {
        Box::new(self.clone_writer())
    }
}

/// An `AsyncWrite` adapter over the shared buffer, so WASI can write into the same
/// `Arc<RwLock<W>>` the host reads from.
struct PipeWriter<W: Write + Send + Sync + 'static> {
    inner: Arc<RwLock<W>>,
}

impl<W: Write + Send + Sync + 'static> AsyncWrite for PipeWriter<W> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let mut guard = match self.inner.write() {
            Ok(g) => g,
            Err(e) => return std::task::Poll::Ready(Err(io::Error::other(e.to_string()))),
        };
        match guard.write_all(buf) {
            Ok(()) => std::task::Poll::Ready(Ok(buf.len())),
            Err(e) => std::task::Poll::Ready(Err(e)),
        }
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let mut guard = match self.inner.write() {
            Ok(g) => g,
            Err(e) => return std::task::Poll::Ready(Err(io::Error::other(e.to_string()))),
        };
        std::task::Poll::Ready(guard.flush())
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl<W: Write + Send + Sync + 'static> std::io::Write for PipeWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write().map_err(|e| io::Error::other(e.to_string()))?.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.write().map_err(|e| io::Error::other(e.to_string()))?.flush()
    }
}

impl<W: Write + Send + Sync + 'static> ReadableWritePipe<W> {
    pub fn borrow(&self) -> std::sync::RwLockWriteGuard<'_, W> {
        RwLock::write(&self.buf).unwrap()
    }
    pub fn get_read_lock(&self) -> std::sync::RwLockReadGuard<'_, W> {
        self.buf.read().unwrap()
    }
    pub fn new(inner: W) -> Self {
        Self {
            buf: Arc::new(RwLock::new(inner)),
        }
    }
    fn clone_writer(&self) -> PipeWriter<W> {
        PipeWriter {
            inner: self.buf.clone(),
        }
    }
}

impl ReadableWritePipe<Cursor<Vec<u8>>> {
    pub fn new_vec_buf() -> Self {
        Self::new(Cursor::new(vec![]))
    }
}

impl<W: Write + Send + Sync + 'static> Clone for ReadableWritePipe<W> {
    fn clone(&self) -> Self {
        Self {
            buf: self.buf.clone(),
        }
    }
}
