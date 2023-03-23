//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::{
    any::Any,
    io::{self, Cursor, Write},
    sync::{Arc, RwLock},
};

use wasi_common::{
    file::{FdFlags, FileType},
    Error, ErrorExt, WasiFile,
};

/// This is a pipe that can be read from and written to.
/// The original wasmtime pipe is only writable when the wasm program is running.
pub struct ReadableWritePipe<W: Write> {
    buf: Arc<RwLock<W>>,
}

#[wiggle::async_trait]
impl<W: Write + Any + Send + Sync> WasiFile for ReadableWritePipe<W> {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    async fn get_filetype(&mut self) -> Result<FileType, Error> {
        Ok(FileType::Pipe)
    }
    async fn get_fdflags(&mut self) -> Result<FdFlags, Error> {
        Ok(FdFlags::APPEND)
    }
    async fn write_vectored<'a>(&mut self, bufs: &[std::io::IoSlice<'a>]) -> Result<u64, Error> {
        let n = self.borrow().write_vectored(bufs)?;
        Ok(n.try_into()?)
    }
    async fn writable(&self) -> Result<(), Error> {
        Ok(())
    }
    async fn write_vectored_at<'a>(
        &mut self,
        _bufs: &[io::IoSlice<'a>],
        _offset: u64,
    ) -> Result<u64, Error> {
        Err(Error::seek_pipe())
    }
    async fn seek(&mut self, _pos: std::io::SeekFrom) -> Result<u64, Error> {
        Err(Error::seek_pipe())
    }
    fn isatty(&mut self) -> bool {
        false
    }
}

impl<W: Write> ReadableWritePipe<W> {
    pub fn borrow(&self) -> std::sync::RwLockWriteGuard<W> {
        RwLock::write(&self.buf).unwrap()
    }
    pub fn get_read_lock(&self) -> std::sync::RwLockReadGuard<W> {
        self.buf.read().unwrap()
    }
    pub fn new(inner: W) -> Self {
        Self {
            buf: Arc::new(RwLock::new(inner)),
        }
    }
}

impl ReadableWritePipe<Cursor<Vec<u8>>> {
    pub fn new_vec_buf() -> Self {
        Self::new(Cursor::new(vec![]))
    }
}

impl<W: Write> Clone for ReadableWritePipe<W> {
    fn clone(&self) -> Self {
        Self {
            buf: self.buf.clone(),
        }
    }
}
