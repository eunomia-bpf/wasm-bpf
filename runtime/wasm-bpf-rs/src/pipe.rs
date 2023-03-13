use std::{
    any::Any,
    io::{Cursor, Write},
    sync::{Arc, RwLock},
};

use wasi_common::{
    file::{FdFlags, FileType},
    WasiFile,
};

pub struct ReadableWritePipe<W: Write> {
    buf: Arc<RwLock<W>>,
}
#[wiggle::async_trait]
impl<W: Write + Any + Send + Sync> WasiFile for ReadableWritePipe<W> {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    async fn get_filetype(&mut self) -> Result<FileType, wasi_common::Error> {
        Ok(FileType::Pipe)
    }
    async fn get_fdflags(&mut self) -> Result<FdFlags, wasi_common::Error> {
        Ok(FdFlags::APPEND)
    }
    async fn write_vectored<'a>(
        &mut self,
        bufs: &[std::io::IoSlice<'a>],
    ) -> Result<u64, wasi_common::Error> {
        let n = self.borrow().write_vectored(bufs)?;
        Ok(n.try_into()?)
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
