//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
//! Resolution of a WASI file descriptor supplied by the guest into a host file
//! descriptor.
//!
//! The only inputs are a descriptor number and the directories the host itself
//! preopened, so this module cannot name a host path, let alone open one. That is the
//! point: a Wasm program can designate an attach target without the runtime accepting
//! an arbitrary path string out of guest memory.

use std::os::fd::{AsRawFd, RawFd};

use anyhow::{bail, Result};

use crate::state::{AppState, CallerType};

/// Translate a WASI file descriptor the guest holds into the host descriptor for the
/// same directory.
///
/// Fails if the guest does not hold that descriptor, or holds one the runtime did not
/// preopen, such as one the guest opened itself or stdio. It never falls back to a
/// descriptor other than the one recorded for `guest_fd`.
pub(crate) fn resolve_guest_fd(caller: &mut CallerType, guest_fd: u32) -> Result<RawFd> {
    resolve_guest_fd_in_state(caller.data(), guest_fd)
}

/// The body of [`resolve_guest_fd`], taking the state directly so it can be exercised
/// without a `wasmtime::Caller`, which cannot be constructed outside a host call. A
/// `&mut AppState` reborrows to the shared reference taken here.
pub(crate) fn resolve_guest_fd_in_state(state: &AppState, guest_fd: u32) -> Result<RawFd> {
    // Read the table through the `wasi.table` field rather than `WasiCtx::table()`,
    // which takes `&mut self`; a shared borrow leaves `preopen_dirs` readable below.
    if !state.wasi.table.contains_key(guest_fd) {
        bail!("fd {} is not open in the guest", guest_fd);
    }
    // wasi-common 5.0.1 keeps `FileEntry` and `DirEntry` `pub(crate)` and re-exports
    // neither, so an out-of-crate caller cannot ask the table what kind of resource a
    // descriptor holds, nor reach the `dyn WasiFile`/`dyn WasiDir` behind it. This
    // lookup discriminates instead: it holds exactly the directories the host opened
    // for `Config::preopen_dirs`. wasi-common refuses to close or renumber a preopen,
    // so a number recorded at preopen time still denotes that same directory.
    let host_dir = match state.preopen_dirs.get(&guest_fd) {
        Some(v) => v,
        None => bail!("fd {} is not a preopened directory", guest_fd),
    };
    Ok(host_dir.as_raw_fd())
}
