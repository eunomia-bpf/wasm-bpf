//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
//! Tests for the resolution of a guest file descriptor into a host one.
//!
//! Unlike the fixtures next to them, none of these load an eBPF program or need root, so they
//! run wherever the crate is tested. They are where the invariant that a guest cannot name a
//! host directory the runtime did not preopen is checked.

use std::fs::File;
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::mpsc;

use wasi_common::{dir::DirCaps, file::FileCaps};
use wasmtime_wasi::{
    ambient_authority, sync::dir::Dir as WasiDirImpl, Dir as CapStdDir, WasiCtx, WasiCtxBuilder,
};

use crate::bpf::fd::resolve_guest_fd_in_state;
use crate::handle::ProgramOperation;
use crate::runner::preopen_config_dirs;
use crate::state::AppState;

/// A directory that exists on every machine these tests run on, which keeps them from having to
/// create anything.
fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Build the state a host function sees, with `dirs` preopened through the same code the runtime
/// runs, and return the descriptor the guest holds for each of them in ascending order.
fn state_with_preopens(dirs: &[PathBuf]) -> (AppState, Vec<u32>) {
    let mut wasi = WasiCtxBuilder::new().build();
    let mapping = dirs
        .iter()
        .enumerate()
        .map(|(idx, dir)| (dir.clone(), PathBuf::from(format!("/preopen{idx}"))))
        .collect::<Vec<_>>();
    let preopen_dirs = preopen_config_dirs(&mut wasi, &mapping).unwrap();
    let mut guest_fds = preopen_dirs.keys().copied().collect::<Vec<_>>();
    guest_fds.sort_unstable();
    let (_operation_tx, operation_rx) = mpsc::channel::<ProgramOperation>();
    let state = AppState::new(wasi, String::default(), operation_rx, preopen_dirs);
    (state, guest_fds)
}

/// Put a directory in the guest's descriptor table without recording a host handle for it, which
/// is what a directory the guest opened for itself looks like to the resolver.
fn push_unrecorded_dir(wasi: &mut WasiCtx, path: &Path) -> u32 {
    let cap_dir = CapStdDir::open_ambient_dir(path, ambient_authority()).unwrap();
    let dir = Box::new(WasiDirImpl::from_cap_std(cap_dir));
    let caps = DirCaps::all();
    let file_caps = FileCaps::all();
    wasi.push_dir(dir, caps, file_caps, path.into()).unwrap()
}

/// What the kernel calls whatever `fd` names, so a resolved descriptor can be compared against
/// the directory it is supposed to be.
fn dev_and_inode(fd: RawFd) -> (libc::dev_t, libc::ino_t) {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `fstat` writes only the `stat` it is handed, and `fd` is owned by the caller for
    // the duration of the call.
    let ret = unsafe { libc::fstat(fd, stat.as_mut_ptr()) };
    assert_eq!(ret, 0, "fstat on fd {fd} failed");
    let stat = unsafe { stat.assume_init() };
    (stat.st_dev, stat.st_ino)
}

#[test]
fn test_resolve_preopened_dir_fd() {
    let dir = crate_dir();
    let (state, guest_fds) = state_with_preopens(&[dir.clone()]);
    // wasi-common hands out descriptors above stdio, so the only preopen is the guest's fd 3.
    assert_eq!(guest_fds, vec![3]);

    let host_fd = resolve_guest_fd_in_state(&state, guest_fds[0]).unwrap();
    // SAFETY: `F_GETFD` only reads the descriptor table entry of `host_fd`.
    let flags = unsafe { libc::fcntl(host_fd, libc::F_GETFD) };
    assert_ne!(flags, -1, "resolved fd {host_fd} is not open in the host");
    let expected = File::open(dir).unwrap();
    assert_eq!(
        dev_and_inode(host_fd),
        dev_and_inode(expected.as_raw_fd()),
        "resolved fd does not name the preopened directory"
    );
}

#[test]
fn test_resolve_rejects_unopened_fd() {
    let (state, _) = state_with_preopens(&[crate_dir()]);
    assert!(resolve_guest_fd_in_state(&state, 999999).is_err());
}

#[test]
fn test_resolve_rejects_non_directory_fd() {
    let (state, _) = state_with_preopens(&[crate_dir()]);
    // stdio is always seated at 0, 1 and 2: open in the guest, yet nothing the host preopened.
    for fd in 0..=2 {
        assert!(
            resolve_guest_fd_in_state(&state, fd).is_err(),
            "stdio fd {fd} resolved to a host descriptor"
        );
    }
}

#[test]
fn test_resolve_rejects_dir_the_host_did_not_preopen() {
    let (mut state, guest_fds) = state_with_preopens(&[crate_dir()]);
    let guest_opened = push_unrecorded_dir(&mut state.wasi, &crate_dir().join("tests"));
    assert!(!guest_fds.contains(&guest_opened));
    assert!(
        resolve_guest_fd_in_state(&state, guest_opened).is_err(),
        "a directory the guest opened itself resolved to a host descriptor"
    );
    // The preopen is still resolvable, so the rejection above is about that descriptor and not
    // about the state having gone bad.
    assert!(resolve_guest_fd_in_state(&state, guest_fds[0]).is_ok());
}

#[test]
fn test_resolve_rejects_closed_fd() {
    let (mut state, guest_fds) = state_with_preopens(&[crate_dir()]);
    let guest_fd = guest_fds[0];
    assert!(resolve_guest_fd_in_state(&state, guest_fd).is_ok());
    // Dropping the table entry is what closing the descriptor does. The host handle recorded at
    // preopen time outlives it, and must not keep answering for a number the guest no longer
    // holds.
    state.wasi.table().delete(guest_fd);
    assert!(resolve_guest_fd_in_state(&state, guest_fd).is_err());
}

#[test]
fn test_resolve_answers_every_fd_without_panicking() {
    let (state, guest_fds) = state_with_preopens(&[crate_dir(), crate_dir().join("tests")]);
    for fd in (0..64).chain([999999, u32::MAX - 1, u32::MAX]) {
        assert_eq!(
            resolve_guest_fd_in_state(&state, fd).is_ok(),
            guest_fds.contains(&fd),
            "fd {fd} resolved against expectation"
        );
    }
}
