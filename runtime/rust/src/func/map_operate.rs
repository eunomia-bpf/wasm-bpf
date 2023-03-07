//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use libbpf_rs::libbpf_sys::{
    bpf_map_delete_elem_flags, bpf_map_get_next_key, bpf_map_lookup_elem_flags,
    bpf_map_update_elem, BPF_MAP_DELETE_ELEM, BPF_MAP_GET_NEXT_KEY, BPF_MAP_LOOKUP_ELEM,
    BPF_MAP_UPDATE_ELEM,
};
use log::debug;

use crate::{
    ensure_enough_memory,
    func::{EINVAL, ENOENT},
    state::CallerType,
    utils::CallerUtils,
};

use super::WasmPointer;

pub fn wasm_bpf_map_operate(
    mut caller: CallerType,
    fd: i32,
    cmd: i32,
    key: WasmPointer,
    value: WasmPointer,
    next_key: WasmPointer, // receives the next_key; Since size of key isn't controlled by us, so it's a bit harder to ensure the safety
    flags: u64,
) -> i32 {
    debug!("Map operate");
    // let mut map = None;
    let (key_size, value_size, fd) = {
        let state = caller.data();

        let map = if let Some(v) = state.get_map_by_fd(fd) {
            v
        } else {
            debug!("No map with fd `{}` found", fd);
            return ENOENT;
        };
        (map.key_size() as usize, map.value_size() as usize, map.fd())
    };

    match cmd as u32 {
        BPF_MAP_GET_NEXT_KEY => {
            ensure_enough_memory!(caller, key, key_size, EINVAL);
            ensure_enough_memory!(caller, next_key, key_size, EINVAL);
            let ret_val = unsafe {
                bpf_map_get_next_key(
                    fd,
                    caller.raw_pointer_at_unchecked(key as usize) as *const _,
                    caller.raw_pointer_at_unchecked(next_key as usize) as *mut _,
                )
            };
            if ret_val != 0 {
                debug!("map get next key failed with {}", ret_val);
                return ret_val;
            }
        }
        BPF_MAP_LOOKUP_ELEM => {
            ensure_enough_memory!(caller, key, key_size, EINVAL);
            ensure_enough_memory!(caller, value, value_size, EINVAL);
            let ret_val = unsafe {
                bpf_map_lookup_elem_flags(
                    fd,
                    caller.raw_pointer_at_unchecked(key as usize) as *const _,
                    caller.raw_pointer_at_unchecked(value as usize) as *mut _,
                    flags,
                )
            };
            if ret_val != 0 {
                debug!("map lookup elem failed with {}", ret_val);
                return ret_val;
            }
        }
        BPF_MAP_UPDATE_ELEM => {
            ensure_enough_memory!(caller, key, key_size, EINVAL);
            ensure_enough_memory!(caller, value, value_size, EINVAL);
            let ret_val = unsafe {
                bpf_map_update_elem(
                    fd,
                    caller.raw_pointer_at_unchecked(key as usize) as *const _,
                    caller.raw_pointer_at_unchecked(value as usize) as *mut _,
                    flags,
                )
            };
            if ret_val != 0 {
                debug!("map update elem failed with {}", ret_val);
                return ret_val;
            }
        }
        BPF_MAP_DELETE_ELEM => {
            ensure_enough_memory!(caller, key, key_size, EINVAL);
            let ret_val = unsafe {
                bpf_map_delete_elem_flags(
                    fd,
                    caller.raw_pointer_at_unchecked(key as usize) as *const _,
                    flags,
                )
            };
            if ret_val != 0 {
                debug!("map delete elem failed with {}", ret_val);
                return ret_val;
            }
        }
        // More syscall commands can be allowed here
        s => {
            debug!("Map operation `{}` currently not supported", s);
            return EINVAL;
        }
    };
    return 0;
}
