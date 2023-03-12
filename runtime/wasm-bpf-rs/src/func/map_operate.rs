//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::os::raw::c_void;

use libbpf_rs::libbpf_sys::{
    bpf_map_delete_elem_flags, bpf_map_get_next_key, bpf_map_info, bpf_map_lookup_elem_flags,
    bpf_map_update_elem, bpf_obj_get_info_by_fd, BPF_MAP_DELETE_ELEM, BPF_MAP_GET_NEXT_KEY,
    BPF_MAP_LOOKUP_ELEM, BPF_MAP_UPDATE_ELEM,
};
use log::{debug, error};

use crate::{ensure_enough_memory, func::EINVAL, state::CallerType, utils::CallerUtils};

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
    let (key_size, value_size) = {
        let mut map_info = unsafe { std::mem::zeroed::<bpf_map_info>() };
        let mut info_len: u32 = std::mem::size_of::<bpf_map_info>() as u32;
        let ret = unsafe {
            bpf_obj_get_info_by_fd(
                fd,
                &mut map_info as *mut bpf_map_info as *mut c_void,
                &mut info_len as *mut u32,
            )
        };
        if ret != 0 {
            error!("Failed to query map info: {}", ret);
            return ret;
        }
        (map_info.key_size as usize, map_info.value_size as usize)
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
    0
}

#[cfg(test)]

mod tests {
    use std::ffi::c_void;

    use libbpf_rs::{ObjectBuilder, libbpf_sys::{bpf_map_info, bpf_obj_get_info_by_fd}};

    use crate::tests::get_test_file_path;

    #[test]
    fn test_retrive_key_value_size_by_bpf_obj_get_info_by_fd() {
        /*
            This function tests if `bpf_obj_get_info_by_fd` corrently works.
            Here we use `bootstrap.bpf.o` to run the test.
            Bootstrap will create two maps.
        */
        let bootstrap_elf = get_test_file_path("bootstrap.bpf.o");
        let object = ObjectBuilder::default()
            .open_file(bootstrap_elf)
            .unwrap()
            .load()
            .unwrap();
        // Iterate over maps, call `bpf_obj_get_info_by_fd` and compare with sizes that libbpf provides
        for map in object.maps_iter() {
            let mut map_info = unsafe { std::mem::zeroed::<bpf_map_info>() };
            let mut info_len = std::mem::size_of::<bpf_map_info>() as u32;
            let ret = unsafe {
                bpf_obj_get_info_by_fd(
                    map.fd(),
                    &mut map_info as *mut bpf_map_info as *mut c_void,
                    &mut info_len as *mut u32,
                )
            };
            assert_eq!(ret, 0, "Failed to run `bpf_obj_get_info_by_fd`");
            assert_eq!(
                map.key_size(),
                map_info.key_size,
                "Different key size found"
            );
            assert_eq!(
                map.value_size(),
                map_info.value_size,
                "Different value size found"
            );
        }
    }
}