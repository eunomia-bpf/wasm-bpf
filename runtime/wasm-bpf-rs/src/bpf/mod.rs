//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
pub(crate) const EINVAL: i32 = 22;
pub(crate) const ENOENT: i32 = 2;

pub(crate) mod attach;
pub(crate) mod close;
pub(crate) mod fd_by_name;
pub(crate) mod load;
pub(crate) mod map_operate;
pub(crate) mod poll;
pub(crate) mod wrapper_poll;

#[macro_export]
macro_rules! ensure_program_mut_by_state {
    ($state: expr, $program: expr) => {
        match $state.object_map.get_mut(&$program) {
            Some(v) => v,
            None => {
                log::debug!("Invalid program: {}", $program);
                return -1;
            }
        }
    };
}

#[macro_export]
macro_rules! ensure_program_by_state {
    ($state: expr, $program: expr) => {
        match $state.object_map.get(&$program) {
            Some(v) => v,
            None => {
                log::debug!("Invalid program: {}", $program);
                return -1;
            }
        }
    };
}

#[macro_export]
macro_rules! ensure_program_mut_by_caller {
    ($caller: expr, $program: expr) => {{
        use $crate::ensure_program_mut_by_state;
        ensure_program_mut_by_state!($caller.data_mut(), $program)
    }};
}

#[macro_export]
macro_rules! ensure_program_by_caller {
    ($caller: expr, $program: expr) => {{
        use $crate::ensure_program_by_state;
        ensure_program_by_state!($caller.data_mut(), $program)
    }};
}

#[macro_export]
macro_rules! ensure_c_str {
    ($caller: expr, $var_name: expr) => {{
        use $crate::utils::CallerUtils;
        match $caller.read_zero_terminated_str($var_name as usize) {
            Ok(v) => v.to_string(),
            Err(err) => {
                log::debug!("Failed to read `{}`: {}", stringify!($var_name), err);
                return -1;
            }
        }
    }};
}
/// The pointer type in 32bit wasm
pub type WasmPointer = u32;
/// The handle to a bpf object
pub type BpfObjectType = u64;
/// The string type in wasm, is also a pointer
pub type WasmString = u32;

#[macro_export]
macro_rules! ensure_enough_memory {
    ($caller: expr, $pointer:expr, $size: expr, $return_val: expr) => {{
        use $crate::utils::CallerUtils;
        let mut buf = vec![0u8];
        match $caller
            .get_memory()
            .expect("Expected exported memory!")
            .read(
                &mut $caller,
                $pointer as usize + $size as usize - 1,
                &mut buf,
            ) {
            Ok(_) => {}
            Err(err) => {
                debug!("Invalid pointer for {}: {}", stringify!($pointer), err);
                return $return_val;
            }
        }
    }};
}
