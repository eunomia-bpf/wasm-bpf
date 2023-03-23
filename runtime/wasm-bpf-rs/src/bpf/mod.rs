//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
pub const EINVAL: i32 = 22;
pub const ENOENT: i32 = 2;

pub mod attach;
pub mod close;
pub mod fd_by_name;
pub mod load;
pub mod map_operate;
pub mod poll;
pub mod wrapper_poll;

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
macro_rules! ensure_program_mut_by_caller {
    ($caller: expr, $program: expr) => {{
        use $crate::ensure_program_mut_by_state;
        ensure_program_mut_by_state!($caller.data_mut(), $program)
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

pub type WasmPointer = u32;
pub type BpfObjectType = u64;
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
