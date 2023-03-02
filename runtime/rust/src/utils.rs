use std::ffi::CStr;

use crate::{state::CallerType, AppState};
use anyhow::{anyhow, bail, Context};
use wasmtime::{Caller, Memory, Table, WasmParams, WasmResults};

const INDIRECT_TABLE_NAME: &str = "__indirect_function_table";

pub trait CallerUtils {
    fn get_memory(&mut self) -> anyhow::Result<Memory>;
    fn get_indirect_call_table(&mut self) -> anyhow::Result<Table>;
    // Terminated zero won't be put in the returned Vec
    fn read_wasm_string(&mut self, offset: usize) -> anyhow::Result<Vec<u8>>;
    // Terminated zero won't be included
    fn read_wasm_string_slice(&mut self, offset: usize) -> anyhow::Result<&[u8]>;
    // Terminated zero will be included
    fn read_wasm_string_slice_include_zero(&mut self, offset: usize) -> anyhow::Result<&[u8]>;
    fn read_zero_terminated_str(&mut self, offset: usize) -> anyhow::Result<&str>;
    unsafe fn raw_pointer_at_unchecked(&mut self, offset: usize) -> *const u8;
}

impl CallerUtils for Caller<'_, AppState> {
    fn get_memory(&mut self) -> anyhow::Result<Memory> {
        match self
            .get_export("memory")
            .with_context(|| anyhow!("No export named `memory` found!"))?
        {
            wasmtime::Extern::Memory(t) => Ok(t),
            _ => bail!("The type of exported instance `memory` is not `Memory`"),
        }
    }

    fn get_indirect_call_table(&mut self) -> anyhow::Result<Table> {
        let table = self.get_export(INDIRECT_TABLE_NAME).with_context(||anyhow!("No export named `{}` found. And `--export-table` to you linker to emit such export.",INDIRECT_TABLE_NAME))?;
        let table = table.into_table().with_context(|| {
            anyhow!(
                "The type of export named `{}` is not table!",
                INDIRECT_TABLE_NAME
            )
        })?;
        return Ok(table);
    }
    fn read_wasm_string(&mut self, offset: usize) -> anyhow::Result<Vec<u8>> {
        let memory = self.get_memory()?;
        let mut buf = vec![];
        let mut at = offset;
        let mut curr = vec![0u8];
        loop {
            memory.read(&mut *self, at, &mut curr).with_context(|| {
                anyhow!(
                    "Failed to access byte at {}, may be memory index out of bound",
                    at
                )
            })?;
            if curr[0] == 0 {
                break;
            } else {
                at += 1;
                buf.push(curr[0]);
            }
        }
        return Ok(buf);
    }

    fn read_wasm_string_slice(&mut self, offset: usize) -> anyhow::Result<&[u8]> {
        self.read_wasm_string_slice_include_zero(offset)
            .map(|v| &v[..=v.len() - 2])
    }

    fn read_wasm_string_slice_include_zero(&mut self, offset: usize) -> anyhow::Result<&[u8]> {
        let memory = self.get_memory()?;
        let mut at = offset;
        let mut curr = vec![0u8];
        loop {
            memory.read(&mut *self, at, &mut curr).with_context(|| {
                anyhow!(
                    "Failed to access byte at {}, may be memory index out of bound",
                    at
                )
            })?;
            if curr[0] == 0 {
                break;
            } else {
                at += 1;
            }
        }
        return Ok(&memory.data(self)[offset..=at]);
    }

    fn read_zero_terminated_str(&mut self, offset: usize) -> anyhow::Result<&str> {
        let data_slice = self
            .read_wasm_string_slice_include_zero(offset)
            .with_context(|| anyhow!("Failed to read byte slice"))?;
        let c_str = CStr::from_bytes_with_nul(data_slice).unwrap();
        return Ok(c_str
            .to_str()
            .with_context(|| anyhow!("Failed to decode bytes into utf8 str"))?);
    }

    unsafe fn raw_pointer_at_unchecked(&mut self, offset: usize) -> *const u8 {
        let memory = self.get_memory().expect("Expected memory exported");
        memory.data_ptr(self).add(offset)
    }
}

pub trait FunctionQuickCall {
    fn perform_indirect_call<Params: WasmParams, Return: WasmResults>(
        &mut self,
        index: u32,
        params: Params,
    ) -> anyhow::Result<Return>;
}

impl FunctionQuickCall for CallerType<'_> {
    fn perform_indirect_call<Params: WasmParams, Return: WasmResults>(
        &mut self,
        index: u32,
        params: Params,
    ) -> anyhow::Result<Return> {
        let table = self
            .get_indirect_call_table()
            .expect("Indirect call table expected!");
        let item = table
            .get(&mut *self, index)
            .with_context(|| anyhow!("No func with index {} found", index))?;
        let func = item
            .funcref()
            .with_context(|| anyhow!("Expect element with index {} to be a function", index))?
            .with_context(|| anyhow!("Invalid type, function expected"))?;
        let ret_val = func
            .typed::<Params, Return>(&mut *self)
            .with_context(|| anyhow!("Invalid function type provides"))?
            .call(self, params)
            .with_context(|| anyhow!("Failed to call function"))?;
        return Ok(ret_val);
    }
}

#[macro_export]
macro_rules! add_bind_function_with_module_and_name {
    ($linker: expr, $module: expr, $func: expr, $name: expr) => {{
        use anyhow::{anyhow, Context};
        $linker
            .func_wrap($module, $name, $func)
            .with_context(|| anyhow!("Failed to register host function `{}`", stringify!($func)))
    }};
}

#[macro_export]
macro_rules! add_bind_function_with_module {
    ($linker: expr, $module: expr, $func: expr) => {
        add_bind_function_with_module_and_name!($linker, $module, $func, stringify!($func))
    };
}

#[macro_export]
macro_rules! add_bind_function {
    ($linker: expr, $func: expr) => {
        add_bind_function_with_module!($linker, "wasm_bpf", $func)
    };
}
