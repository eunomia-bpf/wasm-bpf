use std::sync::mpsc;

use anyhow::{anyhow, bail, Context};
use log::debug;
use wasmtime::Engine;

/// This is the signal that will be sended to the hanging epoch interruption callback function
pub enum ProgramOperation {
    /// Resume the program
    Resume,
    /// Terminate the program
    Terminate,
}

/// This is a handle to the wasm program
pub struct WasmProgramHandle {
    operation_tx: mpsc::Sender<ProgramOperation>,
    paused: bool,
    engine: Engine,
}

impl WasmProgramHandle {
    pub(crate) fn new(operation_tx: mpsc::Sender<ProgramOperation>, engine: Engine) -> Self {
        Self {
            operation_tx,
            engine,
            paused: false,
        }
    }
    /// Pause the wasm program
    /// Error will be returned when the program was already paused
    pub fn pause(&mut self) -> anyhow::Result<()> {
        if self.paused {
            bail!("Already paused!");
        }
        self.engine.increment_epoch();
        self.paused = true;
        Ok(())
    }
    /// Resume the wasm program
    /// Error will be returned when the program was already running, or when the program as terminated
    pub fn resume(&mut self) -> anyhow::Result<()> {
        if !self.paused {
            bail!("Already running!");
        }
        self.operation_tx
            .send(ProgramOperation::Resume)
            .with_context(|| anyhow!("Failed to send resume operation"))?;
        self.paused = false;
        Ok(())
    }
    /// Terminate the wasm program
    /// Error will be returned when the program was already terminated
    pub fn terminate(self) -> anyhow::Result<()> {
        debug!("Terminating wasm program");
        self.engine.increment_epoch();
        self.operation_tx
            .send(ProgramOperation::Terminate)
            .with_context(|| anyhow!("Failed to send terminate operation"))?;
        Ok(())
    }
}
