use std::sync::mpsc;

use anyhow::{anyhow, bail, Context};
use wasmtime::Engine;

pub enum ProgramOperation {
    Resume,
    Terminate,
}

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
    pub fn pause(&mut self) -> anyhow::Result<()> {
        if self.paused {
            bail!("Already paused!");
        }
        self.engine.increment_epoch();
        self.paused = true;
        Ok(())
    }
    pub fn resume(&mut self) -> anyhow::Result<()> {
        if !self.paused {
            bail!("Already running!");
        }
        self.operation_tx
            .send(ProgramOperation::Resume)
            .with_context(|| anyhow!("Failed to send resume operation"))?;
        Ok(())
    }
    pub fn terminate(&self) -> anyhow::Result<()> {
        self.operation_tx
            .send(ProgramOperation::Terminate)
            .with_context(|| anyhow!("Failed to send terminate operation"))?;
        Ok(())
    }
}
