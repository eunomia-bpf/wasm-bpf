//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use anyhow::{anyhow, Context};
use clap::Parser;
use flexi_logger::Logger;
use log_format::my_log_format;
use std::fs;
use std::path::PathBuf;
use wasm_bpf_rs::{run_wasm_bpf_module, Config};

mod log_format;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about,
    long_about = "A WebAssembly runtime for eBPF user-space programs."
)]
struct CommandArgs {
    #[arg(help = "The WebAssembly Module file to run")]
    wasm_module_file: String,
    #[arg(long, help = "Display more logs")]
    verbose: bool,
    #[arg(short = 'm', long, help = "Wrapper module name", default_value_t = String::from("callback-wrapper"))]
    wrapper_module_name: String,
    #[arg(short = 'c', long, help = "Callback export name", default_value_t = String::from("go-callback"))]
    callback_export_name: String,
    #[arg(
        long = "dir",
        value_name = "HOST:GUEST",
        value_parser = parse_preopen,
        help = "Preopen a host directory at a guest path, as an attach target the guest can \
                pass to wasm_attach_bpf_program_fd; it cannot open, list, or change anything \
                beneath it. The first colon splits host from guest, so a host path cannot \
                contain a colon. May be given more than once"
    )]
    dir: Vec<(PathBuf, PathBuf)>,
    #[arg(help = "Arguments that will be passed to the Wasm program")]
    args_to_wasm: Vec<String>,
}

/// Parse a `--dir HOST:GUEST` value into a `(host, guest)` pair.
/// The first colon separates the two, so a guest path may contain colons but a host path
/// cannot. Both parts must be non-empty. The host path is not checked for existence here;
/// preopening reports a clear error when the open fails.
fn parse_preopen(value: &str) -> Result<(PathBuf, PathBuf), String> {
    match value.split_once(':') {
        Some((host, guest)) if !host.is_empty() && !guest.is_empty() => {
            Ok((PathBuf::from(host), PathBuf::from(guest)))
        }
        _ => Err(String::from("expected HOST:GUEST with both parts non-empty")),
    }
}

fn main() -> anyhow::Result<()> {
    let args = CommandArgs::parse();
    Logger::try_with_str(if args.verbose { "debug" } else { "info" })?
        .format(my_log_format)
        .start()?;
    let mut args_to_wasm = args.args_to_wasm;
    args_to_wasm.insert(0, args.wasm_module_file.clone());
    let binary = fs::read(&args.wasm_module_file)
        .with_context(|| anyhow!("Failed to read wasm module file"))?;
    let mut config = Config::default();
    config.set_callback_values(args.callback_export_name, args.wrapper_module_name);
    for (host_path, guest_path) in args.dir {
        config.add_preopen_dir(host_path, guest_path);
    }
    run_wasm_bpf_module(&binary, &args_to_wasm[..], config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_preopen_valid() {
        let parsed = parse_preopen("a:b").unwrap();
        assert_eq!(parsed, (PathBuf::from("a"), PathBuf::from("b")));
    }

    #[test]
    fn test_parse_preopen_splits_at_first_colon() {
        let parsed = parse_preopen("a:b:c").unwrap();
        assert_eq!(parsed, (PathBuf::from("a"), PathBuf::from("b:c")));
    }

    #[test]
    fn test_parse_preopen_rejects_bad_values() {
        for bad in ["ab", ":b", "a:", ":"] {
            assert!(parse_preopen(bad).is_err(), "`{bad}` parsed");
        }
    }

    #[test]
    fn test_dir_flag_repeats_in_order() {
        let args = CommandArgs::try_parse_from([
            "wasm-bpf",
            "--dir",
            "/host/a:/guest/a",
            "--dir",
            "/host/b:/guest/b",
            "module.wasm",
        ])
        .unwrap();
        assert_eq!(
            args.dir,
            vec![
                (PathBuf::from("/host/a"), PathBuf::from("/guest/a")),
                (PathBuf::from("/host/b"), PathBuf::from("/guest/b")),
            ]
        );
    }

    #[test]
    fn test_dir_flag_stops_at_double_dash() {
        let args = CommandArgs::try_parse_from([
            "wasm-bpf",
            "--dir",
            "/host/a:/guest/a",
            "module.wasm",
            "--",
            "--dir",
            "a:b",
        ])
        .unwrap();
        assert_eq!(
            args.dir,
            vec![(PathBuf::from("/host/a"), PathBuf::from("/guest/a"))]
        );
        assert_eq!(
            args.args_to_wasm,
            vec!["--dir".to_string(), "a:b".to_string()]
        );
    }
}
