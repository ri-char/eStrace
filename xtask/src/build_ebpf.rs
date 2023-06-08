use std::path::PathBuf;
use std::process::Command;

use clap::Parser;

#[derive(Debug, Parser)]
pub struct Options {
    /// Build the release target
    #[clap(long)]
    pub release: bool,
}

pub fn build_ebpf(opts: Options) -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("ebpf");
    let mut args = vec![
        "+nightly",
        "build",
        // "--verbose",
        "--target=bpfel-unknown-none",
        "-Z",
        "build-std=core",
    ];

    if opts.release {
        args.push("--release")
    }
    let status = Command::new("cargo")
        .current_dir(&dir)
        .args(&args)
        .status()
        .expect("failed to build bpf program");
    assert!(status.success());
    Ok(())
}
