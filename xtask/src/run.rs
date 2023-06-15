use std::{os::unix::process::CommandExt, process::Command};

use anyhow::Context as _;
use clap::Parser;

use crate::build_ebpf::{build_ebpf, Options as BuildOptions};

#[derive(Debug, Parser)]
pub struct Options {
    /// Set the target architecture
    #[clap(default_value = "x86_64-unknown-linux-musl", long)]
    pub arch: String,
    /// Build and run the release target
    #[clap(long)]
    pub release: bool,
    /// The command used to wrap your application
    #[clap(short, long, default_value = "sudo -E")]
    pub runner: String,
    /// Arguments to pass to your application
    #[clap(name = "args", last = true)]
    pub run_args: Vec<String>,
}

/// Build the project
pub fn build(opts: &Options) -> Result<(), anyhow::Error> {
    // build our ebpf program followed by our application
    build_ebpf(BuildOptions {
        release: opts.release,
    })
    .context("Error while building eBPF program")?;

    let mut args = vec!["build", "--package", "estrace"];
    let target = format!("--target={}", opts.arch);
    args.push(&target);
    if opts.release {
        args.push("--release");
    }
    let status = Command::new("cargo")
        .args(&args)
        .status()
        .expect("failed to build userspace");
    assert!(status.success());
    println!(
        "The result is at target/{}/{}/estrace",
        opts.arch,
        if opts.release { "release" } else { "debug" }
    );
    Ok(())
}

/// Build and run the project
pub fn run(opts: Options) -> Result<(), anyhow::Error> {
    build(&opts).context("Error while building userspace application")?;

    // profile we are building (release or debug)
    let bin_path = format!(
        "target/{}/{}/estrace",
        opts.arch,
        if opts.release { "release" } else { "debug" }
    );

    // arguments to pass to the application
    let mut run_args: Vec<_> = opts.run_args.iter().map(String::as_str).collect();

    // configure args
    let mut args: Vec<_> = opts.runner.trim().split_terminator(' ').collect();
    args.push(bin_path.as_str());
    args.append(&mut run_args);

    // spawn the command
    let err = Command::new(args.first().expect("No first argument"))
        .args(args.iter().skip(1))
        .exec();

    // we shouldn't get here unless the command failed to spawn
    Err(anyhow::Error::from(err).context(format!("Failed to run `{}`", args.join(" "))))
}
