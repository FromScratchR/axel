mod container;
mod utils;
mod io;
mod macros;
mod devices;
mod ugid;
mod cgroups;
mod network;
mod exec;
mod ns;
mod it;
mod monitor;
mod consts;

use anyhow::Context;
use clap::Parser;
use nix::{
    pty::openpty, sched::clone, sys::wait::waitpid, unistd::{close, dup2, setsid, write, ForkResult}
};
use oci_spec::runtime::{Spec};
use std::{
    path::PathBuf,
};

#[allow(unused)]
use crate::macros::{woody, woody_err};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Opts {
    #[command(subcommand)]
    command: OciCommand,
}

#[derive(Parser, Debug)]
enum OciCommand {
    /// Create a container
    #[command(name = "create")]
    Create {
        #[arg(short, long)]
        bundle: PathBuf,
        #[arg(short, long)]
        pids_path: PathBuf,
        #[arg(short, long)]
        it: bool,
        container_id: String,
    },
    /// Execute a command in a running container
    #[command(name = "exec")]
    Exec {
        #[arg(short, long)]
        pids_path: PathBuf,
        container_id: String,
        #[arg(last = true)]
        command: Vec<String>,
    },
}

fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();

    match opts.command {
        OciCommand::Create {
            bundle,
            pids_path,
            container_id,
            it,
        } => {
            let spec_path = bundle.join("config.json");
            let spec = Spec::load(spec_path).context("Failed to load OCI spec")?;
            spawn_container(&spec, &pids_path, &container_id, it)?;
        }
        OciCommand::Exec {
            pids_path,
            container_id,
            command,
        } => {
            exec::run(pids_path, container_id, command)?;
        }
    };

    Ok(())
}

fn spawn_container(
    spec: &Spec,
    pids: &PathBuf,
    container_id: &String,
    it: bool,
) -> anyhow::Result<i32> {
    // Init double-fork pattern
    // This create a decoupled monitor process which handles the cleanup and metrics of the container
    match unsafe { nix::unistd::fork() } {
        Ok(ForkResult::Parent { child: monitor_pid } ) => {
            if it {
                waitpid(monitor_pid, None)?;
            }
        },
        Ok(ForkResult::Child) => {
            let container_pid = monitor::start(container_id, spec, it).unwrap();
            let container_pid_path = pids.join(container_id);

            std::fs::write(container_pid_path, container_pid.as_raw().to_string())
            .context("Could not write container PID")?;

            std::process::exit(0)
        }
        Err(e) => {
            woody_err!("Failed to init monitor: {:?}", e);
        }
    }

    #[cfg(feature = "dbg")] {
        woody!("Cloned child with PID: {}", child_pid);
        woody!("Writing map files for child {}", child_pid);
    }

    woody!("Process exited.");

    Ok(0)
}
