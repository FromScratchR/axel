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

use anyhow::Context;
use clap::Parser;
use nix::{
    errno::Errno, poll::{poll, PollFd, PollFlags}, pty::openpty, sched::{clone, CloneFlags}, sys::{
        termios::{tcgetattr, tcsetattr, LocalFlags, SetArg},
        wait::waitpid,
    }, unistd::{close, dup2, getgid, getuid, read, setsid, write}
};
use oci_spec::runtime::{Spec};
use std::{
    os::unix::io::AsRawFd,
    path::PathBuf,
};

use crate::{io::TerminalGuard};
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
        detach: bool,
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
            detach,
        } => {
            let spec_path = bundle.join("config.json");
            let spec = Spec::load(spec_path).context("Failed to load OCI spec")?;
            spawn_container(&spec, &pids_path, &container_id, detach)?;
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
    detach: bool,
) -> anyhow::Result<i32> {
    let flags = ns::resolve_flags(spec)?;

    #[cfg(feature = "dbg-flags")]
    println!("[woody] using {:?} flags", flags);

    let (pipe_read_fd, pipe_write_fd) = nix::unistd::pipe()?;

    const STACK_SIZE: usize = 1024 * 1024;
    let mut stack = vec![0; STACK_SIZE];

    let pty = openpty(None, None).context("openpty failed")?;
    let master_fd = pty.master;
    let slave_fd = pty.slave;

    let child_fn = move || {
        if !detach {
            // Set new terminal session as detached
            setsid().unwrap();
            // Generate section master fn
            nix::ioctl_write_int_bad!(tiocsctty, nix::libc::TIOCSCTTY);
            // Set section master
            unsafe { tiocsctty(slave_fd, 1).expect("Failed to set controlling TTY"); }

            // Set stdin / out / err onto slave_fd
            dup2(slave_fd, 0).unwrap();
            dup2(slave_fd, 1).unwrap();
            dup2(slave_fd, 2).unwrap();
        }

        close(master_fd).unwrap();
        close(slave_fd).unwrap();

        container::main(pipe_read_fd, pipe_write_fd, &spec)
    };

    let child_pid = clone(
        Box::new(child_fn),
        &mut stack,
        flags,
        Some(nix::sys::signal::Signal::SIGCHLD as i32),
    )
    .context("clone() failed")?;

    // Read is not needed
    close(pipe_read_fd)?;

    let child_pid_path = pids.join(container_id);
    std::fs::write(child_pid_path, child_pid.as_raw().to_string())
        .context("Could not write container PID")?;

    #[cfg(feature = "dbg")] {
        woody!("Cloned child with PID: {}", child_pid);
        woody!("Writing map files for child {}", child_pid);
    }

    ugid::map_ugid(child_pid, spec.linux().as_ref())?;

    devices::apply_device_rules(spec, child_pid, container_id)?;

    cgroups::handle(&spec, child_pid)?;

    #[cfg(feature = "dbg")] {
        woody!("[woody] Maps written.");
        woody!("[woody] Signaling child to continue.");
    }

    // Sinalize to OK to child
    write(pipe_write_fd, &[1]).context("write to pipe failed")?;
    // Write is not needed anymore
    close(pipe_write_fd)?;

    woody!("Process running with PID: {}.", &child_pid);

    #[cfg(feature = "dbg")] {
        woody!("Poll loop exited");
        woody!("Waiting for child process {}", child_pid);
    }

    if !detach {
        crate::it::interactive_mode(master_fd)?;
        waitpid(child_pid, None).context("waitpid() failed")?;
    }

    #[cfg(feature = "dbg")]
    woody!("waitpid finished");

    woody!("Process exited.");

    Ok(0)
}
