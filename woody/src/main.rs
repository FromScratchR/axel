mod container;

use anyhow::Context;
use clap::Parser;
use nix::{
    sched::{clone, CloneFlags},
    unistd::{close, getgid, getuid, write},
};
use oci_spec::runtime::Spec;
use std::{fs::File, io::Write, path::PathBuf};

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
        container_id: String,
    },
}

fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();

    // For now, we implement a simplified "one-shot" runtime.
    // The OCI `create` command will create and run the container.
    // A fully compliant runtime would separate `create` and `start`.
    match opts.command {
        OciCommand::Create {
            bundle,
            pids_path,
            container_id,
        } => {
            let spec_path = bundle.join("config.json");
            let spec = Spec::load(spec_path).context("Failed to load OCI spec")?;
            spawn_container(&spec, &pids_path, &container_id)?;
        }
    };

    Ok(())
}

fn spawn_container(spec: &Spec, pids: &PathBuf, container_id: &String) -> anyhow::Result<i32> {
    let host_uid = getuid();
    let host_gid = getgid();

    let (pipe_read_fd, pipe_write_fd) = nix::unistd::pipe()?;

    const STACK_SIZE: usize = 1024 * 1024;
    let mut stack = vec![0; STACK_SIZE];

    let child_fn = || container::main(pipe_read_fd, pipe_write_fd, spec);

    let flags = CloneFlags::CLONE_NEWUSER
        | CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWUTS
        | CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWIPC;

    let child_pid = clone(
        Box::new(child_fn),
        &mut stack,
        flags,
        Some(nix::sys::signal::Signal::SIGCHLD as i32),
    )
    .context("clone() failed")?;

    let child_pid_path = pids.join(container_id);
    std::fs::write(child_pid_path, child_pid.as_raw().to_string()).context("[woody] Could not write container PID")?;

    println!("[woody] Cloned child with PID: {}", child_pid);

    close(pipe_read_fd)?;

    println!("[woody] Writing map files for child {}", child_pid);
    let mut setgroups_file = File::create(format!("/proc/{}/setgroups", child_pid))
        .context("Failed to open setgroups")?;
    setgroups_file
        .write_all(b"deny")
        .context("Failed to write to setgroups")?;

    let mut uid_map_file =
        File::create(format!("/proc/{}/uid_map", child_pid)).context("Failed to open uid_map")?;
    uid_map_file
        .write_all(format!("0 {} 1", host_uid).as_bytes())
        .context("Failed to write uid_map")?;

    let mut gid_map_file =
        File::create(format!("/proc/{}/gid_map", child_pid)).context("Failed to open gid_map")?;
    gid_map_file
        .write_all(format!("0 {} 1", host_gid).as_bytes())
        .context("Failed to write gid_map")?;

    println!("[woody] Maps written.");
    println!("[woody] Signaling child to continue.");
    write(pipe_write_fd, &[1]).context("write to pipe failed")?;
    close(pipe_write_fd)?;

    // In this one-shot model, woody waits for the child to exit.
    // waitpid(child_pid, None).context("waitpid failed")?;
    println!("[woody] Process exited.");

    Ok(0)
}
