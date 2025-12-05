use std::path::PathBuf;

use anyhow::Context;
use nix::{libc::SIGCHLD, sched::clone, sys::wait::waitpid, unistd::{close, write, Pid}};
use oci_spec::runtime::Spec;

use crate::{cgroups, consts, container, devices, it, ns, ugid};

/// Manage container's process state
///
/// This clones and create the container process itself;
/// It is responsible primarly for removing the process PID from ${pids-folder};
///
///
pub fn start(ctn_id: &String, spec: &Spec, it: bool) -> anyhow::Result<Pid> {
    let flags = ns::resolve_flags(spec)?;
    #[cfg(feature = "dbg-flags")]
    println!("[woody] using {:?} flags", flags);

    let term = nix::pty::openpty(None, None)?;
    let (master_fd, slave_fd) = (term.master, term.slave);

    // Coerce it type
    let it = if it == true { Some(slave_fd) } else { None };

    let (pipe_read_fd, pipe_write_fd) = nix::unistd::pipe()?;
    let ctn_pid = clone(
        Box::new(|| container::main(pipe_write_fd, pipe_read_fd, spec, it)),
        &mut vec![0; consts::CONTAINER_STACK_SIZE],
        flags,
        Some(SIGCHLD)
    )?;

    close(slave_fd)?;
    close(pipe_read_fd)?;

    // Configure container process
    ugid::map_ugid(ctn_pid, spec.linux().as_ref())?;
    devices::apply_device_rules(spec, ctn_pid, ctn_id)?;
    cgroups::handle(&spec, ctn_pid)?;

    // Signal child to continue
    write(pipe_write_fd, &[1])?;
    close(pipe_write_fd)?;

    write_ctn_pid(ctn_id, ctn_pid)?;

    if it.is_some() {
        it::interactive_mode(master_fd)?;
    };

    close(master_fd)?;
    waitpid(ctn_pid, None)?;

    Ok(ctn_pid)
}

fn write_ctn_pid(ctn_id: &String, ctn_pid: Pid) -> anyhow::Result<()> {
    let pids_path = PathBuf::from("./axel-pids");
    let ctn_pid_path = pids_path.join(ctn_id);

    std::fs::write(ctn_pid_path, ctn_pid.as_raw().to_string())
    .context("Could not write container PID")?;

    Ok(())
}
