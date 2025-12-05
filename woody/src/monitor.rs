use std::path::PathBuf;

use anyhow::Context;
use nix::{libc::SIGCHLD, sched::clone, sys::wait::waitpid, unistd::{close, dup2, write, Pid}};
use oci_spec::runtime::Spec;

use crate::{cgroups, consts, container, devices, it, ns, ugid};

/// Manage container's process state
///
/// This clones and create the container process itself;
/// It is responsible primarly for removing the process PID from ${pids-folder};
///
///
pub fn start(ctn_id: &String, woody_write_fd: i32, spec: &Spec, it: bool) -> anyhow::Result<Pid> {
    let flags = ns::resolve_flags(spec)?;
    #[cfg(feature = "dbg-flags")]
    println!("[woody] using {:?} flags", flags);

    if !it {
        let null_path = PathBuf::from("/dev/null");
        let null_fd = nix::fcntl::open(
            &null_path,
            nix::fcntl::OFlag::O_RDWR,
            nix::sys::stat::Mode::empty()
        )?;

        dup2(null_fd, 0)?;
        dup2(null_fd, 1)?;
        dup2(null_fd, 2)?;
        if null_fd > 2 {
            close(null_fd)?;
        }
    }

    let term = nix::pty::openpty(None, None)?;
    let (master_fd, slave_fd) = (term.master, term.slave);

    let (pipe_read_fd, pipe_write_fd) = nix::unistd::pipe()?;
    let ctn_pid = clone(
        Box::new(|| {
            // Close the pipe write end inherited from monitor to prevent hanging the parent
            close(woody_write_fd).ok();
            container::main(pipe_write_fd, pipe_read_fd, spec, slave_fd)
        }),
        &mut vec![0; consts::CONTAINER_STACK_SIZE],
        flags,
        Some(SIGCHLD)
    )?;

    // Send PID to woody
    nix::unistd::write(woody_write_fd, ctn_pid.to_string().as_bytes())?;
    close(woody_write_fd)?;

    // Slave_fd is not needed here anymore
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

    if it {
        it::interactive_mode(master_fd)?;
    }

    waitpid(ctn_pid, None)?;

    // Close on process exit
    if it {
        close(master_fd)?;
    }

    Ok(ctn_pid)
}

fn write_ctn_pid(ctn_id: &String, ctn_pid: Pid) -> anyhow::Result<()> {
    let pids_path = PathBuf::from("./axel-pids");
    let ctn_pid_path = pids_path.join(ctn_id);

    std::fs::write(ctn_pid_path, ctn_pid.as_raw().to_string())
    .context("Could not write container PID")?;

    Ok(())
}
