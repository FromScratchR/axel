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

    let (pipe_write_fd, pipe_read_fd) = nix::unistd::pipe()?;
    let ctn_pid = clone(
        Box::new(|| container::main(pipe_write_fd, pipe_read_fd, spec, it)),
        &mut vec![0; consts::CONTAINER_STACK_SIZE],
        flags,
        Some(SIGCHLD)
    )?;

    close(pipe_read_fd)?;

    ugid::map_ugid(ctn_pid, spec.linux().as_ref())?;
    devices::apply_device_rules(spec, ctn_pid, ctn_id)?;
    cgroups::handle(&spec, ctn_pid)?;

    write(pipe_write_fd, &[1])?;
    close(pipe_write_fd)?;

    if it.is_some() {
        it::interactive_mode(master_fd)?;
    };

    close(master_fd)?;
    waitpid(ctn_pid, None)?;

    Ok(ctn_pid)
}
