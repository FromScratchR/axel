mod container;
mod utils;
mod io;
mod macros;
mod devices;
mod ugid;

use anyhow::Context;
use clap::Parser;
use nix::{
    poll::{poll, PollFd, PollFlags},
    pty::openpty,
    sched::{clone, CloneFlags},
    sys::{
        termios::{tcgetattr, tcsetattr, LocalFlags, SetArg},
        wait::waitpid,
    },
    unistd::{close, dup2, getgid, getuid, read, setsid, write, Pid},
};
use oci_spec::runtime::{Spec};
use std::{
    fs,
    fs::File,
    io::{Write},
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
    };

    Ok(())
}


fn spawn_container(
    spec: &Spec,
    pids: &PathBuf,
    container_id: &String,
    detach: bool,
) -> anyhow::Result<i32> {
    let host_uid = getuid();
    let host_gid = getgid();

    let mut flags = CloneFlags::empty();

    if let Some(linux_spec) = spec.linux() {
        if let Some(namespaces) = linux_spec.namespaces() {
            for nmspc in namespaces {
                flags |= utils::spec_to_flag(nmspc.typ());
            }
        }
    };

    #[cfg(feature = "dbg")]
    println!("[woody] using {:?} flags", flags);

    if detach {
        let (pipe_read_fd, pipe_write_fd) = nix::unistd::pipe()?;

        const STACK_SIZE: usize = 1024 * 1024;
        let mut stack = vec![0; STACK_SIZE];

        let spec_clone = spec.clone();
        let child_fn = || container::main(pipe_read_fd, pipe_write_fd, &spec_clone);

        let child_pid = clone(
            Box::new(child_fn),
            &mut stack,
            flags,
            Some(nix::sys::signal::Signal::SIGCHLD as i32),
        )
        .context("clone() failed")?;

        let child_pid_path = pids.join(container_id);
        std::fs::write(child_pid_path, child_pid.as_raw().to_string())
            .context("Could not write container PID")?;

        #[cfg(feature = "dbg")]
        woody!("Cloned child with PID: {}", child_pid);

        close(pipe_read_fd)?;

        ugid::map_ugid(child_pid, host_uid, host_gid)?;

        devices::apply_device_rules(spec, child_pid, container_id)?;

        #[cfg(feature = "dbg")] {
            woody!("Maps written.");
            woody!("Signaling child to continue.");
        }

        write(pipe_write_fd, &[1]).context("write to pipe failed")?;
        close(pipe_write_fd)?;

        woody!("Process exited.");
    } else {
        let pty = openpty(None, None).context("openpty failed")?;
        let master_fd = pty.master;
        let slave_fd = pty.slave;

        let (pipe_read_fd, pipe_write_fd) = nix::unistd::pipe()?;

        // Generate session helper fn
        nix::ioctl_write_int_bad!(tiocsctty, nix::libc::TIOCSCTTY);

        const STACK_SIZE: usize = 1024 * 1024;
        let mut stack = vec![0; STACK_SIZE];

        let spec_clone = spec.clone();
        let child_fn = move || {
            close(master_fd).unwrap();

            // Set new terminal session as detached
            setsid().unwrap();

            // Set section master
            unsafe { tiocsctty(slave_fd, 1).expect("Failed to set controlling TTY"); }

            // Set stdin / out / err onto slave_fd
            dup2(slave_fd, 0).unwrap();
            dup2(slave_fd, 1).unwrap();
            dup2(slave_fd, 2).unwrap();
            close(slave_fd).unwrap();

            container::main(pipe_read_fd, pipe_write_fd, &spec_clone)
        };

        let child_pid = clone(
            Box::new(child_fn),
            &mut stack,
            flags,
            Some(nix::sys::signal::Signal::SIGCHLD as i32),
        )
        .context("clone() failed")?;

        // Remove base fd from process
        close(slave_fd)?;
        close(pipe_read_fd)?;

        let child_pid_path = pids.join(container_id);
        std::fs::write(child_pid_path, child_pid.as_raw().to_string())
            .context("Could not write container PID")?;

        #[cfg(feature = "dbg")] {
            woody!("Cloned child with PID: {}", child_pid);
            woody!("Writing map files for child {}", child_pid);
        }

        ugid::map_ugid(child_pid, host_uid, host_gid)?;

        devices::apply_device_rules(spec, child_pid, container_id)?;

        #[cfg(feature = "dbg")] {
            woody!("[woody] Maps written.");
            woody!("[woody] Signaling child to continue.");
        }

        write(pipe_write_fd, &[1]).context("write to pipe failed")?;
        close(pipe_write_fd)?;

        println!("[woody-debug] Entering interactive mode setup");
        let term_fd = std::io::stdin().as_raw_fd();
        let mut termios = tcgetattr(term_fd).context("tcgetattr failed")?;

        let _term_guard = TerminalGuard {
            fd: term_fd,
            old_state: termios.clone(),
        };

        #[cfg(feature = "dbg")]
        woody!("Putting terminal in raw mode");

        // Apply custom flags to this process' terminal (prepare for multiplexing)
        termios.local_flags &= !(LocalFlags::ICANON | LocalFlags::ECHO | LocalFlags::IEXTEN | LocalFlags::ISIG);
        tcsetattr(term_fd, SetArg::TCSAFLUSH, &termios).context("tcsetattr failed")?;

        #[cfg(feature = "dbg")]
        woody!("[woody-debug] Terminal is in raw mode");

        let mut fds = [
            PollFd::new(term_fd, PollFlags::POLLIN),
            PollFd::new(master_fd, PollFlags::POLLIN),
        ];

        loop {
            // Multiplex by waiting term_fd (stdin of this process) / master_fs (PTY portal)
            poll(&mut fds, -1).context("poll failed")?;

            // Keyboard (stdin)
            if let Some(revents) = fds[0].revents() {
                if revents.contains(PollFlags::POLLIN) {
                    let mut buf = [0u8; 1024];
                    let n = read(term_fd, &mut buf).context("read from stdin failed")?;
                    if n == 0 {
                        #[cfg(feature= "dbg")]
                        woody!("stdin read 0 bytes, breaking loop");

                        break;
                    }

                    write(master_fd, &buf[..n]).context("write to master failed")?;
                }
            }

            // Shell (master_fd)
            if let Some(revents) = fds[1].revents() {
                if revents.contains(PollFlags::POLLIN) {
                    let mut buf = [0u8; 1024];
                    let n = read(master_fd, &mut buf).context("read from master failed")?;
                    if n == 0 {
                        #[cfg(feature= "dbg")]
                        woody!("[woody-debug] master_fd read 0 bytes, breaking loop");
                        break;
                    }
                    write(std::io::stdout().as_raw_fd(), &buf[..n])
                        .context("write to stdout failed")?;
                }
            }
        }
        
        #[cfg(feature = "dbg")] {
            woody!("Poll loop exited");
            woody!("Waiting for child process {}", child_pid);
        }

        waitpid(child_pid, None).context("waitpid() failed")?;

        #[cfg(feature = "dbg")]
        woody!("[woody-debug] waitpid finished");
    }

    woody!("Process exited.");

    Ok(0)
}
