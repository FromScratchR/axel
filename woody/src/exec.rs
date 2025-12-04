use anyhow::{Context, Result};
use nix::pty::openpty;
use nix::sched::{setns, CloneFlags};
use nix::sys::termios::{tcgetattr, tcsetattr, LocalFlags, SetArg};
use nix::sys::wait::waitpid;
use nix::unistd::{close, dup2, fork, setsid, write, ForkResult};
use nix::poll::{poll, PollFd, PollFlags};
use nix::errno::Errno;
use std::ffi::CString;
use std::fs::{self, File};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use nix::unistd::read;

use crate::io::TerminalGuard;

#[allow(unused)]
use crate::macros::{woody, woody_err};

pub fn run(pids_path: PathBuf, container_id: String, command: Vec<String>) -> Result<()> {
    let pid_path = pids_path.join(&container_id);
    dbg!(&pid_path);

    let pid_str = fs::read_to_string(&pid_path)
        .with_context(|| format!("Failed to read PID file for {}", container_id))?;
    let target_pid = pid_str.trim();

    woody!("Attaching to container {} (PID: {})", container_id, target_pid);

    // Open namespace files
    // Order matters? User NS first usually helps with capabilities.
    let ns_types = [
        ("user", CloneFlags::CLONE_NEWUSER),
        ("mnt", CloneFlags::CLONE_NEWNS),
        ("ipc", CloneFlags::CLONE_NEWIPC),
        ("uts", CloneFlags::CLONE_NEWUTS),
        ("net", CloneFlags::CLONE_NEWNET),
        ("pid", CloneFlags::CLONE_NEWPID),
    ];

    let mut ns_fds = Vec::new();
    for (ns_name, _) in ns_types.iter() {
        let ns_path = format!("/proc/{}/ns/{}", target_pid, ns_name);
        let f = File::open(&ns_path).with_context(|| format!("Failed to open ns {}", ns_path))?;
        ns_fds.push((f, ns_name));
    }

    // Setup PTY
    let pty = openpty(None, None).context("openpty failed")?;
    let master_fd = pty.master;
    let slave_fd = pty.slave;

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            close(slave_fd)?;

            woody!("Child process spawned: {}", child);

            // Handle PTY I/O (copied/adapted from main.rs)
            let term_fd = std::io::stdin().as_raw_fd();
            let mut termios = tcgetattr(term_fd).context("tcgetattr failed")?;
            let _term_guard = TerminalGuard {
                fd: term_fd,
                old_state: termios.clone(),
            };

            termios.local_flags &= !(LocalFlags::ICANON | LocalFlags::ECHO | LocalFlags::IEXTEN | LocalFlags::ISIG);
            tcsetattr(term_fd, SetArg::TCSAFLUSH, &termios).context("tcsetattr failed")?;

            let mut fds = [
                PollFd::new(term_fd, PollFlags::POLLIN),
                PollFd::new(master_fd, PollFlags::POLLIN),
            ];

            loop {
                poll(&mut fds, -1).context("poll failed")?;

                if let Some(revents) = fds[0].revents() {
                    if revents.contains(PollFlags::POLLIN) {
                        let mut buf = [0u8; 1024];
                        let n = read(term_fd, &mut buf).context("read from stdin failed")?;
                        if n == 0 { break; }
                        write(master_fd, &buf[..n]).context("write to master failed")?;
                    }
                }

                if let Some(revents) = fds[1].revents() {
                    if revents.contains(PollFlags::POLLHUP) {
                        break;
                    }
                    if revents.contains(PollFlags::POLLIN) {
                        let mut buf = [0u8; 1024];
                        match read(master_fd, &mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                write(std::io::stdout().as_raw_fd(), &buf[..n])?;
                            }
                            Err(e) => {
                                if e == Errno::EIO { break; }
                            }
                        }
                    }
                }
            }

            waitpid(child, None)?;
        }
        Ok(ForkResult::Child) => {
            close(master_fd).unwrap();

            // Enter namespaces
            for (file, name) in ns_fds {
                 // CloneFlags::empty() lets kernel figure it out from fd, 
                 // or strictly check? woody create uses explicit flags.
                 // setns(fd, flag)
                 // We need to map name to flag again or just use empty if safe.
                 // Usually 0 is fine if fd is correct.
                 if let Err(e) = setns(file.as_raw_fd(), CloneFlags::empty()) {
                     eprintln!("Failed to enter {} namespace: {}", name, e);
                     std::process::exit(1);
                 }
            }

            setsid().unwrap();
            nix::ioctl_write_int_bad!(tiocsctty, nix::libc::TIOCSCTTY);
            unsafe { tiocsctty(slave_fd, 1).expect("Failed to set controlling TTY"); }

            dup2(slave_fd, 0).unwrap();
            dup2(slave_fd, 1).unwrap();
            dup2(slave_fd, 2).unwrap();
            close(slave_fd).unwrap();

            // Execute command
            let cmd = if command.is_empty() {
                "/bin/sh"
            } else {
                &command[0]
            };
            
            let args: Vec<CString> = if command.is_empty() {
                 vec![CString::new("/bin/sh").unwrap()]
            } else {
                command.iter().map(|s| CString::new(s.as_str()).unwrap()).collect()
            };

            // We need to fork AGAIN if we just joined PID namespace?
            // "A process can't enter a new PID namespace and be a member of it; 
            // setns(CLONE_NEWPID) only affects children."
            // So the current process is still in the old PID namespace (but inside other NSs).
            // We need to fork one more time to be *inside* the PID namespace?
            // Yes, usually: setns -> fork -> parent waits -> child is in PID ns.
            
            match unsafe { fork() } {
                Ok(ForkResult::Parent { child: _ }) => {
                    // We are the intermediate process. 
                    // We entered NSs, then forked.
                    // We should wait for the real child.
                    // But wait, our parent (woody main) is waiting for us.
                    // If we wait here, we are good.
                    // But we already did setsid/dup2? 
                    // If we fork, the child inherits fds.
                    let mut status = 0;
                    unsafe { nix::libc::wait(&mut status) };
                    std::process::exit(0);
                },
                Ok(ForkResult::Child) => {
                    // This child is in the new PID namespace (and others).
                    // It inherited stdio (slave_fd).
                    let c_cmd = CString::new(cmd).unwrap();
                    let _ = nix::unistd::execvp(&c_cmd, &args);
                    eprintln!("Failed to exec: {}", cmd);
                    std::process::exit(1);
                }
                Err(_) => std::process::exit(1),
            }
        }
        Err(_) => {
            anyhow::bail!("Fork failed");
        }
    }

    Ok(())
}
