use std::os::fd::AsRawFd;

use anyhow::Context;
use nix::{errno::Errno, poll::{poll, PollFd, PollFlags}, sys::termios::{tcgetattr, tcsetattr, LocalFlags, SetArg}, unistd::{dup2, read, setsid}};

use crate::io::TerminalGuard;

/// Create current terminal termios and uses TermGuard in order to save its state;
/// As well as evoke poll();
///
pub fn interactive_mode(master_fd: i32) -> anyhow::Result<()> {
    let term_fd = std::io::stdin().as_raw_fd();
    // Get current terminal information (create a snapshot of it)
    let mut termios = tcgetattr(term_fd).context("tcgetattr failed")?;

    // Automatically restore terminal previous state
    let _term_guard = TerminalGuard {
        fd: term_fd,
        old_state: termios.clone(),
    };

    #[cfg(feature = "dbg")]
    woody!("Putting terminal in raw mode");

    // Apply custom flags to this process' terminal (prepare for multiplexing)
    termios.local_flags &= !(LocalFlags::ICANON | LocalFlags::ECHO | LocalFlags::IEXTEN | LocalFlags::ISIG);
    // Apply new rules
    tcsetattr(term_fd, SetArg::TCSAFLUSH, &termios).context("tcsetattr failed")?;

    #[cfg(feature = "dbg")]
    woody!("Terminal is in raw mode");

    crate::it::pool(term_fd, master_fd)
}

/// Handles new PTY state
///
fn pool(term_fd: i32, master_fd: i32) -> anyhow::Result<()> {
    // At this point, main_fd points to container's master_fd which points to the slave_fd
    // which is connected to stdin, stdout and stderr of container
    let mut fds = [
        PollFd::new(term_fd, PollFlags::POLLIN),
        PollFd::new(master_fd, PollFlags::POLLIN),
    ];

    // Set handling for receiving / sending information on a two-sided way (receive/send to container)
    loop {
        // Multiplex by waiting term_fd (stdin of this process) / master_fs (PTY portal)
        poll(&mut fds, -1).context("poll failed")?;

        // Keyboard (stdin) to container's stdin
        if let Some(revents) = fds[0].revents() {
            if revents.contains(PollFlags::POLLIN) {
                let mut buf = [0u8; 1024];
                let n = read(term_fd, &mut buf).context("read from stdin failed")?;
                if n == 0 {
                    #[cfg(feature= "dbg")]
                    woody!("stdin read 0 bytes, breaking loop");

                    break;
                }

                nix::unistd::write(master_fd, &buf[..n]).context("write to master failed")?;
            }
        }

        // Shell (master_fd)
        // Container is writing to master_fd
        // so we propagate until the source (stdin of this process)
        if let Some(revents) = fds[1].revents() {
            // Check if the PTY hung up (Child closed/exited)
            if revents.contains(PollFlags::POLLHUP) {
                #[cfg(feature = "dbg")]
                woody!("Master PTY received POLLHUP. Child likely exited.");
                break;
            }

            if revents.contains(PollFlags::POLLIN) {
                let mut buf = [0u8; 1024];

                match read(master_fd, &mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        nix::unistd::write(std::io::stdout().as_raw_fd(), &buf[..n])
                        .context("write to stdout failed")?;
                    }
                    Err(e) => {
                        if e == Errno::EIO {
                            #[cfg(feature = "dbg")]
                            woody!("Master PTY returned EIO (Slave closed). Exiting loop.");
                            break;
                        }
                        // Propagate other actual errors
                    }
                }
            }
        }
    }

    Ok(())
}

/// Assign slave_fd as process stdin/stdout/stderr
///
pub fn set_slave(slave_fd: i32) {
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
