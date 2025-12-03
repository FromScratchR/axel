use nix::sys::termios::tcsetattr;

use crate::macros::woody_err;

pub struct TerminalGuard {
    pub fd: i32,
    pub old_state: nix::sys::termios::Termios
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        // Restore term old state
        // We use if let Err(...) to consume/log the error instead of panicking
        if let Err(e) = tcsetattr(self.fd, nix::sys::termios::SetArg::TCSAFLUSH, &self.old_state) {
            woody_err!("Error: Could not restore old terminal state: {}", e);
        }
    }
}

