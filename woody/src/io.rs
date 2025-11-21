use nix::sys::termios::tcsetattr;

pub struct TerminalGuard {
    pub fd: i32,
    pub old_state: nix::sys::termios::Termios
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        // Restore term old state
        tcsetattr(self.fd, nix::sys::termios::SetArg::TCSAFLUSH, &self.old_state).expect("[Error] Could not restore old terminal state");
    }
}

