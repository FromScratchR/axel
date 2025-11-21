use std::io::Write;

use anyhow::Context;
use nix::unistd::Pid;

/// Maps host uid/gid into valid root user
///
pub fn map_ugid(child_pid: Pid, host_uid: nix::unistd::Uid, host_gid: nix::unistd::Gid) -> anyhow::Result<()> {
    #[cfg(feature = "dbg")]
    woody!("Writing map files for child {}", child_pid);

    let mut setgroups_file = std::fs::File::create(format!("/proc/{}/setgroups", child_pid))
        .context("Failed to open setgroups")?;
    setgroups_file
        .write_all(b"deny")
        .context("Failed to write to setgroups")?;

    let mut uid_map_file =
        std::fs::File::create(format!("/proc/{}/uid_map", child_pid)).context("Failed to open uid_map")?;
    uid_map_file
        .write_all(format!("0 {} 1", host_uid).as_bytes())
        .context("Failed to write uid_map")?;

    let mut gid_map_file =
        std::fs::File::create(format!("/proc/{}/gid_map", child_pid)).context("Failed to open gid_map")?;
    gid_map_file
        .write_all(format!("0 {} 1", host_gid).as_bytes())
        .context("Failed to write gid_map")?;

    Ok(())
}

