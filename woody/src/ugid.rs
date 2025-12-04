use std::io::Write;

use anyhow::Context;
use nix::unistd::{getgid, getuid, Pid};
use oci_spec::runtime::Linux;

/// Maps host uid/gid into valid root user
///
pub fn map_ugid(
    child_pid: Pid,
    linux: Option<&Linux>,
) -> anyhow::Result<()> {
    let host_uid = getuid();
    let host_gid = getgid();

    #[cfg(feature = "dbg")]
    woody!("Writing map files for child {}", child_pid);

    // Rootless root delegation xD
    let mut setgroups_file = std::fs::File::create(format!("/proc/{}/setgroups", child_pid))
        .context("Failed to open setgroups")?;
    setgroups_file
        .write_all(b"deny")
        .context("Failed to write to setgroups")?;

    let mut uid_map_content = String::new();
    let mut gid_map_content = String::new();

    if let Some(linux) = linux {
        if let Some(uid_mappings) = linux.uid_mappings() {
            for map in uid_mappings {
                uid_map_content.push_str(&format!(
                    "{} {} {}\n",
                    map.container_id(),
                    map.host_id(),
                    map.size()
                ));
            }
        }

        if let Some(gid_mappings) = linux.gid_mappings() {
            for map in gid_mappings {
                gid_map_content.push_str(&format!(
                    "{} {} {}\n",
                    map.container_id(),
                    map.host_id(),
                    map.size()
                ));
            }
        }
    }

    // Fallback to default rootless mapping if no OCI mappings are provided
    if uid_map_content.is_empty() {
        uid_map_content = format!("0 {} 1", host_uid);
    }

    if gid_map_content.is_empty() {
        gid_map_content = format!("0 {} 1", host_gid);
    }

    let mut uid_map_file =
        std::fs::File::create(format!("/proc/{}/uid_map", child_pid)).context("Failed to open uid_map")?;
    uid_map_file
        .write_all(uid_map_content.as_bytes())
        .context("Failed to write uid_map")?;

    let mut gid_map_file =
        std::fs::File::create(format!("/proc/{}/gid_map", child_pid)).context("Failed to open gid_map")?;
    gid_map_file
        .write_all(gid_map_content.as_bytes())
        .context("Failed to write gid_map")?;

    Ok(())
}

