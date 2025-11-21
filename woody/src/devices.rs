use std::{fs, path::PathBuf};

use nix::unistd::Pid;
use oci_spec::runtime::Spec;

pub fn apply_device_rules(spec: &Spec, child_pid: Pid, container_id: &String) -> anyhow::Result<()> {
    let devices = match spec.linux().as_ref().and_then(|l| l.resources().as_ref().and_then(|r| r.devices().as_ref())) {
        Some(d) if !d.is_empty() => d,
        _ => return Ok(()), // No device rules to apply
    };

    #[cfg(feature = "dbg")]
    woody!("Applying device rules for container {}", container_id);

    // Create cgroup directory for the container
    let cgroup_path = PathBuf::from("/sys/fs/cgroup/devices/woody").join(container_id);
    fs::create_dir_all(&cgroup_path)?;

    // Deny all devices by default, as per OCI spec
    fs::write(cgroup_path.join("devices.deny"), "a *:* rwm")?;

    // Add child PID to the cgroup
    fs::write(cgroup_path.join("cgroup.procs"), child_pid.to_string())?;

    // Apply the specific allow/deny rules from the spec
    for device_rule in devices {
        let major = device_rule.major().map(|v| v.to_string()).unwrap_or_else(|| "*".to_string());
        let minor = device_rule.minor().map(|v| v.to_string()).unwrap_or_else(|| "*".to_string());

        let rule_string = format!(
            "{} {}:{} {}",
            device_rule.typ().map(|t| t.as_str().to_string()).unwrap_or_else(|| "a".to_string()),
            major,
            minor,
            device_rule.access().as_ref().map(|a| a.as_str()).unwrap_or("")
        );

        let target_file = if device_rule.allow() {
            "devices.allow"
        } else {
            "devices.deny"
        };

        fs::write(cgroup_path.join(target_file), rule_string)?;
    }

    Ok(())
}
