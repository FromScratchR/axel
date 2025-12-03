use std::{fs, path::Path};

use anyhow::Context;

use crate::{macros::container};

pub fn setup_container_network(rootfs_path: &Path) -> anyhow::Result<()> {
    // Paths def
    let conf_fs_path = "/etc/resolv.conf";
    let host_resolv = Path::new(conf_fs_path);
    let container_resolv = rootfs_path.join(conf_fs_path);

    // Ensure /etc exists
    use std::os::unix::fs::MetadataExt;
    if let Some(parent) = container_resolv.parent() {
        if !parent.exists() {
            println!("[woody] Creating /etc directory at {:?}", parent);
            fs::create_dir_all(parent)?;
        } else if let Ok(meta) = fs::metadata(parent) {
             println!("[woody-debug] /etc permissions: mode={:o}, uid={}, gid={}", meta.mode(), meta.uid(), meta.gid());
        }
    }

    if container_resolv.exists() {
        if let Ok(meta) = fs::metadata(&container_resolv) {
             println!("[woody-debug] /etc/resolv.conf permissions: mode={:o}, uid={}, gid={}", meta.mode(), meta.uid(), meta.gid());
        }

        println!("[woody] Target /etc/resolv.conf exists. Removing it to overwrite.");
        if let Err(e) = fs::remove_file(&container_resolv) {
            println!("[woody] Warning: Failed to remove existing /etc/resolv.conf: {}", e);
        }
    }

    println!("[woody] Copying host {:?} to container {:?}", host_resolv, container_resolv);
    if let Err(e) = fs::copy(host_resolv, container_resolv) {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            println!("[woody] Warning: Failed to inject /etc/resolv.conf: Permission denied. Networking (DNS) might be broken.");
            return Ok(());
        }
        return Err(e).context("Could not copy parent to container fs");
    }

    #[cfg(feature = "dbg-ntwk")]
    container!("Injected /etc/resolv.conf");

    Ok(())
}


