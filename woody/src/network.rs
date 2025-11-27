use std::{fs, path::Path};

use anyhow::Context;

use crate::macros::woody;

pub fn setup_container_network(rootfs_path: &Path) -> anyhow::Result<()> {
    // Paths def
    let conf_fs_path = "/etc/resolv.conf";
    let host_resolv = Path::new(conf_fs_path);
    let container_resolv = rootfs_path.join(conf_fs_path);

    // Ensure /etc exists
    if let Some(parent) = container_resolv.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::copy(host_resolv, container_resolv).context("Could not copy parent to container fs")?;

    #[cfg(feature = "dbg-ntwk")]
    container!("Injected /etc/resolv.conf");

    Ok(())
}


