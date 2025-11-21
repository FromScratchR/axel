use std::{env, ffi::CString, path::Path, str::FromStr};

use anyhow::Context;
use caps::{CapSet, CapsHashSet};
use nix::{
    mount::{mount, umount2, MntFlags, MsFlags},
    unistd::{close, execvp, pivot_root, read, setgid, setuid, Gid, Uid},
};
use oci_spec::runtime::{LinuxCapabilities, Spec};

pub fn main(pipe_read_fd: i32, pipe_write_fd: i32, spec: &Spec) -> isize {
    close(pipe_write_fd).unwrap();
    wait_for_parent_setup(pipe_read_fd);

    if let Some(hostname) = spec.hostname() {
        nix::unistd::sethostname(hostname)
            .context("Failed to set hostname")
            .unwrap();
    }

    configure_fs(spec).expect("Error configuring fs");
    exec_user_process(spec);

    0
}

fn wait_for_parent_setup(pipe_read_fd: i32) {
    println!("[woody-child] Waiting for parent to write maps...");
    let mut buf = [0u8; 1];
    read(pipe_read_fd, &mut buf).expect("[Child] read from pipe failed");
    close(pipe_read_fd).expect("[Child] Could not close pipe");
    println!("[woody-child] Signal received. Maps are written.");

    // TODO set uid/gid handling
    setuid(Uid::from_raw(0)).expect("[Child] setuid(0) failed");
    setgid(Gid::from_raw(0)).expect("[Child] setgid(0) failed");
}

fn configure_fs(spec: &Spec) -> anyhow::Result<()> {
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .context("Failed to make root mount private")?;

    let root = spec.root().as_ref().context("OCI spec has no root")?;
    let rootfs = root.path();

    for m in spec.mounts().as_ref().unwrap() {
        let mount_dest = format!("{}/{}", rootfs.to_str().unwrap(), m.destination().to_str().unwrap());
        let path = Path::new(&mount_dest);
        std::fs::create_dir_all(path)?;

        println!("Mounting {:?} to {:?}", m.source(), m.destination());
        let mut source = m.source().as_ref().map(|p| p.to_str().unwrap());
        let mut fstype = m.typ().as_ref().map(|s| s.as_str());

        let mut flags = MsFlags::empty();
        let mut data_options = Vec::new();

        if let Some(opts) = m.options() {
            for opt in opts {
                match opt.as_str() {
                    // --- Common VFS Flags ---
                    "defaults" => {}, // 'defaults' implies 0 flags (rw, suid, dev, exec, auto, nouser, async)
                    "ro" => flags |= MsFlags::MS_RDONLY,
                    "rw" => {}, // 'rw' is the default (absence of MS_RDONLY), so we do nothing
                    "suid" => {}, // 'suid' is default (absence of MS_NOSUID)
                    "nosuid" => flags |= MsFlags::MS_NOSUID,
                    "dev" => {}, // 'dev' is default
                    "nodev" => flags |= MsFlags::MS_NODEV,
                    "exec" => {}, // 'exec' is default
                    "noexec" => flags |= MsFlags::MS_NOEXEC,
                    "sync" => flags |= MsFlags::MS_SYNCHRONOUS,
                    "async" => {}, // default
                    "dirsync" => flags |= MsFlags::MS_DIRSYNC,
                    "remount" => flags |= MsFlags::MS_REMOUNT,
                    "mand" => flags |= MsFlags::MS_MANDLOCK,
                    "nomand" => {},
                    "atime" => {}, // default
                    "noatime" => flags |= MsFlags::MS_NOATIME,
                    "nodiratime" => flags |= MsFlags::MS_NODIRATIME,
                    "relatime" => flags |= MsFlags::MS_RELATIME,
                    "norelatime" => {},
                    "strictatime" => flags |= MsFlags::MS_STRICTATIME,
                    "gid=5" => data_options.push("gid=0".to_string()),

                    // --- Bind Mounts ---
                    "bind" => flags |= MsFlags::MS_BIND,
                    "rbind" => flags |= MsFlags::MS_BIND | MsFlags::MS_REC,
                    
                    // --- Anything else is treated as filesystem-specific data ---
                    // e.g., "mode=755", "size=65k", "lowerdir=..."
                    other => data_options.push(other.to_string()),
                }
            }
        }

        let data_str = if data_options.is_empty() {
            None
        } else {
            Some(data_options.join(","))
        };
        
        dbg!(&source, &fstype, &flags, &data_str);

        if fstype == Some("sysfs") {
            println!("> [Fix] Detected sysfs mount without Network Namespace. Switching to BIND mount.");
            
            source = Some("/sys"); 
            fstype = None; 
            flags |= MsFlags::MS_BIND | MsFlags::MS_REC;
        }

        else if fstype == Some("cgroup") {
            println!("> [Fix] Switching cgroup to BIND mount.");
            // We bind mount the host's cgroup hierarchy
            source = Some("/sys/fs/cgroup"); 
            fstype = None; 
            flags |= MsFlags::MS_BIND | MsFlags::MS_REC;
        }

        mount(
            source,
            &mount_dest[..],
            fstype,
            flags,
            data_str.as_deref(),
        )?;
    }

    mount(
        Some(rootfs),
        rootfs,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .context("Failed to bind mount rootfs")?;

    println!("[Container] Changing CWD to {:?}", &rootfs);
    env::set_current_dir(&rootfs).context("Failed to cd into new root")?;

    pivot_root(".", ".").context("Could not pivot root")?;

    nix::unistd::chdir("/").context("Could not chdir to new root")?;

    umount2("/", MntFlags::MNT_DETACH).context("Could not unmount old root")?;

    if let Some(linux) = spec.linux() {
        if let Some(ro_paths) = linux.readonly_paths() {
            for path_str in ro_paths {
                let ro_path = Path::new(path_str);
                if !ro_path.exists() {
                    println!("[Container] read-only path {} does not exist, skipping.", path_str);
                    continue;
                }
                println!("[Container] Making path {} read-only", path_str);

                mount(
                    Some(path_str.as_str()),
                    path_str.as_str(),
                    None::<&str>,
                    MsFlags::MS_BIND,
                    None::<&str>,
                )
                .context(format!("Failed to bind mount read-only path {}", path_str))?;

                mount(
                    Some(path_str.as_str()),
                    path_str.as_str(),
                    None::<&str>,
                    MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                    None::<&str>,
                )
                .context(format!("Failed to remount read-only path {}", path_str))?;
            }
        }

        if let Some(masked_paths) = linux.masked_paths() {
            for path_str in masked_paths {
                let masked_path = Path::new(path_str);
                if !masked_path.exists() {
                    println!("[Container] masked path {} does not exist, skipping.", path_str);
                    continue;
                }
                println!("[Container] Masking path {}", path_str);

                let metadata = match std::fs::symlink_metadata(masked_path) {
                    Ok(m) => m,
                    Err(e) => {
                        println!("[woody] Warning: could not get metadata for {}: {}", path_str, e);
                        continue;
                    }
                };

                println!("[Container] Masking path: {}", path_str);

                if metadata.is_dir() {
                    // CASE A: It is a Directory
                    // We cannot put /dev/null here. We mount a read-only tmpfs to make it empty.
                    mount(
                        Some("tmpfs"),
                        path_str.as_str(),
                        Some("tmpfs"),
                        MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
                        Some("size=0,mode=755"), // size=0 ensures it stays empty
                    )
                    .context(format!("Failed to mask directory {}", path_str))?;

                } else {
                    // CASE B: It is a File (or device/socket)
                    // We bind mount /dev/null over it.
                    // Note: This relies on /dev/null being set up correctly in previous steps!
                    mount(
                        Some("/dev/null"),
                        path_str.as_str(),
                        None::<&str>,
                        MsFlags::MS_BIND,
                        None::<&str>,
                    )
                    .context(format!("Failed to mask file {}", path_str))?;
                }
            }
        }
    }

    set_caps(spec.process().as_ref().unwrap().capabilities())?;

    Ok(())
}

fn set_caps(caps: &Option<LinuxCapabilities>) -> anyhow::Result<()> {
    dbg!(&caps);

    if let Some(capabilities) = caps {
        // OCI caps to caps::Caps ("CAP_SYS_ADMIN" to caps::Capability enum)
        let to_set = |names: &Option<oci_spec::runtime::Capabilities>| -> anyhow::Result<CapsHashSet> {
            let mut set = CapsHashSet::new();

            if let Some(names) = names {
                for cap in names {
                    let s = cap.to_string().to_uppercase(); 

                    // Check for "CAP_" prefix and add it if missing
                    let cap_string = if s.starts_with("CAP_") {
                        s
                    } else {
                        format!("CAP_{}", s)
                    };

                    dbg!(&cap_string);

                    // OCI names are "CAP_SYS_ADMIN", caps crate expects "SYS_ADMIN"
                    let cap = caps::Capability::from_str(&cap_string)
                        .map_err(|_| anyhow::anyhow!("Invalid capability: {}", cap.to_string()))?;
                    set.insert(cap);
                }
            }

            Ok(set)
        };

        // Parse all sets from spec
        let effective = to_set(capabilities.effective())?;
        let permitted = to_set(capabilities.permitted())?;
        let inheritable = to_set(capabilities.inheritable())?;
        let bounding = to_set(capabilities.bounding())?;
        let ambient = to_set(capabilities.ambient())?;

        // Clear actual caps
        caps::clear(None, CapSet::Effective).ok();

        caps::set(None, CapSet::Inheritable, &inheritable).context("Failed to set Inheritable caps")?;
        caps::set(None, CapSet::Permitted, &permitted).context("Failed to set Permitted caps")?;

        for cap in ambient {
            caps::raise(None, CapSet::Ambient, cap).context("Failed to raise Ambient cap")?;
        }

        caps::set(None, CapSet::Effective, &effective).context("Failed to set Effective caps")?;
        let all_caps = caps::all(); // Get all supported kernel caps
        for cap in all_caps {
            if !bounding.contains(&cap) {
                // If the spec didn't ask for it, drop it from bounding.
                // Ignore errors here (some caps might not be droppable or supported)
                let _ = caps::drop(None, CapSet::Bounding, cap); 
            }
        }
    };

    Ok(())
}

fn exec_user_process(spec: &Spec) {
    let process = spec.process().as_ref().expect("No process in spec");

    let args = process.args().as_ref().expect("No args in spec");
    let env = process.env().as_ref().expect("No env in spec");
    let cwd = process.cwd();

    nix::unistd::chdir(cwd).expect("Failed to chdir to process cwd");

    let program = CString::new(args[0].clone()).unwrap();
    let args: Vec<CString> = args
        .iter()
        .map(|arg| CString::new(arg.clone()).unwrap())
        .collect();
    let env: Vec<CString> = env
        .iter()
        .map(|e| CString::new(e.clone()).unwrap())
        .collect();

    for e in &env {
        let mut parts = e.to_str().unwrap().splitn(2, '=');
        let key = parts.next().unwrap();
        let value = parts.next().unwrap_or("");
        unsafe { std::env::set_var(key, value); }
    }

    execvp(&program, &args).expect("execve failed");
}
