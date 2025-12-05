use anyhow::{Context, Result};
use nix::pty::openpty;
use nix::sched::{setns, CloneFlags};
use nix::sys::wait::waitpid;
use nix::unistd::{close, fork, ForkResult};
use oci_spec::runtime::{LinuxNamespaceType, Spec};
use std::ffi::CString;
use std::fs::{self, File};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;

use crate::it;
#[allow(unused)]
use crate::macros::{woody, woody_err};

pub fn run(pids_path: PathBuf, container_id: String, command: Vec<String>) -> Result<()> {
    let pid_path = pids_path.join(&container_id);

    let pid_str = fs::read_to_string(&pid_path)
        .with_context(|| format!("Failed to read PID file for {}", container_id))?;
    let target_pid = pid_str.trim();

    woody!("Attaching to container {} (PID: {})", container_id, target_pid);

    // Load OCI Spec to determine active namespaces
    let config_path = PathBuf::from("axel-bundles").join(&container_id).join("config.json");
    let spec = Spec::load(&config_path)
        .with_context(|| format!("Failed to load OCI spec from {:?}", config_path))?;

    // Collect enabled namespace types from spec
    let enabled_ns: Vec<LinuxNamespaceType> = spec.linux()
        .as_ref()
        .and_then(|l| l.namespaces().as_ref())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|ns| ns.typ())
        .collect();

    // Map logic: define all supported namespaces and their flags
    let supported_ns = [
        ("user", CloneFlags::CLONE_NEWUSER, LinuxNamespaceType::User),
        ("mnt", CloneFlags::CLONE_NEWNS, LinuxNamespaceType::Mount),
        ("ipc", CloneFlags::CLONE_NEWIPC, LinuxNamespaceType::Ipc),
        ("uts", CloneFlags::CLONE_NEWUTS, LinuxNamespaceType::Uts),
        ("net", CloneFlags::CLONE_NEWNET, LinuxNamespaceType::Network),
        ("pid", CloneFlags::CLONE_NEWPID, LinuxNamespaceType::Pid),
    ];

    let mut ns_fds = Vec::new();
    for (ns_name, _, ns_type) in supported_ns.iter() {
        if enabled_ns.contains(ns_type) {
            let ns_path = format!("/proc/{}/ns/{}", target_pid, ns_name);
            let f = File::open(&ns_path).with_context(|| format!("Failed to open ns {}", ns_path))?;
            ns_fds.push((f, ns_name));
        }
    }

    // Setup PTY
    let pty = openpty(None, None).context("openpty failed")?;
    let master_fd = pty.master;
    let slave_fd = pty.slave;

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            close(slave_fd)?;

            woody!("Child process spawned: {}", child);

            it::interactive_mode(master_fd)?;
            waitpid(child, None)?;
        }
        Ok(ForkResult::Child) => {
            close(master_fd).unwrap();
            dbg!(&ns_fds);

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
            
            match unsafe { fork() } {
                Ok(ForkResult::Parent { child: _ }) => {
                    let mut status = 0;
                    unsafe { nix::libc::wait(&mut status) };
                    std::process::exit(0);
                },
                Ok(ForkResult::Child) => {
                    it::set_slave(slave_fd);

                    // Set Env
                    unsafe { std::env::set_var("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"); }
                    unsafe { std::env::set_var("TERM", "xterm"); }

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
