use std::{ffi::CString, fs};

use anyhow::Context;
use nix::{mount::{mount, umount2, MntFlags, MsFlags}, unistd::{close, pivot_root, read, setgid, setuid, Gid, Uid, execve}};
use oci_spec::runtime::Spec;

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

    // In a proper implementation, we would mount all mounts from spec.mounts()
    // For now, we just pivot_root into the rootfs.

    let old_root_put_dir = "oldroot";
    
    // We must chdir into the new root *before* pivot_root
    nix::unistd::chdir(rootfs)?;
    fs::create_dir_all(old_root_put_dir)?;

    pivot_root(".", old_root_put_dir).context("Could not pivot root")?;
    
    nix::unistd::chdir("/").context("Could not chdir to new root")?;

    umount2(old_root_put_dir, MntFlags::MNT_DETACH).context("Could not unmount old root")?;
    fs::remove_dir(old_root_put_dir)?;

    Ok(())
}

fn exec_user_process(spec: &Spec) {
    let process = spec.process().as_ref().expect("No process in spec");

    let args = process.args().as_ref().expect("No args in spec");
    let env = process.env().as_ref().expect("No env in spec");
    let cwd = process.cwd();

    nix::unistd::chdir(cwd).expect("Failed to chdir to process cwd");

    let program = CString::new(args[0].clone()).unwrap();
    let args: Vec<CString> = args.iter().map(|arg| CString::new(arg.clone()).unwrap()).collect();
    let env: Vec<CString> = env.iter().map(|e| CString::new(e.clone()).unwrap()).collect();

    execve(&program, &args, &env).expect("execve failed");
}
