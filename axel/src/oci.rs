use oci_spec::runtime::{
    LinuxBuilder, LinuxNamespaceBuilder, LinuxNamespaceType, ProcessBuilder, RootBuilder, Spec,
    SpecBuilder,
};

use crate::network;

pub fn generate_oci_config(
    image_config: &network::ConfigDetails,
    container_name: &str,
    command: Vec<String>,
) -> anyhow::Result<Spec> {
    let rootfs_path = std::fs::canonicalize(format!("./axel-images/{}/rootfs", container_name))?;

    let mut process_args: Vec<String> = Vec::new();
    if !command.is_empty() {
        process_args.extend(command);
    } else {
        if let Some(entrypoint) = &image_config.entrypoint {
            process_args.extend(entrypoint.clone());
        }
        if let Some(cmd) = &image_config.cmd {
            process_args.extend(cmd.clone());
        }
        if process_args.is_empty() {
            // Default to sh if no command is specified
            process_args.push("/bin/sh".to_string());
        }
    }

    let process = ProcessBuilder::default()
        .args(process_args)
        .cwd(&image_config.working_dir)
        .env(image_config.env.clone())
        .terminal(true)
        .build()?;

    let root = RootBuilder::default()
        .path(rootfs_path)
        .readonly(false)
        .build()?;

    let linux = LinuxBuilder::default()
        .namespaces(vec![
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Pid)
                .build()?,
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Ipc)
                .build()?,
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Uts)
                .build()?,
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Mount)
                .build()?,
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::User)
                .build()?,
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Cgroup)
                .build()?,
        ])
        .build()?;

    let spec = SpecBuilder::default()
        .process(process)
        .root(root)
        .hostname(container_name)
        .linux(linux)
        .build()?;

    Ok(spec)
}
