use nix::sched::CloneFlags;
use oci_spec::runtime::LinuxNamespaceType;

pub fn spec_to_flag(s: LinuxNamespaceType) -> CloneFlags {
    match s {
        // "Mount" namespace is historically called CLONE_NEWNS
        LinuxNamespaceType::Mount => CloneFlags::CLONE_NEWNS,
        LinuxNamespaceType::Uts => CloneFlags::CLONE_NEWUTS,
        LinuxNamespaceType::Ipc => CloneFlags::CLONE_NEWIPC,
        LinuxNamespaceType::Pid => CloneFlags::CLONE_NEWPID,
        LinuxNamespaceType::User => CloneFlags::CLONE_NEWUSER,
        // CLONE_NEWTIME requires kernel 5.6+
        LinuxNamespaceType::Time => CloneFlags::empty(),
        LinuxNamespaceType::Cgroup => CloneFlags::CLONE_NEWCGROUP,
        // TODO
        LinuxNamespaceType::Network => CloneFlags::empty(),
    }
}
