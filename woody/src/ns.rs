use nix::sched::CloneFlags;
use oci_spec::runtime::Spec;

use crate::utils;

pub fn resolve_flags(spec: &Spec) -> anyhow::Result<CloneFlags> {
    let mut flags = CloneFlags::empty();

    if let Some(linux_spec) = spec.linux() {
        if let Some(namespaces) = linux_spec.namespaces() {
            for ns in namespaces {
                flags |= utils::spec_to_flag(ns.typ());
            }
        }
    };

    Ok(flags)
}

