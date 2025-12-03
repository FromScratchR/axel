# `axel`

<img src=".github/axel-icon.png" align="right" height="165px" />

A experimental daemonless container management tool.

- **Rootless**: Do not require privileged state users in order to run.
- **Zero Contiguos-Overhead**: Do not lie on background services to work.
- **Lightweight**: **~[]x**mb binary size.
- **Self-Contained**: Requires no external deps.
- **Easy-to-use**: Simple commands executes the entire workflow.

Axel doesn't depends on daemons and has it's own hand-crafted container runtime, *woody* which works like *runc*.

The project's main goal is to learn what really containers are, how they are made and how they work, as well as to develop something valuable on the path;
It is very lightweight and runs on a simple spawned process which does not require a daemon in order to run, looks much more like a youki/Podman than a Docker.
And the best: it is rootless; What greatly reduces the surface of security attacks.

Unlike Podman it doesn't depends on a daemon like _conmon_ or _dockerd_ like Docker, containers are managed entirelly using Axel and it's back-end: Woody.

<div align='center'>
    <img src='.github/demo.gif' alt='axel demo' />
</div>


## How to use

## Commands

## OCI Support

## Shades

## Architecture

## Roadmap

- [x] Rootless API architecture
- [x] Run/list/stop/delete containers
- [x] Docker registry complete compatibility
- [x] Interactive shell (-it) / Detach mode (-d)
- [x] Custom PTY Handling
- [x] Network connection
- [x] OCI-Compliant support
    - [x] Hostname
    - [x] Process (user, args, env, cwd)
    - [x] Cgroups
    - [x] Capabilities
    - [x] Namespaces
    - [x] Masked Paths
    - [x] Read-Only Paths
    - [x] Mounts
    - [x] UID/GID Maps
- [x] Container's network internal replication (network fallback)
- [ ] YAML batch config/action support
- [x] Graceful PTY shutdown
- [ ] General registries compatibility
- [ ] Network custom configuration ([pasta](https://passt.top/passt/about/))
- [ ] Network internal bridges
- [ ] PSI usage metrics

## Contributing

## License

MIT
