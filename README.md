# `axel`

<img src=".github/axel-icon.png" align="right" height="165px" />

A experimental daemonless container management tool.

- 🫚 **Rootless**: Do not require high-privilege users in order to run.
- 👹 **No Daemons**: Do not lie on background services to work.
- 🪶 **Lightweight**: ~5.6mb binary size.
- 📦 **Self-Contained**: Requires no external deps.
- 🛌 **Easy-to-Use**: Simple commands executes the entire workflow.

Axel has it's own hand-crafted container runtime, *woody* which works like *runc*.

The project's main goal is to learn what really containers are, how they are made and how they work, as well as to develop something valuable on the path;

It is very lightweight and runs on a simple spawned process managed by Woody. Looks much more like a youki/Podman than a Docker in it's architecture.
And the best: it is rootless; What greatly reduces the surface of security attacks.

> 💡 Unlike Docker it doesn't depends on a daemon like _dockerd_, containers are managed entirelly using Axel and it's back-end: Woody.

## 🖲️ Usage

<div align='center'>
    <img src='.github/demo.gif' alt='axel demo' />
</div>

## How to Use

### Commands

## OCI Support

## Architecture

## Shades

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
