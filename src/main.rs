use std::{ffi::CString, fs::{self, canonicalize, File}, io::Write, path::PathBuf};

use anyhow::{bail, Context};
use clap::Parser;
use nix::{mount::{mount, umount2, MntFlags, MsFlags}, sched::{clone, unshare, CloneFlags}, sys::wait::waitpid, unistd::{close, execve, getgid, getuid, pivot_root, read, setgid, setuid, write, Gid, Uid}};
use serde::{Deserialize, Serialize};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Parser, Debug)]
enum Commands {
    /// Run a command in a new container
    Run {
        /// The image to run, e.g., alpine:latest
        image: String,
    },
    List,
    /// Stop a running container
    Stop {
        /// The ID of the container to stop
        container_id: String,
    },
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum GenericManifest {
    ManifestList(ManifestList),
    ImageManifest(Manifest),
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ManifestList {
    manifests: Vec<ManifestListItem>,
}

#[derive(Deserialize, Debug)]
struct ManifestListItem {
    digest: String,
    platform: Platform,
}

#[derive(Deserialize, Debug)]
struct Platform {
    architecture: String,
    os: String,
}

#[derive(Deserialize, Debug)]
struct AuthResponse {
    token: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    config: Digest,
    layers: Vec<Digest>,
}

#[derive(Deserialize, Debug)]
struct Digest {
    digest: String,
}

#[derive(Deserialize, Debug)]
struct ImageConfig {
    config: ConfigDetails,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
struct ConfigDetails {
    cmd: Option<Vec<String>>,
    entrypoint: Option<Vec<String>>,
    env: Vec<String>,
    #[serde(rename = "WorkingDir")]
    working_dir: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run { image } => {
            run_container(&image).await?;
        }
        Commands::List => {
            list_containers()
        }
        Commands::Stop {
            container_id
        } => {
            stop_container(&container_id)?;
        }
    }

    Ok(())
}

fn list_containers() {
    let pids_path = PathBuf::from("./woody-pids");

    if let Ok(entries) = fs::read_dir(pids_path) {
        for entry in entries {
            match entry {
                Ok(file) => {
                    let file_name = file.file_name().into_string().unwrap();


                    let pid = &fs::read(file.path()).unwrap();

                    println!("[{}] - {}", file_name, std::str::from_utf8(pid).unwrap());
                }
                Err(e) => {
                    panic!("Could not open entry {}", e);
                }
            }
        }
    };
}

fn stop_container(container_id: &str) -> anyhow::Result<()> {
    let container_name = container_id.replace(":", "-");
    println!("-> Stopping container: {}", container_name);

    let pids_dir = PathBuf::from("./woody-pids");
    let pid_file_path = pids_dir.join(format!("{}.pid", container_name));

    if !pid_file_path.exists() {
        bail!("Container '{}' is not running or PID file not found.", container_name);
    }

    let pid_str = fs::read_to_string(&pid_file_path)?;
    let pid = nix::unistd::Pid::from_raw(pid_str.trim().parse::<i32>()?);

    // Kill the container process
    nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL)?;
    println!("[Parent] Sent SIGKILL to PID {}", pid);

    // Wait for the process to be reaped to avoid zombies
    let wait_status = waitpid(pid, None);
    println!("[Parent] Container process reaped with status: {:?}", wait_status);

    // Unmount overlayfs
    let merged_path = PathBuf::from(format!("./woody-images/{}/merged", container_name));
    println!("[Parent] Unmounting {:?}", merged_path);
    umount2(&merged_path, MntFlags::MNT_DETACH).context("Failed to unmount overlay FS")?;

    // Clean up PID file
    fs::remove_file(&pid_file_path)?;

    println!("-> Container '{}' stopped successfully.", container_name);

    Ok(())
}


async fn run_container(image_ref: &str) -> anyhow::Result<()> {
    let container_name = image_ref.replace(":", "-");
    let base_path = PathBuf::from(format!("./woody-images/{}", container_name));
    let rootfs_path = base_path.join("rootfs");

    let config: ConfigDetails;

    if rootfs_path.exists() && fs::read_dir(&rootfs_path)?.next().is_some() {
        println!("-> Using cached image: {}", image_ref);
        let config_path = base_path.join("config.json");
        let config_json = fs::read_to_string(config_path)?;
        config = serde_json::from_str(&config_json)?;
    } else {
        println!("-> Pulling image: {}", image_ref);
        if base_path.exists() {
            fs::remove_dir_all(&base_path)?;
        }
        fs::create_dir_all(&base_path)?;

        let (image_name, tag) = parse_image_name(image_ref);
        let client = reqwest::Client::new();
        let auth_url = format!(
            "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{}:pull",
            image_name
        );
        let token = client
            .get(&auth_url)
            .send().await?
            .json::<AuthResponse>()
            .await?
            .token;

        let (manifest, fetched_config) = fetch_image_manifest(&image_name, &tag, &token, &client).await?;
        config = fetched_config.config;

        let config_path = base_path.join("config.json");
        let config_json = serde_json::to_string(&config)?;
        fs::write(config_path, config_json)?;

        fs::create_dir_all(&rootfs_path)?;
        println!("-> Assembling rootfs at: {}", rootfs_path.to_str().unwrap());
        download_and_unpack_layers(&image_name, &token, &manifest.layers, rootfs_path.to_str().unwrap(), &client).await?;
    }

    spawn_container(&container_name, &config);
    Ok(())
}

fn parse_image_name(image_ref: &str) -> (String, String) {
    // Image / Tag split parsing
    let (image, tag) = image_ref.split_once(':').unwrap_or((image_ref, "latest"));
    let image_name = if image.contains('/') { image.to_string() } else { format!("library/{}", image) };

    (image_name.to_owned(), tag.to_owned())
}

async fn fetch_image_manifest(
    image_name: &str,
    tag: &str,
    token: &String,
    client: &reqwest::Client
) -> anyhow::Result<(Manifest, ImageConfig)> {
    // Manifest get
    let manifest_url = format!("https://registry-1.docker.io/v2/{}/manifests/{}", image_name, tag);

    let generic_manifest: GenericManifest = client
        .get(&manifest_url)
        .header("Accept", "application/vnd.docker.distribution.manifest.v2+json")
        .bearer_auth(&token)
        .send().await?
        .json().await
        .context("Failed to deserialize generic manifest")?;

    let final_manifest_digest;
    let final_manifest: Manifest;

    match generic_manifest {
        GenericManifest::ImageManifest(manifest) => {
            println!("-> Found single-architecture manifest.");
            final_manifest = manifest;
        }
        GenericManifest::ManifestList(list) => {
            println!("-> Found manifest list. Searching for linux/amd64.");

            let amd64_manifest = list.manifests.iter()
            .find(|m| m.platform.os == "linux" && m.platform.architecture == "amd64")
            .context("Could not find linux/amd64 manifest in the list")?;

            final_manifest_digest = amd64_manifest.digest.clone();
            let manifest_url = format!("https://registry-1.docker.io/v2/{}/manifests/{}", image_name, final_manifest_digest);
            final_manifest = client
                .get(&manifest_url)
                .header("Accept", "application/vnd.docker.distribution.manifest.v2+json")
                .bearer_auth(&token)
                .send().await?
                .json().await
                .context("Failed to deserialize final image manifest")?;
        }
    }

    // Config get
    let config_url = format!("https://registry-1.docker.io/v2/{}/blobs/{}", image_name, final_manifest.config.digest);
    let config: ImageConfig = client
        .get(&config_url)
        .bearer_auth(&token)
        .send().await?
        .json().await?;

    Ok((final_manifest, config))
}

async fn download_and_unpack_layers(
    image_name: &str,
    token: &String,
    layers: &[Digest],
    rootfs_path: &str,
    client: &reqwest::Client
) -> anyhow::Result<()> {
    for layer in layers {
        println!("[Woody] Downloading layer {}", &layer.digest[..12]);
        let layer_url = format!("https://registry-1.docker.io/v2/{}/blobs/{}", image_name, layer.digest);
        let response_bytes = client
            .get(&layer_url)
            .bearer_auth(&token)
            .send().await?
            .bytes().await?;

        println!("[Woody] Unpacking layer {}", &layer.digest[..12]);
        let tar = flate2::read::GzDecoder::new(&response_bytes[..]);
        let mut archive = tar::Archive::new(tar);

        archive.unpack(rootfs_path)?;
    }

    Ok(())
}

fn spawn_container(container_name: &str, config: &ConfigDetails) {
    let host_uid = getuid().as_raw();
    let host_gid = getgid().as_raw();

    println!("[Parent] Host UID: {}, Host GID: {}", host_uid, host_gid);

    // Pipe for synchronizing parent and child
    let (pipe_read_fd, pipe_write_fd) = nix::unistd::pipe().unwrap();

    const STACK_SIZE: usize = 1024 * 1024; // 1 MB;
    let mut stack = vec![0; STACK_SIZE];

    let cloned_config = config.clone();
    let child_fn = move || child_main(pipe_read_fd, pipe_write_fd, container_name, &cloned_config);

    // Clone with NEWUSER
    let flags = CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS;
    let child_pid = clone(
        Box::new(child_fn),
        &mut stack,
        flags,
        Some(nix::sys::signal::Signal::SIGCHLD as i32),
    )
    .expect("[Parent] clone() failed");

    // Save PID to file
    let pids_dir = PathBuf::from("./woody-pids");
    fs::create_dir_all(&pids_dir).expect("Could not create pids directory");
    let pid_file_path = pids_dir.join(format!("{}.pid", container_name));
    fs::write(pid_file_path, child_pid.to_string()).expect("Could not write PID file");


    println!("[Parent] Cloned child with PID: {}", child_pid);

    close(pipe_read_fd).unwrap();

    println!("[Parent] Writing map files for child {}", child_pid);

    // Deny setgroups
    let mut setgroups_file = File::create(format!("/proc/{}/setgroups", child_pid))
        .expect("Failed to open setgroups");
    setgroups_file.write_all(b"deny")
        .expect("Failed to write setgroups");

    // Write UID map
    let mut uid_map_file = File::create(format!("/proc/{}/uid_map", child_pid))
        .expect("Failed to open uid_map");
    uid_map_file.write_all(format!("0 {} 1", host_uid).as_bytes())
        .expect("Failed to write uid_map");

    // Write GID map
    let mut gid_map_file = File::create(format!("/proc/{}/gid_map", child_pid))
        .expect("Failed to open gid_map");
    gid_map_file.write_all(format!("0 {} 1", host_gid).as_bytes())
        .expect("Failed to write gid_map");

    println!("[Parent] Maps written.");

    // Signal the child (by writing to the pipe) that it can proceed
    println!("[Parent] Signaling child to continue.");
    write(pipe_write_fd, &[1]).expect("[Parent] write to pipe failed");
    close(pipe_write_fd).unwrap();

    // Detach from the child process, allowing it to run in the background
    println!("[Parent] Detaching from child process. Container is running in the background.");
    println!("[Parent] To stop the container, run: woody stop {}", container_name);
}

fn child_main(pipe_read_fd: i32, pipe_write_fd: i32, container_name: &str, config: &ConfigDetails) -> isize {
    close(pipe_write_fd).unwrap();

    // wait for uid/gid parent set
    wait_for_parent(pipe_read_fd);

    // overlayfs
    configure_fs(container_name).expect("Error configuring fs");

    exec(config);

    0
}

fn wait_for_parent(pipe_read_fd: i32) {
    println!("[Child] Waiting for parent to write maps...");

    let mut buf = [0u8; 1];
    read(pipe_read_fd, &mut buf).expect("[Child] read from pipe failed");
    close(pipe_read_fd).expect("[Child] Could not close pipe");
    println!("[Child] Signal received. Maps are written.");

    setuid(Uid::from_raw(0)).expect("[Child] setuid(0) failed");
    setgid(Gid::from_raw(0)).expect("[Child] setgid(0) failed");
}

fn configure_fs(container_name: &str) -> anyhow::Result<()> {
    use std::fs::create_dir_all as cd;

    // 1. Create paths
    let base = canonicalize(format!("./woody-images/{}", container_name))?;
    let rootfs = base.join("rootfs");
    let upper = base.join("upper");
    let work = base.join("work");
    let merged = base.join("merged");

    // rootfs is already created
    cd(&upper)?;
    cd(&work)?;
    cd(&merged)?;
    println!("[Child] Created base directories for overlay.");

    // 4. Mount / as private
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    ).context("Failed to mount '/' container fs.")?;
    println!("[Child] Mounted '/'");

    // 5. Attempt overlayfs mount
    let mount_opts = format!(
        "lowerdir={},upperdir={},workdir={}",
        rootfs.to_str().unwrap(),
        upper.to_str().unwrap(),
        work.to_str().unwrap()
    );

    mount(
        Some("overlay"),
        &merged,
        Some("overlay"),
        MsFlags::empty(),
        Some(mount_opts.as_str())
    ).context("Could not mount overlay fs.")?;
    println!("[Child] Created overlayFS.");

    std::env::set_current_dir(&merged).context("[Child] Could not change cwd")?;
    println!("[Child] Changed cwd.");

    pivot_root(".", ".").context("[Child] Could not pivot root")?;
    println!("[Child] Pivoted root.");

    umount2("/", MntFlags::MNT_DETACH).context("[Child] Could not unmount stacked fs")?;
    println!("[Child] Isolated environment.");

    Ok(())
}

fn exec(config: &ConfigDetails) {
    println!("[Child] Executing commands...");

    dbg!(config);

    // Set working directory
    if !config.working_dir.is_empty() {
        std::env::set_current_dir(&config.working_dir)
            .expect("Could not set working directory");
    }

    // Prepare environment variables
    let env_vars: Vec<CString> = config.env
        .iter()
        .map(|e| CString::new(e.clone()).unwrap())
        .collect();

    let mut command_args: Vec<CString> = Vec::new();

    // Determine the command and arguments
    if let Some(entrypoint) = &config.entrypoint {
        command_args.extend(entrypoint.iter().map(|s| CString::new(s.clone()).unwrap()));
        if let Some(cmd) = &config.cmd {
            command_args.extend(cmd.iter().map(|s| CString::new(s.clone()).unwrap()));
        }
    } else if let Some(cmd) = &config.cmd {
        command_args.extend(cmd.iter().map(|s| CString::new(s.clone()).unwrap()));
    } else {
        panic!("No command or entrypoint specified in config");
    }

    if command_args.is_empty() {
        panic!("Command arguments are empty");
    }

    let program = command_args[0].clone();
    nix::unistd::execve(&program, &command_args, &env_vars).expect("Could not exec command");
}
