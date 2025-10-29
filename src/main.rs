use std::{env, ffi::CString, fs, path::PathBuf};

use anyhow::{bail, Context};
use nix::{mount::{mount, umount2, MntFlags, MsFlags}, sched::{unshare, CloneFlags}, sys::wait::waitpid, unistd::{execve, fork, pivot_root, sethostname, ForkResult}};
use serde::Deserialize;

#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum GenericManifest {
    ManifestList(ManifestList),
    ImageManifest(Manifest)
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ManifestList {
    schema_version: u32,
    media_type: String,
    manifests: Vec<ManifestListItem>
}

#[derive(Deserialize, Debug)]
struct ManifestListItem {
    digest: String,
    platform: Platform
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
    schema_version: u32,
    media_type: String,
    config: Digest,
    layers: Vec<Digest>
}

#[derive(Deserialize, Debug)]
struct Digest {
    digest: String
}

#[derive(Deserialize, Debug)]
struct ImageConfig {
    architecture: String,
    os: String,
    config: ConfigDetails
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct ConfigDetails {
    // Can be null, thats why option
    cmd: Option<Vec<String>>,
    entrypoint: Option<Vec<String>>,
    env: Vec<String>,
    #[serde(rename = "WorkingDir")]
    working_dir: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = std::env::args().collect::<Vec<String>>();

    if args.len() < 2 {
        eprintln!("Usage: {} <image:tag>", args[0]);

        return Ok(());
    }

    let image_ref = &args[1];
    println!("-> Pulling image: {}", image_ref);

    let container_id = "image-container";
    let base_path = PathBuf::from(format!("./woody-image/{}", container_id));
    // idempotency WOW
    if base_path.exists() {
        fs::remove_dir_all(&base_path)?;
    }
    fs::create_dir_all(format!("./woody-image/{}", container_id))?;

    // SECTION image name parsing / token acquisition

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

    // SECTION


    // Get image specification / options before downloading the containers
    let (manifest, config) = fetch_image_manifest(&image_name, &tag, &token, &client).await?;

    let rootfs_path = format!("./woody-image/{}/rootfs", container_id);
    fs::create_dir_all(&rootfs_path)?;

    println!("-> Assembling rootfs at: {}", &rootfs_path);
    download_and_unpack_layers(&image_name, &token, &manifest.layers, &rootfs_path, &client).await?;

    run_container(container_id, config)?;

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

            #[cfg(feature = "debug-reqs")]
            dbg!(amd64_manifest);

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

    #[cfg(feature = "debug-reqs")]
    dbg!(config);

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
        println!("   - Downloading layer {}", &layer.digest[..12]);
        let layer_url = format!("https://registry-1.docker.io/v2/{}/blobs/{}", image_name, layer.digest);
        let response_bytes = client
            .get(&layer_url)
            .bearer_auth(&token)
            .send().await?
            .bytes().await?;

        println!("   - Unpacking layer {}", &layer.digest[..12]);
        let tar = flate2::read::GzDecoder::new(&response_bytes[..]);
        let mut archive = tar::Archive::new(tar);

        archive.unpack(rootfs_path)?;
    }

    Ok(())
}

fn run_container(container_id: &str, config: ImageConfig) -> anyhow::Result<()> {
    if !nix::unistd::geteuid().is_root() {
        bail!("You must run this program as root. Try with sudo.");
    }

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => {
            println!("-> Container Child PID from Parent: {}", child);

            let pid = child.to_string();
            println!("[PARENT] Waiting for child {}...", pid);

            let status = waitpid(child, None)?;
            println!("-> Container exited with status: {:?}", status);
        }
        Ok(ForkResult::Child) => {
            let flags = CloneFlags::CLONE_NEWNS |
                        CloneFlags::CLONE_NEWUTS |
                        CloneFlags::CLONE_NEWIPC |
                        CloneFlags::CLONE_NEWNET;

            unshare(flags).context("Failed to unshare namespaces")?;

            mount_fs(container_id, &config).context("Could not mount fs.")?;

            sethostname("woody-image").context("Failed to set hostname.")?;

            exec_command(config).context("Failed to exec command.")?;

        }
        Err(e) => {
            bail!("Fork failed: {}", e);
        }
    }

    Ok(())
}


fn mount_fs(container_id: &str, config: &ImageConfig) -> anyhow::Result<()> {
    let container_root = fs::canonicalize(format!("./woody-image/{}", container_id))?;
    let rootfs = container_root.join("rootfs");
    let upperdir = container_root.join("upper");
    let workdir = container_root.join("work");
    let merged = container_root.join("merged");
    fs::create_dir_all(&upperdir)?;
    fs::create_dir_all(&workdir)?;
    fs::create_dir_all(&merged)?;
    println!("[Container] Created base overlayFS dirs.");

    mount(None::<&str>, "/", None::<&str>, MsFlags::MS_REC | MsFlags::MS_PRIVATE, None::<&str>)
        .context("Failed to make root mount private")?;

    let mount_opts = format!(
        "lowerdir={},upperdir={},workdir={}",
        rootfs.to_str().unwrap(),
        upperdir.to_str().unwrap(),
        workdir.to_str().unwrap(),
    );
    println!("[Container] Mounting overlayfs to {:?}", &merged);
    mount(Some("overlay"), &merged, Some("overlay"), MsFlags::empty(), Some(mount_opts.as_str()))
        .context("Failed to mount overlayfs")?;

    println!("[Container] Changing CWD to {:?}", &merged);
    env::set_current_dir(&merged).context("Failed to cd into new root")?;

    println!("[Container] Pivoting root and stacking old root at /");
    pivot_root(".", ".").context("pivot_root(.,.) failed")?;

    println!("[Container] Unmounting stacked old root at /");
    umount2("/", MntFlags::MNT_DETACH).context("Failed to unmount old root")?;
    
    env::set_current_dir("/").context("Failed to change directory to new root")?;

    let work_dir = &config.config.working_dir;
    if !work_dir.is_empty() && work_dir != "/" {
        println!("[Container] Setting working directory to {}", work_dir);
        fs::create_dir_all(work_dir)?;
        env::set_current_dir(work_dir).context(format!("Failed to change to working directory: {}", work_dir))?;
    }

    Ok(())
}

fn exec_command(config: ImageConfig) -> anyhow::Result<()> {
    let cmd = config.config.cmd.unwrap_or_default();
    let entrypoint = config.config.entrypoint.unwrap_or_default();

    let (command, args) = if !entrypoint.is_empty() {
        (entrypoint[0].clone(), entrypoint)
    } else if !cmd.is_empty() {
        (cmd[0].clone(), cmd)
    } else {
        bail!("Image has no entrypoint or command specified");
    };

    let command_c = CString::new(command)?;
    let args_c: Vec<CString> = args.iter()
        .map(|s| CString::new(s.as_bytes()).unwrap())
        .collect();
    let env_c: Vec<CString> = config.config.env.iter()
        .map(|s| CString::new(s.as_bytes()).unwrap())
        .collect();

    println!("-> Executing command: {:?}", &args);
    execve(&command_c, &args_c, &env_c)
        .expect("execve failed.");

    Ok(())
}

