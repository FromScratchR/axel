mod network;
mod oci;
mod utils;
mod macros;

#[allow(unused)]
use crate::macros::{axel, axel_err};

use clap::Parser;
use std::{
    fs::{self},
    path::{PathBuf},
    process::Command,
};

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

        /// The command to run in the container
        command: Vec<String>,

        #[arg(short='i', long)]
        interactive: bool
    },
    /// Connects into a running image
    Hook {
        container_id: String,
        #[arg(last = true)]
        command: Vec<String>,
    },
    List,
    Stop {
        container_id: String
    },
    Destroy {},
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run { image, command, interactive } => {
            run_container(&image, command, interactive).await?;
        }
        Commands::Hook { container_id, command } => {
            hook_container(container_id, command)?;
        }
        Commands::List => {
            list_containers()?;
        }
        Commands::Stop { container_id } => {
            stop_container(container_id)?;
        }
        Commands::Destroy {} => todo!(),
    }

    Ok(())
}

fn hook_container(container_id: String, command: Vec<String>) -> anyhow::Result<()> {
    let container_name = utils::normalize_container_id(&container_id);
    let pids_path = PathBuf::from("./axel-pids");

    let bin_path = std::env::current_exe()?.parent().unwrap().join("woody");
    let mut cmd = Command::new(bin_path);
    
    cmd.arg("exec")
        .arg("--pids-path").arg(pids_path)
        .arg(container_name)
        .args(command);

    let status = cmd.status()?;
    if !status.success() {
        axel_err!("Woody exit status: {:?}", status);
    }

    Ok(())
}

fn stop_container(container_id: String) -> anyhow::Result<()> {
    let container_id = utils::normalize_container_id(container_id);

    let pids = PathBuf::from("./axel-pids");
    let target = pids.join(&container_id);

    #[cfg(feature = "dbg")]
    dbg!(&target);

    let container_pid = str::parse::<i32>(&fs::read_to_string(&target)?)?;
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(container_pid), nix::sys::signal::SIGTERM)?;
    fs::remove_file(target)?;

    axel!("{} has stopped", container_id);

    Ok(())
}

fn list_containers() -> anyhow::Result<()> {
    let pids_path = PathBuf::from("./axel-pids");

    if let Ok(dir) = fs::read_dir(pids_path) {
        for entry in dir {
            match entry {
                Ok(e) => {
                    let pid = fs::read_to_string(e.path()).unwrap();
                    axel!("{} - PID {}", e.file_name().to_str().unwrap(), pid);
                }
                Err(e) => {
                    axel_err!("{}", e);
                }
            }
        }
    };

    Ok(())
}

async fn run_container(image_ref: &str, command: Vec<String>, it: bool) -> anyhow::Result<()> {
    let container_name = utils::normalize_container_id(image_ref);

    let image_base_path = PathBuf::from(format!("./axel-images/{}", container_name));
    let rootfs_path = image_base_path.join("rootfs");
    let image_config: network::ConfigDetails;

    // Check for image on cache, otherwise get from registry
    if rootfs_path.exists() && fs::read_dir(&rootfs_path)?.next().is_some() {
        axel!("Using cached image: {}", image_ref);

        let config_path = image_base_path.join("config.json");
        let config_json = fs::read_to_string(config_path)?;

        image_config = serde_json::from_str(&config_json)?;
    } else {
        axel!("Pulling image: {}", image_ref);

        // idempotency :0
        if image_base_path.exists() {
            fs::remove_dir_all(&image_base_path)?;
        }
        fs::create_dir_all(&image_base_path)?;

        let (image_name, tag) = utils::parse_image_name(image_ref);

        // Get Docker specific token (only supported register)
        let client = reqwest::Client::new();
        let token = network::authorize(&client, &image_name).await?;
        let (manifest, fetched_config) =
            network::fetch_image_manifest(&image_name, &tag, &token, &client).await?;

        image_config = fetched_config.config;
        let config_path = image_base_path.join("config.json");
        let config_json = serde_json::to_string(&image_config)?;

        // Save physical config file on container's folder
        fs::write(config_path, config_json)?;
        fs::create_dir_all(&rootfs_path)?;

        #[cfg(feature = "dbg")]
        axel!("Assembling rootfs at: {}", rootfs_path.to_str().unwrap());

        network::download_and_unpack_layers(
            &image_name,
            &token,
            &manifest.layers,
            rootfs_path.to_str().unwrap(),
            &client,
        ).await?;
    }

    // TODO set cache to OCI
    axel!("Generating OCI spec...");

    let spec = oci::generate_oci_config(&image_config, &container_name, command)?;

    // Create bundle directory / Save config.json spec file
    let bundle_path = PathBuf::from(format!("./axel-bundles/{}", container_name));
    fs::create_dir_all(&bundle_path)?;
    let config_path = bundle_path.join("config.json");
    spec.save(&config_path)?;

    axel!("OCI spec saved to {:?}", config_path);

    // Create PID folder if doesnt exist
    let pids_path = PathBuf::from("./axel-pids");
    fs::create_dir_all(&pids_path)?;

    #[cfg(feature = "dbg")]
    axel!("Calling woody...");

    // Assume woody was compiled to the same folder
    let bin_path = std::env::current_exe()?.parent().unwrap().join("woody");

    // Check for systemd-run to enable cgroup delegation
    let has_systemd = std::process::Command::new("which")
        .arg("systemd-run")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let mut cmd;
    if has_systemd {
        // axel!("Detected systemd-run. Wrapping woody to enable Cgroup delegation.");
        cmd = Command::new("systemd-run");
        cmd.arg("--user")
            .arg("--scope")
            .arg("--property=Delegate=yes")
            .arg("--quiet")
            .arg(bin_path) // executable
            .arg("create") // woody args start here
            .arg("--bundle").arg(bundle_path)
            .arg("--pids-path").arg(pids_path)
            .arg(container_name.clone());
    } else {
        axel!("systemd-run not found. Cgroups might fail if not in a delegated scope.");
        cmd = Command::new(bin_path);
        cmd.arg("create")
            .arg("--bundle").arg(bundle_path)
            .arg("--pids-path").arg(pids_path)
            .arg(container_name.clone());
    }

    // it mode
    if it { cmd.arg("--interactive"); }

    // axel!("Executing woody command: {:?}", cmd);

    let status = cmd.status()?;
    if !status.success() {
        axel_err!("Woody exit status: {:?}", status);
    }

    Ok(())
}
