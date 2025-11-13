mod network;
mod oci;
mod utils;

use clap::Parser;
use nix::{
    sys::signal::{self, Signal},
    unistd::Pid,
};
use std::{
    fs::{self},
    path::{Path, PathBuf},
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
    },
    List,
    /// Stop a running container
    Stop {
        /// The ID of the container to stop
        container_id: String,
    },
    /// Show logs for a container
    Logs {
        container_id: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run { image } => {
            run_container(&image).await?;
        }
        Commands::List => {
            list_containers();
        }
        Commands::Stop { container_id } => {
            ax_stop(&container_id)?;
        }
        Commands::Logs { container_id } => {
            ax_show_logs(&container_id)?;
        }
    }

    Ok(())
}

fn list_containers() {
    // This needs to be adapted to how conmon stores state
    println!("Listing containers is not yet implemented with conmon.");
}

async fn run_container(image_ref: &str) -> anyhow::Result<()> {
    let container_name = image_ref.replace(':', "-");
    let image_base_path = PathBuf::from(format!("./axel-images/{}", container_name));
    let rootfs_path = image_base_path.join("rootfs");

    let image_config: network::ConfigDetails;

    if rootfs_path.exists() && fs::read_dir(&rootfs_path)?.next().is_some() {
        println!("-> Using cached image: {}", image_ref);
        let config_path = image_base_path.join("config.json");
        let config_json = fs::read_to_string(config_path)?;
        image_config = serde_json::from_str(&config_json)?;
    } else {
        println!("-> Pulling image: {}", image_ref);
        if image_base_path.exists() {
            fs::remove_dir_all(&image_base_path)?;
        }
        fs::create_dir_all(&image_base_path)?;

        let (image_name, tag) = utils::parse_image_name(image_ref);
        let client = reqwest::Client::new();

        let token = network::authorize(&client, &image_name).await?;

        let (manifest, fetched_config) =
            network::fetch_image_manifest(&image_name, &tag, &token, &client).await?;
        image_config = fetched_config.config;

        let config_path = image_base_path.join("config.json");
        let config_json = serde_json::to_string(&image_config)?;
        fs::write(config_path, config_json)?;

        fs::create_dir_all(&rootfs_path)?;
        println!("-> Assembling rootfs at: {}", rootfs_path.to_str().unwrap());
        network::download_and_unpack_layers(
            &image_name,
            &token,
            &manifest.layers,
            rootfs_path.to_str().unwrap(),
            &client,
        )
        .await?;
    }

    // 1. Generate OCI spec config.json
    println!("-> Generating OCI spec...");
    let spec = oci::generate_oci_config(&image_config, &container_name)?;

    // 2. Create bundle directory
    let bundle_path = PathBuf::from(format!("./axel-bundles/{}", container_name));
    fs::create_dir_all(&bundle_path)?;

    // 3. Save spec to config.json in the bundle
    let config_path = bundle_path.join("config.json");
    spec.save(&config_path)?;
    println!("-> OCI spec saved to {:?}", config_path);

    // 4. Call conmon
    println!("-> Calling conmon...");
    run_conmon(&container_name, bundle_path.to_str().unwrap())?;

    Ok(())
}

fn run_conmon(container_id: &str, bundle_path: &str) -> std::io::Result<()> {
    // This directory should be configurable
    let conmon_state_dir = Path::new("/tmp/axel-conmon");
    fs::create_dir_all(conmon_state_dir)?;

    let pid_file = conmon_state_dir.join(format!("{}.pid", container_id));
    let log_file = conmon_state_dir.join(format!("{}.log", container_id));
    
    // This needs to point to the woody binary, which needs to be in the PATH
    // or specified with an absolute path.
    let runtime_bin = "woody"; 

    println!("  Conmon state dir: {}", conmon_state_dir.display());
    println!("  Container ID: {}", container_id);
    println!("  Bundle path: {}", bundle_path);
    println!("  Runtime: {}", runtime_bin);


    let mut cmd = Command::new("conmon");
    cmd.arg("--api-version").arg("1")
        .arg("-c").arg(container_id)
        .arg("-n").arg(container_id) // Use same for name
        .arg("-b").arg(bundle_path)
        .arg("--log-level").arg("debug")
        .arg("--pidfile").arg(pid_file)
        .arg("--log-path").arg(log_file)
        .arg("--runtime").arg(runtime_bin);

    println!("Executing conmon command: {:?}", cmd);

    let status = cmd.status()?;

    if status.success() {
        println!("Container '{}' started successfully via conmon.", container_id);
    } else {
        eprintln!("Failed to start conmon. It might not be in your PATH.");
        eprintln!("Conmon exit status: {:?}", status);
    }

    Ok(())
}

fn ax_show_logs(container_id: &str) -> std::io::Result<()> {
    let container_name = container_id.replace(':', "-");
    let log_path = PathBuf::from(format!("/tmp/axel-conmon/{}.log", container_name));
    let contents = fs::read_to_string(log_path)?;
    println!("{}", contents);
    Ok(())
}

fn ax_stop(container_id: &str) -> std::io::Result<()> {
    let container_name = container_id.replace(':', "-");
    let pid_path = PathBuf::from(format!("/tmp/axel-conmon/{}.pid", container_name));
    
    let pid_str = fs::read_to_string(pid_path)?;
    let pid_int: i32 = pid_str.trim().parse().expect("Invalid PID file");
    
    signal::kill(Pid::from_raw(pid_int), Signal::SIGTERM)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        
    println!("Sent SIGTERM to container process {}", container_id);
    Ok(())
}
