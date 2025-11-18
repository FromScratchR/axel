mod network;
mod oci;
mod utils;

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
        #[arg(short='d', long)]
        detach: bool
    },
    Stop {
        container_id: String
    },
    List,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run { image, command, detach } => {
            run_container(&image, command, detach).await?;
        }
        Commands::List => {
            list_containers()?;
        }
        Commands::Stop { container_id } => {
            stop_container(container_id)?;
        }
    }

    Ok(())
}

fn stop_container(container_id: String) -> anyhow::Result<()> {
    let container_id = container_id.replace(':', "-");
    let pids = PathBuf::from("./axel-pids");
    let target = pids.join(&container_id);
    dbg!(&target);

    let container_pid = str::parse::<i32>(&fs::read_to_string(&target)?)?;
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(container_pid), nix::sys::signal::SIGKILL)?;

    fs::remove_file(target)?;
    println!("[axel] {} has stopped", container_id);

    Ok(())
}

fn list_containers() -> anyhow::Result<()> {
    let pids_path = PathBuf::from("./axel-pids");

    if let Ok(dir) = fs::read_dir(pids_path) {
        for entry in dir {
            match entry {
                Ok(e) => {
                    println!("{} - PID {}", e.file_name().to_str().unwrap(), fs::read_to_string(e.path())?);
                }
                Err(e) => {
                    panic!("{}", e);
                }
            }
        }
    };

    Ok(())
}

async fn run_container(image_ref: &str, command: Vec<String>, detach: bool) -> anyhow::Result<()> {
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

    println!("-> Generating OCI spec...");

    // TODO check if exists
    let spec = oci::generate_oci_config(&image_config, &container_name, command)?;

    // Create bundle directory / save config.json spec
    let bundle_path = PathBuf::from(format!("./axel-bundles/{}", container_name));
    fs::create_dir_all(&bundle_path)?;
    let config_path = bundle_path.join("config.json");
    spec.save(&config_path)?;

    println!("-> OCI spec saved to {:?}", config_path);

    let pids_path = PathBuf::from("./axel-pids");

    fs::create_dir_all(&pids_path)?;

    println!("-> Calling woody...");
    let bin_path = std::env::current_exe()?.parent().unwrap().join("woody");
    let mut cmd = Command::new(bin_path);
    cmd.arg("create")
        .arg("--bundle").arg(bundle_path)
        .arg("--pids-path").arg(pids_path)
        .arg(container_name.clone());

    // -it mode
    if detach { cmd.arg("--detach"); }

    println!("Executing woody command: {:?}", cmd);

    let status = cmd.status()?;
    if status.success() {
        println!("Container '{}' started successfully via woody.", container_name);
    } else {
        eprintln!("Failed to start container via woody.");
        eprintln!("Woody exit status: {:?}", status);
    }

    Ok(())
}
