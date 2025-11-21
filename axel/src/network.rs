use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::macros::axel;

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum GenericManifest {
    ManifestList(ManifestList),
    ImageManifest(Manifest),
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ManifestList {
    pub manifests: Vec<ManifestListItem>,
}

#[derive(Deserialize, Debug)]
pub struct ManifestListItem {
    pub digest: String,
    pub platform: Platform,
}

#[derive(Deserialize, Debug)]
pub struct Platform {
    pub architecture: String,
    pub os: String,
}

#[derive(Deserialize, Debug)]
pub struct AuthResponse {
    token: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub config: Digest,
    pub layers: Vec<Digest>,
}

#[derive(Deserialize, Debug)]
pub struct Digest {
    pub digest: String,
}

#[derive(Deserialize, Debug)]
pub struct ImageConfig {
    pub config: ConfigDetails,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ConfigDetails {
    pub cmd: Option<Vec<String>>,
    pub entrypoint: Option<Vec<String>>,
    pub env: Vec<String>,
    #[serde(rename = "WorkingDir")]
    pub working_dir: String,
}

pub async fn authorize(client: &reqwest::Client, image_name: &str) -> anyhow::Result<String> {
    let auth_url = format!(
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{}:pull",
        image_name
    );

    let token = client
        .get(&auth_url)
        .send()
        .await?
        .json::<AuthResponse>()
        .await?
        .token;

    #[cfg(feature = "dbg")]
    axel!("Acquired Token; Authorized.");

    Ok(token)
}

pub async fn fetch_image_manifest(
    image_name: &str,
    tag: &str,
    token: &str,
    client: &reqwest::Client,
) -> anyhow::Result<(Manifest, ImageConfig)> {
    let manifest_url = format!(
        "https://registry-1.docker.io/v2/{}/manifests/{}",
        image_name, tag
    );

    let generic_manifest: GenericManifest = client
        .get(&manifest_url)
        .header(
            "Accept",
            "application/vnd.docker.distribution.manifest.v2+json",
        )
        .bearer_auth(token)
        .send()
        .await?
        .json()
        .await
        .context("Failed to deserialize generic manifest")?;

    let final_manifest: Manifest = match generic_manifest {
        GenericManifest::ImageManifest(manifest) => {
            #[cfg(feature = "dbg")]
            axel!("Found single-architecture manifest.");
            manifest
        }
        GenericManifest::ManifestList(list) => {
            #[cfg(feature = "dbg")]
            axel!("Found manifest list. Searching for linux/amd64.");

            let amd64_manifest = list
                .manifests
                .iter()
                .find(|m| m.platform.os == "linux" && m.platform.architecture == "amd64")
                .context("Could not find linux/amd64 manifest in the list")?;

            let manifest_url = format!(
                "https://registry-1.docker.io/v2/{}/manifests/{}",
                image_name, amd64_manifest.digest
            );
            client
                .get(&manifest_url)
                .header(
                    "Accept",
                    "application/vnd.docker.distribution.manifest.v2+json",
                )
                .bearer_auth(token)
                .send()
                .await?
                .json()
                .await
                .context("Failed to deserialize final image manifest")?
        }
    };

    let config_url = format!(
        "https://registry-1.docker.io/v2/{}/blobs/{}",
        image_name, final_manifest.config.digest
    );

    let config: ImageConfig = client
        .get(&config_url)
        .bearer_auth(token)
        .send()
        .await?
        .json()
        .await?;

    Ok((final_manifest, config))
}

pub async fn download_and_unpack_layers(
    image_name: &str,
    token: &str,
    layers: &[Digest],
    rootfs_path: &str,
    client: &reqwest::Client,
) -> anyhow::Result<()> {
    for layer in layers {
        #[cfg(feature = "dbg")]
        axel!("Downloading layer {}", &layer.digest[..12]);

        let layer_url = format!(
            "https://registry-1.docker.io/v2/{}/blobs/{}",
            image_name, layer.digest
        );
        let response_bytes = client
            .get(&layer_url)
            .bearer_auth(token)
            .send()
            .await?
            .bytes()
            .await?;

        #[cfg(feature = "dbg")]
        axel!("Unpacking layer {}", &layer.digest[..12]);

        let tar = flate2::read::GzDecoder::new(&response_bytes[..]);
        let mut archive = tar::Archive::new(tar);
        archive.unpack(rootfs_path)?;
    }
    Ok(())
}
