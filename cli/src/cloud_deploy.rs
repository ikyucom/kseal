//! A Google Cloud Deploy custom target that seeds Secret Manager.
//!
//! Cloud Deploy runs this for both a release's render and a rollout's deploy,
//! saying which in `CLOUD_DEPLOY_REQUEST_TYPE`, and reads the outcome from a
//! `results.json` it expects in `CLOUD_DEPLOY_OUTPUT_GCS_PATH`
//! (<https://docs.cloud.google.com/deploy/docs/custom-targets>). A release's
//! source is one environment's directory. The environment itself comes from the
//! custom target type's environment variables, not from the release, so a
//! release can supply sealed files but cannot point them at another key ring,
//! project, or state:
//!
//! - `KSEAL_KEY_RING`: the key ring every sealed file and the `.kseal.kdl` must use
//! - `KSEAL_PROJECT`: the project holding the environment's secrets
//! - `KSEAL_STATE`: the state object, `gs://BUCKET/OBJECT`
//!
//! Render checks the source like `kseal seed --check` and passes it on; deploy
//! seeds it like `kseal seed`.

use std::path::{Path, PathBuf};

use google_cloud_storage::client::Storage;
use kseal_google_cloud::seed;

use crate::CliResult;

/// Serve a Google Cloud Deploy custom target that seeds Secret Manager,
/// configured by environment variables (see the README)
#[derive(argh::FromArgs)]
#[argh(subcommand, name = "cloud-deploy")]
pub struct CloudDeploy {}

type Error = Box<dyn std::error::Error>;

impl CloudDeploy {
    pub async fn run(self) -> CliResult {
        let output = var("CLOUD_DEPLOY_OUTPUT_GCS_PATH")?;
        let storage = Storage::builder().build().await?;
        let outcome = serve(&storage, &output).await;
        let results = match &outcome {
            Ok(results) => results.clone(),
            Err(e) => {
                serde_json::json!({"resultStatus": "FAILED", "failureMessage": e.to_string()})
            }
        };
        upload(
            &storage,
            &format!("{output}/results.json"),
            results.to_string().into_bytes(),
        )
        .await?;
        outcome.map(|_| ())
    }
}

/// Do what the request asks and return the results Cloud Deploy reads.
async fn serve(storage: &Storage, output: &str) -> Result<serde_json::Value, Error> {
    let env = seed::Environment {
        key_ring: var("KSEAL_KEY_RING")?.parse()?,
        project: var("KSEAL_PROJECT")?,
        state: var("KSEAL_STATE")?.parse()?,
    };
    let input = var("CLOUD_DEPLOY_INPUT_GCS_PATH")?;
    match var("CLOUD_DEPLOY_REQUEST_TYPE")?.as_str() {
        "RENDER" => {
            // The release's source archive, checked and passed on unchanged.
            let archive = download(storage, &input).await?;
            let dir = Unpacked::new(&archive)?;
            let sealed = crate::check_environment(dir.path(), &env).await?;
            let manifest: String = sealed
                .iter()
                .map(|s| {
                    format!(
                        "{}\t{}\t{}\n",
                        s.secret(),
                        s.body_sha256,
                        file_name(&s.path)
                    )
                })
                .collect();
            let manifest_at = format!("{output}/manifest.tsv");
            upload(storage, &manifest_at, manifest.into_bytes()).await?;
            upload(storage, &format!("{output}/source.tgz"), archive).await?;
            Ok(serde_json::json!({"resultStatus": "SUCCEEDED", "manifestFile": manifest_at}))
        }
        "DEPLOY" => {
            // Render's output; load_dir checks the key ring again, since this is
            // the identity that decrypts.
            let archive = download(storage, &format!("{input}/source.tgz")).await?;
            let dir = Unpacked::new(&archive)?;
            let sealed = seed::load_dir(dir.path(), &env.key_ring)?;
            let seeded = seed::seed(&sealed, &env).await?;
            Ok(serde_json::json!({
                "resultStatus": "SUCCEEDED",
                "metadata": {"seeded": seeded.join(",")},
            }))
        }
        other => Err(format!("unsupported request type {other}").into()),
    }
}

fn var(name: &str) -> Result<String, Error> {
    std::env::var(name).map_err(|_| format!("{name} is not set").into())
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

async fn download(storage: &Storage, url: &str) -> Result<Vec<u8>, Error> {
    let at: seed::GcsObject = url.parse()?;
    let mut request = storage.read_object(at.bucket_resource(), &at.object);
    if let Some(generation) = at.generation {
        request = request.set_generation(generation);
    }
    let mut response = request
        .send()
        .await
        .map_err(|e| format!("reading {at}: {e}"))?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.next().await {
        bytes.extend_from_slice(&chunk.map_err(|e| format!("reading {at}: {e}"))?);
    }
    Ok(bytes)
}

async fn upload(storage: &Storage, url: &str, bytes: Vec<u8>) -> Result<(), Error> {
    let at: seed::GcsObject = url.parse()?;
    storage
        .write_object(at.bucket_resource(), &at.object, bytes::Bytes::from(bytes))
        .send_buffered()
        .await
        .map_err(|e| format!("writing {at}: {e}"))?;
    Ok(())
}

/// A gzipped tar archive unpacked into a fresh directory, removed on drop.
/// Entries that would land outside the directory are not written.
struct Unpacked(PathBuf);

impl Unpacked {
    fn new(archive: &[u8]) -> Result<Self, Error> {
        let dir = std::env::temp_dir().join(format!("kseal-{:016x}", rand::random::<u64>()));
        std::fs::create_dir(&dir)?;
        let unpacked = Unpacked(dir);
        tar::Archive::new(flate2::read::GzDecoder::new(archive)).unpack(&unpacked.0)?;
        Ok(unpacked)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Unpacked {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}
