use std::fs;
use std::path::{Path, PathBuf};

use kseal_google_cloud::CryptoKeyVersionName;

/// Per-directory seal defaults, discovered as the nearest `.kseal.kdl` walking up
/// from the working directory (like `.editorconfig`). Environments map to KMS
/// projects, so each environment keeps its own file, pinning that environment's
/// key and the committed public key next to it.
///
/// Tagged by provider like the sealed file's [`kseal::KmsRef`]: config exists
/// only for backends whose sealing needs pinned material (a key reference and a
/// committed public key). Local sealing needs none of that, so there is no local
/// variant; a new backend is a new variant with its own fields.
pub enum Config {
    /// Google Cloud KMS: a fully-qualified crypto key version (parsed, so every
    /// consumer receives a valid one), and the committed public-key PEM resolved
    /// next to the config file.
    GoogleCloud {
        key: CryptoKeyVersionName,
        public_key: PathBuf,
    },
}

/// The on-disk shape of `.kseal.kdl`, before `public-key` is resolved against the
/// config's own directory. Its variant is selected by the `provider` node.
#[derive(serde::Deserialize)]
#[serde(tag = "provider", deny_unknown_fields)]
enum ConfigFile {
    #[serde(rename = "google-cloud")]
    GoogleCloud {
        key: String,
        #[serde(rename = "public-key")]
        public_key: String,
    },
}

const FILE_NAME: &str = ".kseal.kdl";

impl Config {
    /// Find and load the nearest config walking up from `start`.
    pub fn find(start: &Path) -> Result<Config, Box<dyn std::error::Error>> {
        let path = nearest(start)
            .ok_or_else(|| format!("no {FILE_NAME} found from {}", start.display()))?;
        Config::load(&path)
    }

    pub fn load(path: &Path) -> Result<Config, Box<dyn std::error::Error>> {
        let file: ConfigFile = kdl::de::from_str(&fs::read_to_string(path)?)?;
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        Ok(match file {
            ConfigFile::GoogleCloud { key, public_key } => Config::GoogleCloud {
                // Parse here so a hand-edited or truncated key is caught at load,
                // and seal/rewrap/verify all receive a valid resource name.
                key: key.parse()?,
                public_key: dir.join(public_key),
            },
        })
    }
}

fn nearest(start: &Path) -> Option<PathBuf> {
    let mut dir = Some(start);
    while let Some(d) = dir {
        let candidate = d.join(FILE_NAME);
        if candidate.is_file() {
            return Some(candidate);
        }
        dir = d.parent();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{Config, FILE_NAME, nearest};

    #[test]
    fn nearest_finds_the_containing_ancestor() {
        let base = std::env::temp_dir().join(format!("kseal-cfg-{}", std::process::id()));
        let deep = base.join("a/y/z");
        std::fs::create_dir_all(&deep).unwrap();
        let cfg = base.join("a").join(FILE_NAME);
        std::fs::write(&cfg, "provider \"google-cloud\"\n").unwrap();
        assert_eq!(nearest(&deep), Some(cfg));
        std::fs::remove_dir_all(&base).ok();
    }

    fn write_config(body: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("kseal-cfg-load-{}-{:p}", std::process::id(), body));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(FILE_NAME), body).unwrap();
        dir
    }

    #[test]
    fn load_parses_google_cloud_and_resolves_public_key() {
        let dir = write_config(
            "provider \"google-cloud\"\nkey \"projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1\"\npublic-key \"key.pem\"\n",
        );
        let Config::GoogleCloud { key, public_key } = Config::load(&dir.join(FILE_NAME)).unwrap();
        assert_eq!(
            key.to_string(),
            "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
        );
        // public-key is resolved next to the config file, not left relative.
        assert_eq!(public_key, dir.join("key.pem"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_rejects_a_non_fully_qualified_key() {
        // A hand-edited key that is not fully qualified fails at load, so seal
        // never records it.
        let dir = write_config("provider \"google-cloud\"\nkey \"foo\"\npublic-key \"key.pem\"\n");
        assert!(Config::load(&dir.join(FILE_NAME)).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
