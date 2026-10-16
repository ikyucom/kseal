//! Seeding Google Secret Manager from one environment's directory of sealed
//! files.
//!
//! A directory holds an environment's `.kseal.kdl`, its committed public key,
//! and one `*.enc` per secret. Seeding opens each value that changed since the
//! last successful seed and adds it as a new version of the secret named in the
//! file. What changed is decided by a state object in Cloud Storage that records
//! the (secret, body digest) pairs the last successful seed left in Secret
//! Manager: the digest covers only the encrypted body, so a rewrap or a rename
//! changes nothing, and the state holds what the directory had rather than an
//! accumulation, so reverting a value to an earlier one seeds it again.
//!
//! The state is written back with a generation precondition, so two seeds of one
//! environment cannot overwrite each other. A seed that fails part-way writes no
//! state, and the next seed repeats the whole difference; Secret Manager does
//! not deduplicate versions, so a value already added by the failed seed gets a
//! second version with the same payload.
//!
//! Seeding never creates secrets: each secret must already exist, created by
//! whatever manages them.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use google_cloud_secretmanager_v1::{client::SecretManagerService, model::SecretPayload};
use google_cloud_storage::client::Storage;
use kseal::{KmsRef, SealedFile};

use crate::{CryptoKeyVersionName, KeyRingName, Unwrapper};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{path}: {source}")]
    Sealed { path: PathBuf, source: kseal::Error },
    #[error("{path}: {reason}")]
    NotSeedable { path: PathBuf, reason: String },
    #[error("{secret} is sealed with more than one value")]
    Ambiguous { secret: String },
    #[error("secret {secret} does not exist in {project}")]
    MissingSecret { secret: String, project: String },
    #[error("not a Cloud Storage object: {0} (expected gs://BUCKET/OBJECT)")]
    GcsObject(String),
    #[error("malformed state at line {line}")]
    MalformedState { line: usize },
    #[error("{context}: {message}")]
    Service { context: String, message: String },
}

pub type Result<T> = std::result::Result<T, Error>;

fn service(context: impl Into<String>) -> impl FnOnce(google_cloud_storage::Error) -> Error {
    let context = context.into();
    move |e| Error::Service {
        context,
        message: e.to_string(),
    }
}

/// A sealed file in an environment's directory, checked to be sealed with a key
/// in the environment's key ring.
pub struct Sealed {
    pub path: PathBuf,
    pub file: SealedFile,
    /// The key version that opens it, inside the environment's key ring.
    pub key: CryptoKeyVersionName,
    pub body_sha256: String,
}

impl Sealed {
    pub fn secret(&self) -> &str {
        self.file.secret()
    }
}

/// Every `*.enc` directly in `dir`, sorted by secret name. Each must be sealed
/// with a Google Cloud key in `key_ring`: seeding decrypts through KMS, so a
/// locally sealed file can never be seeded, and a key outside the ring could
/// not be opened by the environment's seed identity. Two files sealing
/// different values under one name leave "the" value ambiguous, so that is an
/// error too; the same value under one name in two files is not.
pub fn load_dir(dir: &Path, key_ring: &KeyRingName) -> Result<Vec<Sealed>> {
    let entries = std::fs::read_dir(dir).map_err(|source| Error::Io {
        path: dir.to_owned(),
        source,
    })?;
    let mut sealed = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|source| Error::Io {
                path: dir.to_owned(),
                source,
            })?
            .path();
        if path.extension() != Some("enc".as_ref()) {
            continue;
        }
        let text = std::fs::read_to_string(&path).map_err(|source| Error::Io {
            path: path.clone(),
            source,
        })?;
        let file = SealedFile::from_json(&text).map_err(|source| Error::Sealed {
            path: path.clone(),
            source,
        })?;
        let key = check_key(&path, file.kms(), key_ring)?;
        sealed.push(Sealed {
            body_sha256: file.body_sha256(),
            key,
            path,
            file,
        });
    }
    sealed.sort_by(|a, b| (a.secret(), &a.path).cmp(&(b.secret(), &b.path)));
    for pair in sealed.windows(2) {
        if pair[0].secret() == pair[1].secret() && pair[0].body_sha256 != pair[1].body_sha256 {
            return Err(Error::Ambiguous {
                secret: pair[0].secret().to_owned(),
            });
        }
    }
    Ok(sealed)
}

fn check_key(path: &Path, kms: &KmsRef, key_ring: &KeyRingName) -> Result<CryptoKeyVersionName> {
    let not_seedable = |reason: String| Error::NotSeedable {
        path: path.to_owned(),
        reason,
    };
    match kms {
        KmsRef::GoogleCloud { key } => {
            let version = key
                .parse::<CryptoKeyVersionName>()
                .map_err(|e| not_seedable(e.to_string()))?;
            if &version.key_ring() == key_ring {
                Ok(version)
            } else {
                Err(not_seedable(format!("key {key} is not in {key_ring}")))
            }
        }
        KmsRef::Local {} => Err(not_seedable(
            "sealed with a local key; seeding needs a Google Cloud key".to_owned(),
        )),
    }
}

/// What a successful seed left in Secret Manager: the (secret, body digest)
/// pairs of the directory it seeded.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct State(BTreeSet<(String, String)>);

impl State {
    /// The state a successful seed of `sealed` leaves.
    pub fn of(sealed: &[Sealed]) -> Self {
        State(
            sealed
                .iter()
                .map(|s| (s.secret().to_owned(), s.body_sha256.clone()))
                .collect(),
        )
    }

    /// Read the stored form: one `secret<TAB>body_sha256` line per pair.
    pub fn from_tsv(text: &str) -> Result<Self> {
        let mut pairs = BTreeSet::new();
        for (i, line) in text.lines().enumerate() {
            let Some((secret, digest)) = line.split_once('\t') else {
                return Err(Error::MalformedState { line: i + 1 });
            };
            if secret.is_empty() || digest.is_empty() || digest.contains('\t') {
                return Err(Error::MalformedState { line: i + 1 });
            }
            pairs.insert((secret.to_owned(), digest.to_owned()));
        }
        Ok(State(pairs))
    }

    /// The stored form, sorted, so equal states store identically.
    pub fn to_tsv(&self) -> String {
        self.0
            .iter()
            .map(|(secret, digest)| format!("{secret}\t{digest}\n"))
            .collect()
    }
}

/// The sealed files whose value the state does not have, one per secret.
pub fn changed<'a>(sealed: &'a [Sealed], state: &State) -> Vec<&'a Sealed> {
    let mut seen = BTreeSet::new();
    sealed
        .iter()
        .filter(|s| {
            let pair = (s.secret().to_owned(), s.body_sha256.clone());
            !state.0.contains(&pair) && seen.insert(pair)
        })
        .collect()
}

/// A Cloud Storage object, such as where an environment's state is kept,
/// optionally pinned to one generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcsObject {
    pub bucket: String,
    pub object: String,
    pub generation: Option<i64>,
}

impl std::str::FromStr for GcsObject {
    type Err = Error;

    /// Parse a gcloud storage URL, `gs://BUCKET/OBJECT`, or
    /// `gs://BUCKET/OBJECT#GENERATION` for one generation of it. The object name
    /// is taken verbatim, with no percent-decoding.
    fn from_str(url: &str) -> Result<Self> {
        // Like gcloud, only a trailing '#' and digits is a generation; anything
        // else after '#' is part of the object name.
        let (rest, generation) = match url.rsplit_once('#') {
            Some((rest, digits))
                if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) =>
            {
                let generation = digits
                    .parse()
                    .map_err(|_| Error::GcsObject(url.to_owned()))?;
                (rest, Some(generation))
            }
            _ => (url, None),
        };
        rest.strip_prefix("gs://")
            .and_then(|rest| rest.split_once('/'))
            .filter(|(bucket, object)| !bucket.is_empty() && !object.is_empty())
            .map(|(bucket, object)| GcsObject {
                bucket: bucket.to_owned(),
                object: object.to_owned(),
                generation,
            })
            .ok_or_else(|| Error::GcsObject(url.to_owned()))
    }
}

impl GcsObject {
    /// The bucket as the storage API names it.
    pub fn bucket_resource(&self) -> String {
        format!("projects/_/buckets/{}", self.bucket)
    }
}

impl std::fmt::Display for GcsObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "gs://{}/{}", self.bucket, self.object)?;
        if let Some(generation) = self.generation {
            write!(f, "#{generation}")?;
        }
        Ok(())
    }
}

/// The stored state and its object generation, which the write-back must match.
/// An absent object means nothing has been seeded yet: an empty state at
/// generation 0, which a write-back requires to still be absent. The state is
/// always its latest generation, so `at` must not name one.
pub async fn read_state(storage: &Storage, at: &GcsObject) -> Result<(State, i64)> {
    if at.generation.is_some() {
        return Err(Error::GcsObject(format!(
            "{at}: the state is always the latest generation; drop the #GENERATION"
        )));
    }
    let mut response = match storage
        .read_object(at.bucket_resource(), &at.object)
        .send()
        .await
    {
        Ok(response) => response,
        Err(e) if e.http_status_code() == Some(404) => return Ok((State::default(), 0)),
        Err(e) => return Err(service(format!("reading {at}"))(e)),
    };
    let generation = response.object().generation;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.next().await {
        bytes.extend_from_slice(&chunk.map_err(service(format!("reading {at}")))?);
    }
    let text = String::from_utf8(bytes).map_err(|_| Error::MalformedState { line: 0 })?;
    Ok((State::from_tsv(&text)?, generation))
}

/// Store `state`, failing if the object changed since it was read at
/// `generation`.
pub async fn write_state(
    storage: &Storage,
    at: &GcsObject,
    state: &State,
    generation: i64,
) -> Result<()> {
    storage
        .write_object(at.bucket_resource(), &at.object, state.to_tsv())
        .set_if_generation_match(generation)
        .send_buffered()
        .await
        .map_err(service(format!(
            "writing {at} (changed since it was read?)"
        )))?;
    Ok(())
}

/// An environment's secrets in Secret Manager.
pub struct Secrets {
    client: SecretManagerService,
    project: String,
}

impl Secrets {
    pub async fn new(project: impl Into<String>) -> Result<Self> {
        let client = SecretManagerService::builder()
            .build()
            .await
            .map_err(|e| Error::Service {
                context: "creating the Secret Manager client".to_owned(),
                message: e.to_string(),
            })?;
        Ok(Secrets {
            client,
            project: project.into(),
        })
    }

    fn secret_resource(&self, secret: &str) -> String {
        format!("projects/{}/secrets/{secret}", self.project)
    }

    /// Fail unless every sealed file's secret exists. Reads metadata only.
    pub async fn check_exist(&self, sealed: &[Sealed]) -> Result<()> {
        let names: BTreeSet<&str> = sealed.iter().map(Sealed::secret).collect();
        for secret in names {
            match self
                .client
                .get_secret()
                .set_name(self.secret_resource(secret))
                .send()
                .await
            {
                Ok(_) => {}
                Err(e) if e.http_status_code() == Some(404) => {
                    return Err(Error::MissingSecret {
                        secret: secret.to_owned(),
                        project: self.project.clone(),
                    });
                }
                Err(e) => {
                    return Err(Error::Service {
                        context: format!("describing {secret}"),
                        message: e.to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Add `value` as a new version of `secret`, with its CRC32C so Secret
    /// Manager rejects a payload damaged on the way.
    async fn add_version(&self, secret: &str, value: &[u8]) -> Result<()> {
        let payload = SecretPayload::new()
            .set_data(value.to_vec())
            .set_data_crc32c(i64::from(crc32c::crc32c(value)));
        self.client
            .add_secret_version()
            .set_parent(self.secret_resource(secret))
            .set_payload(payload)
            .send()
            .await
            .map_err(|e| Error::Service {
                context: format!("adding a version to {secret}"),
                message: e.to_string(),
            })?;
        Ok(())
    }
}

/// Where an environment's values come from and go: the key ring its sealed
/// files must use, the project holding its secrets, and its state object.
pub struct Environment {
    pub key_ring: KeyRingName,
    pub project: String,
    pub state: GcsObject,
}

/// Seed the sealed files that changed since the environment's state was
/// written, then record the new state. Returns the secrets that got a new
/// version.
pub async fn seed(sealed: &[Sealed], env: &Environment) -> Result<Vec<String>> {
    let secrets = Secrets::new(&env.project).await?;
    let storage = Storage::builder()
        .build()
        .await
        .map_err(|e| Error::Service {
            context: "creating the Cloud Storage client".to_owned(),
            message: e.to_string(),
        })?;
    let state_at = &env.state;
    let (state, generation) = read_state(&storage, state_at).await?;
    let mut unwrappers: HashMap<String, Unwrapper> = HashMap::new();
    let mut seeded = Vec::new();
    for s in changed(sealed, &state) {
        let key = s.key.to_string();
        if !unwrappers.contains_key(&key) {
            let unwrapper = Unwrapper::new(key.clone())
                .await
                .map_err(|source| Error::Sealed {
                    path: s.path.clone(),
                    source,
                })?;
            unwrappers.insert(key.clone(), unwrapper);
        }
        let value = kseal::open(&s.file, &unwrappers[&key])
            .await
            .map_err(|source| Error::Sealed {
                path: s.path.clone(),
                source,
            })?;
        secrets.add_version(s.secret(), &value).await?;
        seeded.push(s.secret().to_owned());
    }
    write_state(&storage, state_at, &State::of(sealed), generation).await?;
    Ok(seeded)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use kseal::{KmsRef, PublicKey};
    use rsa::{
        RsaPrivateKey, RsaPublicKey,
        pkcs8::{EncodePublicKey as _, LineEnding},
    };

    use super::{Error, GcsObject, State, changed, load_dir};
    use crate::KeyRingName;

    const RING: &str = "projects/p/locations/l/keyRings/r";

    fn public_key(kms: KmsRef) -> PublicKey {
        let key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let pem = RsaPublicKey::from(&key)
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        PublicKey::from_pem(&pem, kms).unwrap()
    }

    fn in_ring(ring: &str) -> PublicKey {
        public_key(KmsRef::GoogleCloud {
            key: format!("{ring}/cryptoKeys/k/cryptoKeyVersions/1"),
        })
    }

    fn write(dir: &Path, file: &str, value: &[u8], name: &str, key: &PublicKey) {
        let sealed = kseal::seal(value, name, key).unwrap();
        std::fs::write(dir.join(file), sealed.to_json().unwrap()).unwrap();
    }

    fn scratch(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("kseal-seed-{label}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn ring() -> KeyRingName {
        RING.parse().unwrap()
    }

    #[test]
    fn loads_only_sealed_files_sorted_by_secret() {
        let dir = scratch("load");
        let key = in_ring(RING);
        write(&dir, "b.enc", b"2", "B", &key);
        write(&dir, "a.enc", b"1", "A", &key);
        std::fs::write(dir.join(".kseal.kdl"), "ignored").unwrap();
        std::fs::write(dir.join("key.pem"), "ignored").unwrap();
        let sealed = load_dir(&dir, &ring()).unwrap();
        let names: Vec<&str> = sealed.iter().map(|s| s.secret()).collect();
        assert_eq!(names, ["A", "B"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_a_key_outside_the_ring() {
        let dir = scratch("ring");
        // A look-alike project: a prefix check would let it through.
        write(
            &dir,
            "a.enc",
            b"1",
            "A",
            &in_ring("projects/p-evil/locations/l/keyRings/r"),
        );
        assert!(matches!(
            load_dir(&dir, &ring()),
            Err(Error::NotSeedable { .. })
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_a_locally_sealed_file() {
        let dir = scratch("local");
        write(&dir, "a.enc", b"1", "A", &public_key(KmsRef::Local {}));
        assert!(matches!(
            load_dir(&dir, &ring()),
            Err(Error::NotSeedable { .. })
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn two_values_for_one_name_are_ambiguous() {
        let dir = scratch("ambiguous");
        let key = in_ring(RING);
        write(&dir, "a.enc", b"1", "A", &key);
        write(&dir, "a-again.enc", b"2", "A", &key);
        assert!(matches!(
            load_dir(&dir, &ring()),
            Err(Error::Ambiguous { .. })
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_same_value_twice_is_seeded_once() {
        let dir = scratch("copy");
        write(&dir, "a.enc", b"1", "A", &in_ring(RING));
        std::fs::copy(dir.join("a.enc"), dir.join("a-copy.enc")).unwrap();
        let sealed = load_dir(&dir, &ring()).unwrap();
        assert_eq!(sealed.len(), 2);
        assert_eq!(changed(&sealed, &State::default()).len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn only_values_missing_from_the_state_change() {
        let dir = scratch("changed");
        let key = in_ring(RING);
        write(&dir, "a.enc", b"1", "A", &key);
        write(&dir, "b.enc", b"2", "B", &key);
        let sealed = load_dir(&dir, &ring()).unwrap();
        // Everything is new on the first seed, nothing right after it.
        assert_eq!(changed(&sealed, &State::default()).len(), 2);
        let state = State::of(&sealed);
        assert!(changed(&sealed, &state).is_empty());
        // Resealing B (a new value, or the same one again) changes only B.
        write(&dir, "b.enc", b"3", "B", &key);
        let resealed = load_dir(&dir, &ring()).unwrap();
        let names: Vec<&str> = changed(&resealed, &state)
            .iter()
            .map(|s| s.secret())
            .collect();
        assert_eq!(names, ["B"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn state_round_trips_through_its_stored_form() {
        let dir = scratch("state");
        let key = in_ring(RING);
        write(&dir, "a.enc", b"1", "A", &key);
        write(&dir, "b.enc", b"2", "B", &key);
        let state = State::of(&load_dir(&dir, &ring()).unwrap());
        assert_eq!(State::from_tsv(&state.to_tsv()).unwrap(), state);
        assert_eq!(State::from_tsv("").unwrap(), State::default());
        for bad in ["A", "A\t", "\tdigest", "A\td\textra"] {
            assert!(State::from_tsv(bad).is_err(), "{bad:?}");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn gcs_object_needs_a_bucket_and_an_object() {
        let at: GcsObject = "gs://bucket/path/to/state.tsv".parse().unwrap();
        assert_eq!(at.bucket, "bucket");
        assert_eq!(at.object, "path/to/state.tsv");
        assert_eq!(at.to_string(), "gs://bucket/path/to/state.tsv");
        assert_eq!(at.generation, None);
        // gcloud's form for one generation, as Cloud Deploy passes its inputs.
        let pinned: GcsObject = "gs://bucket/source.tgz#1791887613363191".parse().unwrap();
        assert_eq!(pinned.object, "source.tgz");
        assert_eq!(pinned.generation, Some(1791887613363191));
        assert_eq!(
            pinned.to_string(),
            "gs://bucket/source.tgz#1791887613363191"
        );
        // A '#' not followed by digits alone is part of the object name; a
        // signed number is not a generation either.
        for name in ["a#b", "a#-1", "a#+1", "a#"] {
            let at: GcsObject = format!("gs://bucket/{name}").parse().unwrap();
            assert_eq!((at.object.as_str(), at.generation), (name, None));
        }
        // Percent escapes are part of the name, as gcloud reads them.
        let escaped: GcsObject = "gs://bucket/a%20b".parse().unwrap();
        assert_eq!(escaped.object, "a%20b");
        for bad in [
            "bucket/object",
            "gs://bucket",
            "gs://bucket/",
            "gs:///object",
        ] {
            assert!(bad.parse::<GcsObject>().is_err(), "{bad}");
        }
    }
}
