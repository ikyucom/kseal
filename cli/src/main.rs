//! kseal command-line interface.
//!
//! The offline paths (seal with a public-key PEM, open with a private-key PEM)
//! use only the core crate. The Google Cloud paths (fetch the public key, or
//! decrypt via Cloud KMS) go through kseal-google-cloud and run on this binary's
//! tokio runtime. `keygen` is a test helper: a real deployment's private key
//! lives in KMS, never on disk.

mod config;

use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kseal::{KmsRef, PublicKey, SealedFile, local::LocalPrivateKey};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePublicKey as _, EncodePrivateKey as _, EncodePublicKey as _, LineEnding},
};
use zeroize::Zeroizing;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kseal: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> CliResult {
    let cli: Cli = argh::from_env();
    if cli.version {
        println!("{VERSION}");
        return Ok(());
    }
    match cli.command {
        Some(Command::Init(cmd)) => cmd.run().await,
        Some(Command::Seal(cmd)) => cmd.run().await,
        Some(Command::Open(cmd)) => cmd.run().await,
        Some(Command::Rewrap(cmd)) => cmd.run().await,
        Some(Command::Verify(cmd)) => cmd.run().await,
        Some(Command::Inspect(cmd)) => cmd.run(),
        Some(Command::Keygen(cmd)) => cmd.run(),
        None => Err("no subcommand given; run `kseal --help`".into()),
    }
}

type CliResult = Result<(), Box<dyn std::error::Error>>;

/// The build's version line, composed at build time (see build.rs): the crate
/// version, plus the commit the release was built from when it records
/// KSEAL_GIT_SHA.
const VERSION: &str = env!("KSEAL_VERSION");

/// Asymmetric-KMS envelope encryption for secrets in git.
#[derive(argh::FromArgs)]
struct Cli {
    /// print version information and exit
    #[argh(switch)]
    version: bool,
    #[argh(subcommand)]
    command: Option<Command>,
}

#[derive(argh::FromArgs)]
#[argh(subcommand)]
enum Command {
    Init(Init),
    Seal(Seal),
    Open(Open),
    Rewrap(Rewrap),
    Verify(Verify),
    Inspect(Inspect),
    Keygen(Keygen),
}

/// Write a `.kseal.kdl` and the committed public-key PEM for a Google Cloud KMS
/// key version, so later seals run offline. Fetches the key version's public key
/// once; both files are then committed together.
#[derive(argh::FromArgs)]
#[argh(subcommand, name = "init")]
struct Init {
    /// the fully-qualified Google Cloud KMS crypto key version to pin
    /// (projects/.../cryptoKeyVersions/N)
    #[argh(option)]
    gcp_key_version: String,
    /// directory to write .kseal.kdl and the PEM into (default: current)
    #[argh(option)]
    out_dir: Option<PathBuf>,
    /// public-key PEM filename to write and record (default: key.pem)
    #[argh(option)]
    pem: Option<String>,
    /// overwrite an existing .kseal.kdl / PEM
    #[argh(switch)]
    force: bool,
}

impl Init {
    async fn run(self) -> CliResult {
        let dir = self.out_dir.unwrap_or_else(|| PathBuf::from("."));
        let pem_name = self.pem.as_deref().unwrap_or("key.pem");
        let pem_path = dir.join(pem_name);
        let config_path = dir.join(".kseal.kdl");
        if !self.force && (config_path.exists() || pem_path.exists()) {
            return Err(format!(
                "{} or {} already exists; pass --force to overwrite",
                config_path.display(),
                pem_path.display()
            )
            .into());
        }
        let (pem, kms_ref) = kseal_google_cloud::fetch_public_key(self.gcp_key_version).await?;
        let KmsRef::GoogleCloud { key } = kms_ref else {
            return Err("fetch_public_key returned a non-google-cloud key".into());
        };
        fs::write(&pem_path, pem.as_bytes())?;
        let kdl = format!("provider \"google-cloud\"\nkey {key:?}\npublic-key {pem_name:?}\n");
        fs::write(&config_path, kdl)?;
        eprintln!("wrote {} and {}", config_path.display(), pem_path.display());
        Ok(())
    }
}

/// Seal a value. Offline with a public-key PEM or the nearest .kseal.kdl;
/// --gcp-key-version instead fetches the public key from Cloud KMS.
#[derive(argh::FromArgs)]
#[argh(subcommand, name = "seal")]
struct Seal {
    /// secret name to seal for; bound as AEAD associated data
    #[argh(option)]
    name: String,
    /// public key PEM file (offline path)
    #[argh(option)]
    public_key: Option<PathBuf>,
    /// fetch the public key from this fully-qualified Google Cloud KMS crypto key
    /// version (projects/.../cryptoKeyVersions/N)
    #[argh(option)]
    gcp_key_version: Option<String>,
    /// plaintext input file; stdin if omitted
    #[argh(option)]
    input: Option<PathBuf>,
    /// where to write the sealed JSON. The nearest .kseal.kdl is searched from
    /// this path's directory, so the value is sealed for the environment it is
    /// stored in
    #[argh(option)]
    output: PathBuf,
}

impl Seal {
    async fn run(self) -> CliResult {
        let plaintext = Zeroizing::new(read_bytes(&self.input)?);
        let public_key =
            public_key_for_output(&self.public_key, &self.gcp_key_version, &self.output).await?;
        let sealed = kseal::seal(&plaintext, &self.name, &public_key)?;
        write_sealed(&self.output, &sealed)?;
        Ok(())
    }
}

/// Open a sealed value: unwrap the data key and decrypt.
#[derive(argh::FromArgs)]
#[argh(subcommand, name = "open")]
struct Open {
    /// private key PEM file (offline path)
    #[argh(option)]
    private_key: Option<PathBuf>,
    /// override the fully-qualified KMS key version to decrypt with
    /// (projects/.../cryptoKeyVersions/N; default: the file's own)
    #[argh(option)]
    gcp_key_version: Option<String>,
    /// sealed JSON input file; stdin if omitted
    #[argh(option)]
    input: Option<PathBuf>,
}

impl Open {
    async fn run(self) -> CliResult {
        if self.private_key.is_some() && self.gcp_key_version.is_some() {
            return Err("pass only one of --private-key or --gcp-key-version, not both".into());
        }
        let sealed = SealedFile::from_json(&read_text(&self.input)?)?;
        if let Some(path) = &self.private_key {
            let unwrapper = LocalPrivateKey::from_pem(&fs::read_to_string(path)?)?;
            write_bytes(&kseal::open(&sealed, &unwrapper).await?)?;
            return Ok(());
        }
        let version = unwrap_version(&sealed, &self.gcp_key_version)?;
        let unwrapper = kseal_google_cloud::Unwrapper::new(version).await?;
        write_bytes(&kseal::open(&sealed, &unwrapper).await?)?;
        Ok(())
    }
}

/// Re-wrap a sealed value under a new key version, without changing the value.
/// The unwrap side defaults to the file's own key version; the destination is
/// given like `seal` — an explicit --to-public-key / --to-gcp-key-version, or
/// the nearest .kseal.kdl to the output when neither is given.
#[derive(argh::FromArgs)]
#[argh(subcommand, name = "rewrap")]
struct Rewrap {
    /// sealed JSON input file; stdin if omitted
    #[argh(option)]
    input: Option<PathBuf>,
    /// private key PEM to unwrap the current data key (offline path)
    #[argh(option)]
    private_key: Option<PathBuf>,
    /// override the fully-qualified KMS key version to unwrap with
    /// (projects/.../cryptoKeyVersions/N; default: the file's own)
    #[argh(option)]
    gcp_key_version: Option<String>,
    /// destination public key PEM (offline path)
    #[argh(option)]
    to_public_key: Option<PathBuf>,
    /// fetch the destination public key from this fully-qualified Google Cloud KMS
    /// crypto key version (projects/.../cryptoKeyVersions/N)
    #[argh(option)]
    to_gcp_key_version: Option<String>,
    /// where to write the rewrapped JSON
    #[argh(option)]
    output: PathBuf,
}

impl Rewrap {
    async fn run(self) -> CliResult {
        if self.private_key.is_some() && self.gcp_key_version.is_some() {
            return Err("pass only one of --private-key or --gcp-key-version, not both".into());
        }
        let sealed = SealedFile::from_json(&read_text(&self.input)?)?;
        // Like `seal`, fall back to the destination's .kseal.kdl when no key is
        // given, so the key-rotation path runs with only repo access and records
        // the environment's real provider and key version.
        let new_key =
            public_key_for_output(&self.to_public_key, &self.to_gcp_key_version, &self.output)
                .await?;
        let rewrapped = if let Some(path) = &self.private_key {
            let unwrapper = LocalPrivateKey::from_pem(&fs::read_to_string(path)?)?;
            kseal::rewrap(&sealed, &unwrapper, &new_key).await?
        } else {
            let version = unwrap_version(&sealed, &self.gcp_key_version)?;
            let unwrapper = kseal_google_cloud::Unwrapper::new(version).await?;
            kseal::rewrap(&sealed, &unwrapper, &new_key).await?
        };
        write_sealed(&self.output, &rewrapped)?;
        Ok(())
    }
}

/// Check that the committed public-key PEM matches the pinned key version's
/// public key, by fetching it from Google Cloud KMS. Reads the nearest
/// `.kseal.kdl`.
#[derive(argh::FromArgs)]
#[argh(subcommand, name = "verify")]
struct Verify {
    /// config file to check (default: nearest .kseal.kdl)
    #[argh(option)]
    config: Option<PathBuf>,
    /// require the pinned key to belong to this key ring, compared as an exact
    /// resource, so a .kseal.kdl swapped to another project or key ring is
    /// rejected before any KMS call
    /// (projects/P/locations/L/keyRings/R)
    #[argh(option)]
    expect_key_ring: Option<kseal_google_cloud::KeyRingName>,
}

impl Verify {
    async fn run(self) -> CliResult {
        let cfg = match &self.config {
            Some(path) => config::Config::load(path)?,
            None => config::Config::find(&std::env::current_dir()?)?,
        };
        let config::Config::GoogleCloud { key, public_key } = cfg;
        // Config::load already parsed the key, so it is a valid resource here.
        // Confirm the pin points where the caller expects before trusting or
        // fetching it: matching the committed PEM proves the key is genuine, not
        // that it is the right key for this environment. Compare the key ring by
        // value; a substring prefix would accept a look-alike project.
        // The expected ring was parsed with the arguments, so a mistyped resource
        // is its own error rather than a false "wrong key ring".
        if let Some(expected) = &self.expect_key_ring {
            let ring = key.key_ring();
            if &ring != expected {
                return Err(format!(
                    "pinned key is not in the expected key ring:\n  key ring: {ring}\n  expected: {expected}"
                )
                .into());
            }
        }
        // Parse both sides into keys and compare, so a corrupt or hand-edited PEM
        // fails here rather than silently sealing under a key that cannot decrypt,
        // and PEM whitespace differences do not matter.
        let committed = RsaPublicKey::from_public_key_pem(&fs::read_to_string(&public_key)?)?;
        let (fetched_pem, _) = kseal_google_cloud::fetch_public_key(key.to_string()).await?;
        let fetched = RsaPublicKey::from_public_key_pem(&fetched_pem)?;
        if committed == fetched {
            eprintln!("ok: {} matches {}", public_key.display(), key);
            Ok(())
        } else {
            Err(format!(
                "public key mismatch: {} does not match GetPublicKey({})",
                public_key.display(),
                key
            )
            .into())
        }
    }
}

/// Print a sealed file's metadata. No plaintext is shown.
#[derive(argh::FromArgs)]
#[argh(subcommand, name = "inspect")]
struct Inspect {
    /// sealed JSON input file; stdin if omitted
    #[argh(option)]
    input: Option<PathBuf>,
    /// emit machine-readable metadata for tooling: a stable JSON object
    /// {schema, secret, kms, body_sha256}, no plaintext. kms is tagged by
    /// provider and carries that provider's own addressing (google-cloud: key;
    /// local: none). body_sha256 is SHA-256 of the nonce then ciphertext, so
    /// seeding can tell an unchanged secret from a rewrapped one
    #[argh(switch)]
    json: bool,
}

impl Inspect {
    fn run(self) -> CliResult {
        let sealed = SealedFile::from_json(&read_text(&self.input)?)?;
        if self.json {
            println!("{}", inspect_metadata(&sealed));
        } else {
            let kms = sealed.kms();
            println!("secret:   {}", sealed.secret());
            println!("provider: {}", kms.provider());
            if let KmsRef::GoogleCloud { key } = kms {
                println!("key:      {key}");
            }
        }
        Ok(())
    }
}

/// The stable `inspect --json` object: the sealed file's metadata for tooling,
/// carrying no plaintext. Callers (the seed/gate CI) depend on this shape, so
/// its keys are a contract — see the test that pins them.
fn inspect_metadata(sealed: &SealedFile) -> serde_json::Value {
    serde_json::json!({
        "schema": sealed.schema(),
        "secret": sealed.secret(),
        "kms": sealed.kms(),
        "body_sha256": sealed.body_sha256(),
    })
}

/// Generate a local RSA keypair. TEST HELPER: a real private key lives in KMS
/// and never touches disk.
#[derive(argh::FromArgs)]
#[argh(subcommand, name = "keygen")]
struct Keygen {
    /// output path prefix; writes PREFIX.key.pem (PKCS#8 private) and
    /// PREFIX.pub.pem (SPKI public)
    #[argh(option)]
    out: PathBuf,
    /// key size in bits (default 2048)
    #[argh(option, default = "2048")]
    bits: usize,
}

impl Keygen {
    fn run(self) -> CliResult {
        let mut rng = rand::thread_rng();
        let key = RsaPrivateKey::new(&mut rng, self.bits)?;
        let public = RsaPublicKey::from(&key);
        let private_pem = key.to_pkcs8_pem(LineEnding::LF)?;
        let public_pem = public.to_public_key_pem(LineEnding::LF)?;
        let private_path = PathBuf::from(format!("{}.key.pem", self.out.display()));
        let public_path = PathBuf::from(format!("{}.pub.pem", self.out.display()));
        write_private_key(&private_path, private_pem.as_bytes())?;
        fs::write(&public_path, public_pem.as_bytes())?;
        eprintln!(
            "wrote {} and {}",
            private_path.display(),
            public_path.display()
        );
        Ok(())
    }
}

/// The public key to seal (or rewrap) a value under, for a value that will be
/// written to `output`. An explicit `--public-key` / `--gcp-key-version` wins;
/// otherwise this falls back to the nearest `.kseal.kdl` and its committed key,
/// anchored on the output's own directory so the value is bound to the
/// environment it lands in, not wherever the command runs. The fallback needs
/// only repo access — no KMS — which is what lets both sealing and key rotation
/// run offline, and it records the environment's real provider and key version.
async fn public_key_for_output(
    pem_path: &Option<PathBuf>,
    gcp_key_version: &Option<String>,
    output: &Path,
) -> Result<PublicKey, Box<dyn std::error::Error>> {
    if pem_path.is_none() && gcp_key_version.is_none() {
        let cfg = config::Config::find(&config_anchor(&std::env::current_dir()?, output)?)?;
        let config::Config::GoogleCloud { key, public_key } = cfg;
        let kms_ref = KmsRef::GoogleCloud {
            key: key.to_string(),
        };
        return Ok(PublicKey::from_pem(
            &fs::read_to_string(&public_key)?,
            kms_ref,
        )?);
    }
    resolve_public_key(pem_path, gcp_key_version).await
}

/// Build a public key from either an offline PEM or a Google Cloud KMS key
/// version. Exactly one source must be given. An offline PEM is recorded as a
/// [`KmsRef::Local`] — the provider is decided by the source, never labelled by
/// hand, so the record cannot disagree with what can open the file.
async fn resolve_public_key(
    pem_path: &Option<PathBuf>,
    gcp_key_version: &Option<String>,
) -> Result<PublicKey, Box<dyn std::error::Error>> {
    match (pem_path, gcp_key_version) {
        (Some(path), None) => Ok(PublicKey::from_pem(
            &fs::read_to_string(path)?,
            KmsRef::Local {},
        )?),
        (None, Some(version)) => {
            let (pem, kms_ref) = kseal_google_cloud::fetch_public_key(version.clone()).await?;
            Ok(PublicKey::from_pem(&pem, kms_ref)?)
        }
        (Some(_), Some(_)) | (None, None) => {
            Err("provide exactly one public-key source: a PEM file or a KMS key version".into())
        }
    }
}

/// The KMS key version to unwrap a sealed file with: the caller's override, or
/// the file's own recorded version. A locally-sealed file has no KMS unwrapper,
/// so it needs `--private-key` instead.
fn unwrap_version(
    sealed: &SealedFile,
    override_version: &Option<String>,
) -> Result<String, String> {
    match sealed.kms() {
        KmsRef::GoogleCloud { key } => Ok(override_version.clone().unwrap_or_else(|| key.clone())),
        KmsRef::Local {} => {
            Err("this file was sealed with a local key; pass --private-key".to_owned())
        }
    }
}

/// Write a freshly-created private key, 0600 on unix. Uses create_new so it
/// never overwrites an existing key (and mode applies only at creation, so
/// write-then-chmod's brief 0644 window and its overwrite-keeps-old-mode bug
/// are both avoided).
fn write_private_key(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .map_err(|e| std::io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
    file.write_all(bytes)
}

/// Write a sealed file's JSON to `path` by writing a sibling temp file and
/// renaming it over the destination, so a reader or a crash never sees a
/// half-written sealed file — the rename either replaces the old one wholesale
/// or leaves it untouched. The temp name carries a random suffix.
fn write_sealed(path: &Path, sealed: &SealedFile) -> CliResult {
    let name = path.file_name().unwrap_or(std::ffi::OsStr::new("sealed"));
    let mut tmp = path.to_path_buf();
    tmp.set_file_name(format!(
        ".{}.tmp.{:016x}",
        name.to_string_lossy(),
        rand::random::<u64>()
    ));
    write_via_temp(path, &tmp, format!("{}\n", sealed.to_json()?).as_bytes())?;
    Ok(())
}

/// Write `bytes` to `tmp`, sync it, and rename it over `path`. `tmp` is
/// created exclusively, so an existing file or symlink there is an error rather
/// than something to write through; once this call has created `tmp`, any
/// later failure removes it.
fn write_via_temp(path: &Path, tmp: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(tmp)
        .map_err(|e| std::io::Error::new(e.kind(), format!("{}: {e}", tmp.display())))?;
    let written = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::rename(tmp, path));
    if written.is_err() {
        fs::remove_file(tmp).ok();
    }
    written
}

/// The directory to search for `.kseal.kdl`: the output file's own directory,
/// resolved to a real absolute path (`..` collapsed) so the search climbs the
/// output's true ancestors, not the working directory's, wherever it runs.
fn config_anchor(cwd: &Path, output: &Path) -> std::io::Result<PathBuf> {
    let absolute = cwd.join(output);
    let dir = absolute.parent().unwrap_or(&absolute);
    // Canonicalize so `..` segments resolve; otherwise the ancestor walk would
    // pass back through the working directory (e.g. `dev/../prod` climbs `dev`).
    dir.canonicalize().map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("output directory {} not usable: {e}", dir.display()),
        )
    })
}

/// Read raw bytes from a file, or all of stdin when no path is given.
fn read_bytes(path: &Option<PathBuf>) -> std::io::Result<Vec<u8>> {
    match path {
        Some(path) => fs::read(path),
        None => {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            Ok(buf)
        }
    }
}

/// Read UTF-8 text (a sealed JSON file) from a file or stdin.
fn read_text(path: &Option<PathBuf>) -> std::io::Result<String> {
    match path {
        Some(path) => fs::read_to_string(path),
        None => {
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            Ok(buf)
        }
    }
}

/// Write bytes to stdout verbatim, with no trailing newline.
fn write_bytes(bytes: &[u8]) -> std::io::Result<()> {
    std::io::stdout().write_all(bytes)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use kseal::SealedFile;

    use super::{
        Rewrap, VERSION, config_anchor, inspect_metadata, resolve_public_key, unwrap_version,
        write_sealed, write_via_temp,
    };

    #[test]
    fn version_names_the_tool_and_crate_version() {
        assert!(
            VERSION.starts_with(concat!("kseal ", env!("CARGO_PKG_VERSION"))),
            "{VERSION}"
        );
    }

    fn sealed_with_kms(kms: &str) -> SealedFile {
        let json = format!(
            r#"{{"schema":"kseal/v1","secret":"N","kms":{kms},"wrapped_dek":"AA==","aes":{{"nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AA=="}}}}"#
        );
        SealedFile::from_json(&json).unwrap()
    }

    fn sealed_gcp(key: &str) -> SealedFile {
        sealed_with_kms(&format!(r#"{{"provider":"google-cloud","key":"{key}"}}"#))
    }

    fn sealed_local() -> SealedFile {
        sealed_with_kms(r#"{"provider":"local"}"#)
    }

    #[test]
    fn gcp_uses_file_version_by_default_and_honors_override() {
        let file = sealed_gcp("projects/p/cryptoKeyVersions/1");
        assert_eq!(
            unwrap_version(&file, &None).unwrap(),
            "projects/p/cryptoKeyVersions/1"
        );
        assert_eq!(
            unwrap_version(&file, &Some("projects/p/cryptoKeyVersions/2".to_owned())).unwrap(),
            "projects/p/cryptoKeyVersions/2"
        );
    }

    #[test]
    fn local_needs_private_key_even_with_an_override() {
        let file = sealed_local();
        assert!(unwrap_version(&file, &None).is_err());
        // An override must not route a locally-sealed file to KMS.
        assert!(unwrap_version(&file, &Some("projects/p/cryptoKeyVersions/9".to_owned())).is_err());
    }

    #[test]
    fn inspect_json_keys_are_the_stable_contract() {
        let file = sealed_gcp("projects/p/cryptoKeyVersions/1");
        let meta = inspect_metadata(&file);
        // serde_json's Map is a BTreeMap, so keys serialize in sorted order.
        let keys: Vec<&str> = meta
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, ["body_sha256", "kms", "schema", "secret"]);
        let kms_keys: Vec<&str> = meta["kms"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(kms_keys, ["key", "provider"]);
        // No plaintext-bearing fields leak into the metadata view.
        assert!(meta.get("wrapped_dek").is_none());
        assert!(meta.get("aes").is_none());
        // A local file's kms carries only the provider tag, no key.
        let local = inspect_metadata(&sealed_local());
        assert_eq!(local["kms"], serde_json::json!({"provider": "local"}));
    }

    #[test]
    fn write_sealed_writes_json_and_leaves_no_temp() {
        let dir = std::env::temp_dir().join(format!("kseal-write-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("s.enc");
        let file = sealed_local();
        write_sealed(&out, &file).unwrap();
        // The destination round-trips back to the same sealed value.
        let back = SealedFile::from_json(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(back.body_sha256(), file.body_sha256());
        assert_eq!(back.secret(), file.secret());
        // The temp sibling used for the atomic rename is gone.
        let temps: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp."))
            .collect();
        assert!(temps.is_empty(), "temp files left behind: {temps:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    fn scratch_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("kseal-{label}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn write_via_temp_refuses_an_existing_temp_and_leaves_it() {
        let dir = scratch_dir("temp-exists");
        let (out, tmp) = (dir.join("s.enc"), dir.join(".s.enc.tmp.x"));
        std::fs::write(&tmp, "someone else's").unwrap();
        assert!(write_via_temp(&out, &tmp, b"new").is_err());
        // Not ours to remove, and nothing reached the destination.
        assert_eq!(std::fs::read_to_string(&tmp).unwrap(), "someone else's");
        assert!(!out.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn write_via_temp_does_not_write_through_a_symlinked_temp() {
        let dir = scratch_dir("temp-symlink");
        let (out, tmp, target) = (
            dir.join("s.enc"),
            dir.join(".s.enc.tmp.x"),
            dir.join("target"),
        );
        std::fs::write(&target, "untouched").unwrap();
        std::os::unix::fs::symlink(&target, &tmp).unwrap();
        assert!(write_via_temp(&out, &tmp, b"new").is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "untouched");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_via_temp_removes_its_temp_when_the_rename_fails() {
        let dir = scratch_dir("rename-fails");
        // A non-empty directory at the destination makes the rename fail.
        let (out, tmp) = (dir.join("s.enc"), dir.join(".s.enc.tmp.x"));
        std::fs::create_dir_all(out.join("occupied")).unwrap();
        assert!(write_via_temp(&out, &tmp, b"new").is_err());
        assert!(!tmp.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn write_via_temp_replaces_a_symlinked_destination_instead_of_following_it() {
        let dir = scratch_dir("dest-symlink");
        let (out, tmp, target) = (
            dir.join("s.enc"),
            dir.join(".s.enc.tmp.x"),
            dir.join("target"),
        );
        std::fs::write(&target, "untouched").unwrap();
        std::os::unix::fs::symlink(&target, &out).unwrap();
        write_via_temp(&out, &tmp, b"new").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "untouched");
        assert!(!out.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "new");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rewrap_rejects_both_unwrap_sources() {
        let rewrap = Rewrap {
            input: None,
            private_key: Some("k.pem".into()),
            gcp_key_version: Some("projects/p/cryptoKeyVersions/1".to_owned()),
            to_public_key: Some("pub.pem".into()),
            to_gcp_key_version: None,
            output: "s.enc".into(),
        };
        let err = rewrap.run().await.unwrap_err().to_string();
        assert!(err.contains("only one of --private-key"), "{err}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn destination_key_needs_exactly_one_source() {
        let both = resolve_public_key(
            &Some("pub.pem".into()),
            &Some("projects/p/cryptoKeyVersions/1".to_owned()),
        )
        .await;
        assert!(both.is_err());
        assert!(resolve_public_key(&None, &None).await.is_err());
    }

    #[test]
    fn config_anchor_resolves_relative_output_to_its_real_dir() {
        let base = std::env::temp_dir().join(format!("kseal-anchor-{}", std::process::id()));
        let dev = base.join("dev");
        let prod = base.join("prod");
        std::fs::create_dir_all(&dev).unwrap();
        std::fs::create_dir_all(&prod).unwrap();
        // Sealing from dev/ to ../prod/ anchors on prod, not on dev.
        let anchor = config_anchor(&dev, Path::new("../prod/s.json")).unwrap();
        assert_eq!(anchor, prod.canonicalize().unwrap());
        std::fs::remove_dir_all(&base).ok();
    }
}
