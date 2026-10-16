use base64::engine::general_purpose::STANDARD as B64;
use sha2::Digest as _;

use crate::error::Result;

/// One sealed secret value, tagged by its on-disk schema. A new on-disk format
/// is a new variant, and an unknown tag fails to deserialize. No plaintext ever
/// lives here: a caller gets one from [`seal`](crate::seal), stores its JSON,
/// and later hands it to [`open`](crate::open). The value's secret name is bound
/// into the AES-GCM AAD, so a sealed body cannot be replayed under another name.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "schema", deny_unknown_fields)]
pub enum SealedFile {
    #[serde(rename = "kseal/v1")]
    V1 {
        secret: String,
        kms: KmsRef,
        /// RSA-OAEP(SHA-256)-wrapped 32-byte data key.
        #[serde(with = "b64")]
        wrapped_dek: Vec<u8>,
        aes: AesBlock,
    },
}

impl SealedFile {
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn from_json(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
    }

    /// The secret name this value is sealed for (also its AEAD binding). Metadata,
    /// safe to read; no plaintext is exposed.
    pub fn secret(&self) -> &str {
        match self {
            SealedFile::V1 { secret, .. } => secret,
        }
    }

    /// The KMS key version that can unseal this value.
    pub fn kms(&self) -> &KmsRef {
        match self {
            SealedFile::V1 { kms, .. } => kms,
        }
    }

    /// The on-disk schema tag (the stable format identifier).
    pub fn schema(&self) -> &'static str {
        match self {
            SealedFile::V1 { .. } => "kseal/v1",
        }
    }

    /// SHA-256 over the sealed body's raw bytes — the AES-GCM nonce followed by
    /// the ciphertext — as lowercase hex. It is stable across
    /// [`rewrap`](crate::rewrap), which leaves the body untouched, so two sealed
    /// files with the same [`secret`](Self::secret) name and the same digest
    /// hold the same value and seeding can skip re-adding one. The converse does
    /// not hold: re-sealing the same value draws a fresh data key and nonce, so
    /// its digest differs. A skip keyed on this digest is therefore safe but
    /// conservative — it never skips a real change, but a re-seal (rather than a
    /// rewrap) of an unchanged value looks like a change.
    pub fn body_sha256(&self) -> String {
        match self {
            SealedFile::V1 { aes, .. } => {
                let mut hasher = sha2::Sha256::new();
                hasher.update(aes.nonce);
                hasher.update(&aes.ciphertext);
                format!("{:x}", hasher.finalize())
            }
        }
    }
}

/// Which KMS holds the private key that can unwrap a sealed value, addressed the
/// way that provider names keys. Tagged by `provider` on disk; a new backend is
/// a new variant, and each variant carries only the addressing that backend
/// needs. `open` dispatches on the variant, so this record must be truthful.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "provider", deny_unknown_fields)]
pub enum KmsRef {
    /// Google Cloud KMS, addressed by a fully-qualified crypto key *version*
    /// (projects/.../cryptoKeyVersions/N) so decrypt and rewrap call an exact
    /// version and rotation stays visible.
    #[serde(rename = "google-cloud")]
    GoogleCloud { key: String },
    /// A local RSA private key: self-tests and fully-offline use only. It records
    /// no key reference — the private key is supplied out of band, never by name.
    /// An empty struct variant, not a unit one, so `deny_unknown_fields` still
    /// rejects a stray field (a unit variant would silently accept any).
    #[serde(rename = "local")]
    Local {},
}

impl KmsRef {
    /// The provider's wire name, for display and text output.
    pub fn provider(&self) -> &'static str {
        match self {
            KmsRef::GoogleCloud { .. } => "google-cloud",
            KmsRef::Local {} => "local",
        }
    }
}

/// The AES-GCM nonce length in bytes.
pub(crate) const NONCE_LEN: usize = 12;

/// The AES-256-GCM body of a [`SealedFile`]. An internal representation, not
/// part of the public API: callers go through `seal` / `open`, never this. The
/// byte fields are base64 only on disk.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AesBlock {
    #[serde(with = "b64_nonce")]
    pub(crate) nonce: [u8; NONCE_LEN],
    /// Ciphertext concatenated with the 16-byte GCM tag.
    #[serde(with = "b64")]
    pub(crate) ciphertext: Vec<u8>,
}

/// base64 (de)serialization for a byte vector: the on-disk form of the wrapped
/// data key and the ciphertext.
mod b64 {
    use super::B64;
    use base64::Engine as _;
    use serde::{Deserialize as _, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(d)?;
        B64.decode(encoded).map_err(serde::de::Error::custom)
    }
}

/// base64 (de)serialization for the fixed-length nonce: length is enforced at
/// the disk boundary.
mod b64_nonce {
    use super::{B64, NONCE_LEN};
    use base64::Engine as _;
    use serde::{Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        nonce: &[u8; NONCE_LEN],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(nonce))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<[u8; NONCE_LEN], D::Error> {
        let bytes = super::b64::deserialize(d)?;
        let len = bytes.len();
        bytes.try_into().map_err(|_| {
            serde::de::Error::custom(format!("nonce must be {NONCE_LEN} bytes, got {len}"))
        })
    }
}
