use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead as _, KeyInit as _, Payload},
};
use rand::RngCore as _;
use zeroize::Zeroizing;

use crate::{
    error::{Error, Result},
    format::{AesBlock, NONCE_LEN, SealedFile},
    key::PublicKey,
    provider::DekUnwrapper,
};

const DEK_LEN: usize = 32;

/// Seal a value: AES-256-GCM under a fresh random data key, with the secret
/// name bound as AAD, then RSA-OAEP-wrap the data key with the public key. No
/// KMS or credentials are needed here; `key` holds only the public key.
pub fn seal(plaintext: &[u8], secret_name: &str, key: &PublicKey) -> Result<SealedFile> {
    if secret_name.is_empty() {
        return Err(Error::EmptySecretName);
    }
    let mut rng = rand::thread_rng();

    let mut dek = Zeroizing::new([0u8; DEK_LEN]);
    rng.fill_bytes(&mut dek[..]);
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek[..]));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: secret_name.as_bytes(),
            },
        )
        .map_err(|_| Error::Aead)?;

    let wrapped_dek = key.wrap(&dek[..])?;

    Ok(SealedFile::V1 {
        secret: secret_name.to_owned(),
        kms: key.kms_ref(),
        wrapped_dek,
        aes: AesBlock { nonce, ciphertext },
    })
}

/// Open a sealed value: unwrap the data key via `unwrapper` (a KMS
/// asymmetricDecrypt in production), then AES-256-GCM-decrypt with the secret
/// name as AAD. A mismatched secret name, a tampered body, or a wrong key all
/// fail as [`Error::Aead`]. Generic over the unwrapper, so no trait object is
/// needed.
pub async fn open<U: DekUnwrapper>(file: &SealedFile, unwrapper: &U) -> Result<Zeroizing<Vec<u8>>> {
    match file {
        SealedFile::V1 {
            secret,
            wrapped_dek,
            aes,
            ..
        } => {
            let dek = Zeroizing::new(unwrapper.unwrap(wrapped_dek).await?);
            if dek.len() != DEK_LEN {
                return Err(Error::DekLen(dek.len()));
            }

            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek[..]));
            let plaintext = cipher
                .decrypt(
                    Nonce::from_slice(&aes.nonce),
                    Payload {
                        msg: &aes.ciphertext,
                        aad: secret.as_bytes(),
                    },
                )
                .map_err(|_| Error::Aead)?;

            Ok(Zeroizing::new(plaintext))
        }
    }
}

/// Re-wrap a sealed value's data key under a new public key, leaving the AES
/// body untouched. Unwraps the data key via `unwrapper` (the file's current KMS
/// version) and RSA-OAEP-wraps it with `new_key`; the ciphertext, nonce, and
/// secret name (the AEAD binding) all carry over, so the plaintext is never
/// materialized. This is the key-rotation path: seal once, then rewrap to each
/// new key version. A wrong `unwrapper` fails as [`Error::Rsa`].
pub async fn rewrap<U: DekUnwrapper>(
    file: &SealedFile,
    unwrapper: &U,
    new_key: &PublicKey,
) -> Result<SealedFile> {
    match file {
        SealedFile::V1 {
            secret,
            wrapped_dek,
            aes,
            ..
        } => {
            let dek = Zeroizing::new(unwrapper.unwrap(wrapped_dek).await?);
            if dek.len() != DEK_LEN {
                return Err(Error::DekLen(dek.len()));
            }
            let rewrapped = new_key.wrap(&dek)?;

            Ok(SealedFile::V1 {
                secret: secret.clone(),
                kms: new_key.kms_ref(),
                wrapped_dek: rewrapped,
                aes: aes.clone(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use rsa::{
        RsaPrivateKey, RsaPublicKey,
        pkcs8::{EncodePublicKey as _, LineEnding},
    };

    use super::{open, rewrap, seal};
    use crate::{
        PublicKey,
        error::Error,
        format::{KmsRef, SealedFile},
        local::LocalPrivateKey,
    };

    fn keypair() -> (PublicKey, LocalPrivateKey) {
        let mut rng = rand::thread_rng();
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA key");
        let pub_key = RsaPublicKey::from(&priv_key);
        let kms_ref = KmsRef::Local {};
        let pem = pub_key
            .to_public_key_pem(LineEnding::LF)
            .expect("encode public key PEM");
        (
            PublicKey::from_pem(&pem, kms_ref).expect("parse public key PEM"),
            LocalPrivateKey::new(priv_key),
        )
    }

    #[tokio::test]
    async fn round_trip_preserves_bytes_exactly() {
        let (w, u) = keypair();
        // PEM-shaped, multi-line, with a trailing newline: the RwG-key shape
        // that lost a byte when it went through a shell variable.
        let plaintext =
            b"-----BEGIN RSA PRIVATE KEY-----\nAAAA\nBBBB\n-----END RSA PRIVATE KEY-----\n";
        let sealed = seal(plaintext, "RSOWN_SESSION-HASH_KEY", &w).unwrap();
        assert_eq!(&open(&sealed, &u).await.unwrap()[..], &plaintext[..]);
    }

    #[tokio::test]
    async fn empty_and_binary_values_round_trip() {
        let (w, u) = keypair();
        for plaintext in [b"".as_slice(), &[0u8, 1, 2, 255, 0, 128][..]] {
            let sealed = seal(plaintext, "N", &w).unwrap();
            assert_eq!(&open(&sealed, &u).await.unwrap()[..], plaintext);
        }
    }

    #[tokio::test]
    async fn json_holds_no_plaintext_and_survives_disk_form() {
        let (w, u) = keypair();
        let sealed = seal(b"super-secret-value", "API-KEY", &w).unwrap();
        let json = sealed.to_json().unwrap();
        assert!(!json.contains("super-secret-value"));
        // The on-disk form still carries its schema tag.
        assert!(json.contains("\"schema\": \"kseal/v1\""));
        let reparsed = SealedFile::from_json(&json).unwrap();
        assert_eq!(
            &open(&reparsed, &u).await.unwrap()[..],
            b"super-secret-value"
        );
    }

    #[tokio::test]
    async fn wrong_secret_name_fails_to_open() {
        let (w, u) = keypair();
        let mut sealed = seal(b"v", "CORRECT-NAME", &w).unwrap();
        let SealedFile::V1 { secret, .. } = &mut sealed;
        *secret = "WRONG-NAME".to_owned();
        assert!(matches!(open(&sealed, &u).await, Err(Error::Aead)));
    }

    #[tokio::test]
    async fn tampered_ciphertext_fails_to_open() {
        let (w, u) = keypair();
        let mut sealed = seal(b"value", "N", &w).unwrap();
        // Flip a bit of the ciphertext so the GCM tag no longer verifies.
        let SealedFile::V1 { aes, .. } = &mut sealed;
        aes.ciphertext[0] ^= 0x01;
        assert!(matches!(open(&sealed, &u).await, Err(Error::Aead)));
    }

    #[tokio::test]
    async fn tampered_nonce_fails_to_open() {
        let (w, u) = keypair();
        let mut sealed = seal(b"value", "N", &w).unwrap();
        let SealedFile::V1 { aes, .. } = &mut sealed;
        aes.nonce[0] ^= 0x01;
        assert!(matches!(open(&sealed, &u).await, Err(Error::Aead)));
    }

    #[tokio::test]
    async fn tampered_wrapped_dek_fails_to_open() {
        let (w, u) = keypair();
        let mut sealed = seal(b"value", "N", &w).unwrap();
        let SealedFile::V1 { wrapped_dek, .. } = &mut sealed;
        wrapped_dek[0] ^= 0x01;
        assert!(matches!(open(&sealed, &u).await, Err(Error::Rsa(_))));
    }

    #[tokio::test]
    async fn a_body_does_not_open_under_another_files_data_key() {
        // Two values sealed for the same name under the same key: grafting one
        // file's wrapped data key onto the other's body must not open, since
        // each seal draws its own data key.
        let (w, u) = keypair();
        let mut a = seal(b"value-a", "N", &w).unwrap();
        let b = seal(b"value-b", "N", &w).unwrap();
        let SealedFile::V1 {
            wrapped_dek: b_dek, ..
        } = &b;
        let SealedFile::V1 { wrapped_dek, .. } = &mut a;
        *wrapped_dek = b_dek.clone();
        assert!(matches!(open(&a, &u).await, Err(Error::Aead)));
    }

    #[test]
    fn sealing_twice_draws_a_fresh_data_key_and_nonce() {
        let (w, _u) = keypair();
        let first = seal(b"same", "N", &w).unwrap();
        let second = seal(b"same", "N", &w).unwrap();
        let SealedFile::V1 {
            wrapped_dek: w1,
            aes: a1,
            ..
        } = &first;
        let SealedFile::V1 {
            wrapped_dek: w2,
            aes: a2,
            ..
        } = &second;
        assert_ne!(a1.nonce, a2.nonce);
        assert_ne!(w1, w2);
        assert_ne!(first.body_sha256(), second.body_sha256());
    }

    #[tokio::test]
    async fn a_data_key_of_the_wrong_length_is_rejected() {
        // An unwrapper that returns something other than a 32-byte key, as a
        // misbehaving provider might, must not reach AES.
        struct ShortKey;
        impl crate::DekUnwrapper for ShortKey {
            async fn unwrap(&self, _wrapped: &[u8]) -> crate::Result<Vec<u8>> {
                Ok(vec![0u8; 16])
            }
        }
        let (w, _u) = keypair();
        let sealed = seal(b"v", "N", &w).unwrap();
        assert!(matches!(
            open(&sealed, &ShortKey).await,
            Err(Error::DekLen(16))
        ));
    }

    #[tokio::test]
    async fn wrong_private_key_fails_to_open() {
        let (w, _u) = keypair();
        let (_w2, u2) = keypair();
        let sealed = seal(b"value", "N", &w).unwrap();
        assert!(matches!(open(&sealed, &u2).await, Err(Error::Rsa(_))));
    }

    #[tokio::test]
    async fn rewrap_moves_key_and_keeps_body() {
        let (w1, u1) = keypair();
        let (w2, u2) = keypair();
        let sealed = seal(b"rotate-me", "API-KEY", &w1).unwrap();
        let rewrapped = rewrap(&sealed, &u1, &w2).await.unwrap();
        // The AES body and its AAD binding carry over untouched; only the
        // wrapped data key changes.
        let SealedFile::V1 {
            secret: s0,
            aes: a0,
            wrapped_dek: w0,
            ..
        } = &sealed;
        let SealedFile::V1 {
            secret: s1,
            aes: a1,
            wrapped_dek: w1,
            ..
        } = &rewrapped;
        assert_eq!(s1, s0);
        assert_eq!(a1.nonce, a0.nonce);
        assert_eq!(a1.ciphertext, a0.ciphertext);
        assert_ne!(w1, w0);
        // The body digest is what seeding compares to skip an unchanged secret,
        // so it must survive a rewrap even as the wrapped data key changes.
        assert_eq!(rewrapped.body_sha256(), sealed.body_sha256());
        // It now opens under the new key and no longer under the old one.
        assert_eq!(&open(&rewrapped, &u2).await.unwrap()[..], b"rotate-me");
        assert!(matches!(open(&rewrapped, &u1).await, Err(Error::Rsa(_))));
    }

    #[test]
    fn schema_accessor_matches_serialized_tag() {
        let (w, _u) = keypair();
        let sealed = seal(b"v", "N", &w).unwrap();
        let value: serde_json::Value = serde_json::from_str(&sealed.to_json().unwrap()).unwrap();
        // The `schema()` literal and the serde tag are two copies of the same
        // string (serde's rename cannot reference a constant); pin them equal.
        assert_eq!(value["schema"], sealed.schema());
    }

    #[test]
    fn seal_rejects_empty_secret_name() {
        let (w, _u) = keypair();
        assert!(matches!(seal(b"v", "", &w), Err(Error::EmptySecretName)));
    }

    #[test]
    fn from_json_rejects_unknown_fields() {
        let (w, _u) = keypair();
        let json = seal(b"v", "N", &w).unwrap().to_json().unwrap();
        let tampered = json.replacen('{', "{\n  \"extra\": 1,", 1);
        assert!(SealedFile::from_json(&tampered).is_err());
    }

    #[test]
    fn from_json_rejects_a_local_kms_with_a_key() {
        let (w, _u) = keypair();
        let json = seal(b"v", "N", &w).unwrap().to_json().unwrap();
        // A local kms records no key. Injecting one must be rejected, not
        // silently ignored (which a unit variant would have allowed).
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value["kms"]["key"] = serde_json::Value::String("x".to_owned());
        assert!(SealedFile::from_json(&value.to_string()).is_err());
    }
}
