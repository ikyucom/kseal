# kseal

Keep secret values in git, sealed with an asymmetric KMS key.

Anyone who has a key's public half can seal a value, offline, with no
credentials and no KMS call. Only an identity allowed to call the KMS
`asymmetricDecrypt` can open it, and the private key never leaves the KMS. So
adding a value takes nothing but the committed public key, and the only
permission that uses the key is decrypt, granted to the identity that must read
values.

kseal supports Google Cloud KMS.

## Why not sops

[sops](https://getsops.io/) calls a cloud KMS with symmetric encrypt / decrypt,
so it cannot use asymmetric KMS keys
([getsops/sops#691](https://github.com/getsops/sops/issues/691)). With a
symmetric key, everyone who adds a value needs a permission to use the same key
that decrypts, and keeping "may encrypt" apart from "may decrypt" is left to IAM
roles. sops also encrypts a whole file and decrypts all of it to edit one value;
kseal keeps one value per file.

## How it works

Sealing a value:

1. Draw a random 32-byte data key (DEK) and a random 12-byte nonce.
2. Encrypt the value with AES-256-GCM under the DEK. The secret's name is the
   associated data, so a sealed body cannot be moved to another name.
3. Wrap the DEK with the KMS public key using RSA-OAEP with SHA-256.

Opening reverses it: the KMS unwraps the DEK (`asymmetricDecrypt`), and kseal
decrypts the value locally. The KMS only ever sees the wrapped DEK, never the
value.

A sealed file is JSON:

```json
{
  "schema": "kseal/v1",
  "secret": "DB_PASSWORD",
  "kms": {
    "provider": "google-cloud",
    "key": "projects/my-project/locations/asia-northeast1/keyRings/kseal/cryptoKeys/secrets/cryptoKeyVersions/1"
  },
  "wrapped_dek": "DF9Jb12OjJPA7vgCBdHaCdYo…",
  "aes": {
    "nonce": "Qn3I90YTD2Ky4TgN",
    "ciphertext": "9+1D2ZHp4l8GZ8w0pmA+EqRz+5AOY7s="
  }
}
```

`kms.key` names an exact key version, so opening and rewrapping call a specific
version and a key rotation shows up in the diff. Sealing draws a fresh DEK and
nonce every time, so sealing the same value twice gives different files.

## Install

Releases carry static binaries for `x86_64-unknown-linux-musl`,
`x86_64-apple-darwin`, and `aarch64-apple-darwin`, with build provenance
attestations. Verify a download before using it:

```sh
gh release download v0.1.0 --repo ikyucom/kseal \
  --pattern 'kseal-v0.1.0-x86_64-unknown-linux-musl.tar.gz'
gh attestation verify kseal-v0.1.0-x86_64-unknown-linux-musl.tar.gz \
  --repo ikyucom/kseal \
  --signer-workflow ikyucom/kseal/.github/workflows/release.yaml
```

## Usage

The key must be a Google Cloud KMS asymmetric decryption key using
`RSA_DECRYPT_OAEP_2048_SHA256`, `RSA_DECRYPT_OAEP_3072_SHA256`, or
`RSA_DECRYPT_OAEP_4096_SHA256`.

### Pin a key for a directory

```sh
kseal init --out-dir prod \
  --gcp-key-version projects/my-project/locations/asia-northeast1/keyRings/kseal/cryptoKeys/secrets/cryptoKeyVersions/1
```

This fetches the key version's public key once and writes two files to commit
together: `prod/key.pem` and `prod/.kseal.kdl`.

```kdl
provider "google-cloud"
key "projects/my-project/locations/asia-northeast1/keyRings/kseal/cryptoKeys/secrets/cryptoKeyVersions/1"
public-key "key.pem"
```

Commands that write a sealed file look for the nearest `.kseal.kdl` above the
output path, so a value is sealed for the directory, and thus the environment,
it is stored in.

### Seal a value

```sh
printf %s "$VALUE" | kseal seal --name DB_PASSWORD --output prod/DB_PASSWORD.enc
```

This runs offline, using the committed public key. The secret name must match
where the value will be stored, since opening under another name fails.

### Check what a file is

```sh
kseal inspect --input prod/DB_PASSWORD.enc
kseal inspect --json --input prod/DB_PASSWORD.enc
```

Neither prints the value. `--json` is a stable object for tooling:
`{schema, secret, kms, body_sha256}`, where `body_sha256` is the SHA-256 of the
nonce followed by the ciphertext. It is unchanged by a rewrap, so a pipeline can
tell a rewrapped value from a new one.

### Verify the committed public key

```sh
kseal verify --config prod/.kseal.kdl \
  --expect-key-ring projects/my-project/locations/asia-northeast1/keyRings/kseal
```

This fetches the pinned version's public key and compares it with the committed
PEM, and `--expect-key-ring` rejects a config pointing at any other key ring.
Run it in CI, so that a change swapping `.kseal.kdl` and the PEM for someone
else's key fails.

### Open a value

```sh
kseal open --input prod/DB_PASSWORD.enc > value
```

This calls `asymmetricDecrypt` on the version recorded in the file, and needs
`roles/cloudkms.cryptoKeyDecrypter` on that key. The value goes to stdout
unchanged, trailing newline included; redirect it to a file rather than
capturing it in a shell variable.

### Rotate the key

```sh
kseal rewrap --input prod/DB_PASSWORD.enc --output prod/DB_PASSWORD.enc
```

Asymmetric KMS keys do not rotate automatically. To rotate, create a new key
version, pin it with `kseal init --force --out-dir prod --gcp-key-version …`,
then rewrap each sealed file. Rewrap unwraps the DEK with the file's current
version and wraps it for the nearest `.kseal.kdl` (or `--to-gcp-key-version`);
the encrypted value is untouched. Unwrapping needs decrypt access, so rewrap
runs wherever decrypting is allowed (typically CI). Keep the old version enabled
until no file refers to it.

## Security

kseal has not been audited by a third party. It implements no cryptography of
its own: AES-256-GCM comes from RustCrypto's
[`aes-gcm`](https://github.com/RustCrypto/AEADs/tree/master/aes-gcm) and
RSA-OAEP from RustCrypto's [`rsa`](https://github.com/RustCrypto/RSA), each of
which has had a security audit (`rsa` still has the timing issue below). What
kseal adds is how they are put together and the file format around them.

### What it protects

- A sealed value's confidentiality against anyone who can read the repository
  but cannot call `asymmetricDecrypt` on the key, including everyone who seals.
- A sealed value's integrity and its binding to its secret name: a changed
  nonce, ciphertext, or wrapped data key, a body moved to another name, or a
  body paired with another file's wrapped data key fails to open.

### What it does not protect

- Values from whoever can decrypt with the key. Grant decrypt only to the
  identity that must read values (typically CI); sealing needs only the public
  key (`roles/cloudkms.publicKeyViewer`) or the committed PEM.
- Which values exist and when they change. Secret names and key versions are in
  the clear, and `body_sha256` tells whether a value changed.
- Which value is current. The associated data is the secret's name only, so
  anyone who can commit can restore an older sealed file for the same name.
  Review changes to sealed files like any other change.
- Environments from each other, beyond their keys. The environment is not part
  of the associated data; give each environment its own KMS key, since a key
  shared by several environments lets any of them open the others' values.
- Timing of local decryption. Opening with `--private-key` decrypts with the
  `rsa` crate, which is not constant time
  ([RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071), the
  Marvin attack; no release fixes it). Use it only locally, never behind a
  service an attacker can time. Opening through the KMS and sealing are not
  affected: the KMS does the decryption, and sealing only encrypts.

## Development

```sh
cargo fmt --all
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo audit
cargo test --workspace
```

`kseal keygen` makes a local RSA key pair, and `--public-key` / `--private-key`
seal and open with local keys instead of KMS. These exist for tests: a real
private key belongs in the KMS.
