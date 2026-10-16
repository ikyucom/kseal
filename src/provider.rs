use std::future::Future;

use crate::error::Result;

/// Decrypt side. Unwraps the data key, typically by calling a KMS
/// asymmetricDecrypt so the private key never leaves the KMS. There is more than
/// one implementation (a local key, Google Cloud, ...), so this stays a trait
/// and [`open`](crate::open) is generic over it; no trait object is needed. The
/// method is spelled as a returned `impl Future` rather than `async fn` so the
/// future is `Send` and callers can drive it on any runtime. The returned data
/// key is a plain `Vec<u8>`, so an implementation needs no `zeroize` dependency;
/// the core zeroizes it on receipt.
pub trait DekUnwrapper {
    fn unwrap(&self, wrapped: &[u8]) -> impl Future<Output = Result<Vec<u8>>> + Send;
}
