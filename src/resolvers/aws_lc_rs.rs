//! An `aws-lc-rs`-backed resolver.
//!
//! NB: this is intentionally a near-verbatim port of `resolvers::ring` — aws-lc-rs exposes a
//! ring-compatible `aead`/`digest`/`rand` surface, so the two implementations are meant to stay
//! in lockstep. Any fix to nonce construction, the in-place/copy branches of `decrypt`, or tag
//! placement needs applying to both files. `tests/resolvers.rs` cross-checks them against the
//! `default-resolver` to catch drift.
//!
//! Unlike `resolvers::ring`, this module is std-only (aws-lc-rs is), which is why
//! `aws-lc-rs-resolver` enables snow's `std` feature and there's no `no_std` import path below.

use super::CryptoResolver;
use crate::{
    constants::{CIPHERKEYLEN, TAGLEN},
    params::{CipherChoice, DHChoice, HashChoice},
    types::{Cipher, Dh, Hash, Random},
    Error,
};
use aws_lc_rs::{
    aead::{self, LessSafeKey, UnboundKey},
    digest,
    rand::{SecureRandom, SystemRandom},
};

/// A resolver that chooses [aws-lc-rs](https://github.com/aws/aws-lc-rs)-backed
/// primitives when available.
#[allow(clippy::module_name_repetitions)]
#[derive(Default)]
pub struct AwsLcRsResolver;

#[cfg(feature = "aws-lc-rs")]
impl CryptoResolver for AwsLcRsResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        Some(Box::new(AwsLcRsRng::default()))
    }

    /// DH is deliberately left to the `default-resolver` fallback for now.
    ///
    /// Note this is *not* for ring's reason. ring can't implement `Dh` at all, because its
    /// agreement API is ephemeral-only (`EphemeralPrivateKey` is consumed by `agree_ephemeral`),
    /// which can't model a Noise static key. aws-lc-rs does expose a reusable
    /// `agreement::PrivateKey` plus `X25519` and `ECDH_P256`, so a native implementation is
    /// possible here — including P-256, which no native backend currently provides. It's left
    /// out of this change because it wants its own known-answer vectors (RFC 7748 / RFC 5903)
    /// rather than being smuggled in with the port.
    fn resolve_dh(&self, _choice: &DHChoice) -> Option<Box<dyn Dh>> {
        None
    }

    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        match *choice {
            HashChoice::SHA256 => Some(Box::new(HashSHA256::default())),
            HashChoice::SHA512 => Some(Box::new(HashSHA512::default())),
            _ => None,
        }
    }

    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        match *choice {
            CipherChoice::AESGCM => Some(Box::new(CipherAESGCM::default())),
            CipherChoice::ChaChaPoly => Some(Box::new(CipherChaChaPoly::default())),
            #[cfg(feature = "use-xchacha20poly1305")]
            CipherChoice::XChaChaPoly => None,
        }
    }
}

// NB: Intentionally private so RNG details aren't leaked into
// the public API.
struct AwsLcRsRng {
    rng: SystemRandom,
}

impl Default for AwsLcRsRng {
    fn default() -> Self {
        Self { rng: SystemRandom::new() }
    }
}

impl Random for AwsLcRsRng {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.rng.fill(dest).map_err(|_| Error::Rng)
    }
}

struct CipherAESGCM {
    // NOTE: LessSafeKey is chosen here because nonce atomicity is handled outside of this structure.
    // See aws-lc-rs documentation for more details on the naming choices.
    key: LessSafeKey,
}

impl Default for CipherAESGCM {
    fn default() -> Self {
        CipherAESGCM {
            key: LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, &[0_u8; 32]).unwrap()),
        }
    }
}

impl Cipher for CipherAESGCM {
    fn name(&self) -> &'static str {
        "AESGCM"
    }

    fn set(&mut self, key: &[u8; CIPHERKEYLEN]) {
        self.key = aead::LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, key).unwrap());
    }

    fn encrypt(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) -> usize {
        let mut nonce_bytes = [0_u8; 12];
        copy_slices!(&nonce.to_be_bytes(), &mut nonce_bytes[4..]);

        out[..plaintext.len()].copy_from_slice(plaintext);

        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let tag = self
            .key
            .seal_in_place_separate_tag(
                nonce,
                aead::Aad::from(authtext),
                &mut out[..plaintext.len()],
            )
            .unwrap();
        out[plaintext.len()..plaintext.len() + TAGLEN].copy_from_slice(tag.as_ref());

        plaintext.len() + TAGLEN
    }

    fn decrypt(
        &self,
        nonce: u64,
        authtext: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut nonce_bytes = [0_u8; 12];
        copy_slices!(&nonce.to_be_bytes(), &mut nonce_bytes[4..]);
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        if out.len() >= ciphertext.len() {
            let in_out = &mut out[..ciphertext.len()];
            in_out.copy_from_slice(ciphertext);

            let len = self
                .key
                .open_in_place(nonce, aead::Aad::from(authtext), in_out)
                .map_err(|_| Error::Decrypt)?
                .len();

            Ok(len)
        } else {
            let mut in_out = ciphertext.to_vec();

            let out0 = self
                .key
                .open_in_place(nonce, aead::Aad::from(authtext), &mut in_out)
                .map_err(|_| Error::Decrypt)?;

            out[..out0.len()].copy_from_slice(out0);
            Ok(out0.len())
        }
    }
}

struct CipherChaChaPoly {
    // NOTE: LessSafeKey is chosen here because nonce atomicity is to be ensured outside of this structure.
    // See aws-lc-rs documentation for more details on the naming choices.
    key: aead::LessSafeKey,
}

impl Default for CipherChaChaPoly {
    fn default() -> Self {
        Self {
            key: LessSafeKey::new(UnboundKey::new(&aead::CHACHA20_POLY1305, &[0_u8; 32]).unwrap()),
        }
    }
}

impl Cipher for CipherChaChaPoly {
    fn name(&self) -> &'static str {
        "ChaChaPoly"
    }

    fn set(&mut self, key: &[u8; CIPHERKEYLEN]) {
        self.key = LessSafeKey::new(UnboundKey::new(&aead::CHACHA20_POLY1305, key).unwrap());
    }

    fn encrypt(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) -> usize {
        let mut nonce_bytes = [0_u8; 12];
        copy_slices!(&nonce.to_le_bytes(), &mut nonce_bytes[4..]);
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        out[..plaintext.len()].copy_from_slice(plaintext);

        let tag = self
            .key
            .seal_in_place_separate_tag(
                nonce,
                aead::Aad::from(authtext),
                &mut out[..plaintext.len()],
            )
            .unwrap();
        out[plaintext.len()..plaintext.len() + TAGLEN].copy_from_slice(tag.as_ref());

        plaintext.len() + TAGLEN
    }

    fn decrypt(
        &self,
        nonce: u64,
        authtext: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut nonce_bytes = [0_u8; 12];
        copy_slices!(&nonce.to_le_bytes(), &mut nonce_bytes[4..]);
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        if out.len() >= ciphertext.len() {
            let in_out = &mut out[..ciphertext.len()];
            in_out.copy_from_slice(ciphertext);

            let len = self
                .key
                .open_in_place(nonce, aead::Aad::from(authtext), in_out)
                .map_err(|_| Error::Decrypt)?
                .len();

            Ok(len)
        } else {
            let mut in_out = ciphertext.to_vec();

            let out0 = self
                .key
                .open_in_place(nonce, aead::Aad::from(authtext), &mut in_out)
                .map_err(|_| Error::Decrypt)?;

            out[..out0.len()].copy_from_slice(out0);
            Ok(out0.len())
        }
    }
}
struct HashSHA256 {
    context: digest::Context,
}

impl Default for HashSHA256 {
    fn default() -> Self {
        Self { context: digest::Context::new(&digest::SHA256) }
    }
}

impl Hash for HashSHA256 {
    fn name(&self) -> &'static str {
        "SHA256"
    }

    fn block_len(&self) -> usize {
        64
    }

    fn hash_len(&self) -> usize {
        32
    }

    fn reset(&mut self) {
        self.context = digest::Context::new(&digest::SHA256);
    }

    fn input(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    fn result(&mut self, out: &mut [u8]) {
        out[..32].copy_from_slice(self.context.clone().finish().as_ref());
    }
}

struct HashSHA512 {
    context: digest::Context,
}

impl Default for HashSHA512 {
    fn default() -> Self {
        Self { context: digest::Context::new(&digest::SHA512) }
    }
}

impl Hash for HashSHA512 {
    fn name(&self) -> &'static str {
        "SHA512"
    }

    fn block_len(&self) -> usize {
        128
    }

    fn hash_len(&self) -> usize {
        64
    }

    fn reset(&mut self) {
        self.context = digest::Context::new(&digest::SHA512);
    }

    fn input(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    fn result(&mut self, out: &mut [u8]) {
        out[..64].copy_from_slice(self.context.clone().finish().as_ref());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn test_randomness_sanity() {
        let mut samples = BTreeSet::new();
        let mut rng = AwsLcRsRng::default();
        for _ in 0..100_000 {
            let mut buf = vec![0_u8; 128];
            rng.try_fill_bytes(&mut buf).unwrap();
            assert!(samples.insert(buf));
        }
    }
}
