//! Cross-resolver equivalence checks.
//!
//! `resolvers::aws_lc_rs` is a near-verbatim copy of `resolvers::ring`, so the two can silently
//! drift apart when only one is fixed. These tests pin every available resolver against the
//! others at the primitive level: a ciphertext produced by one must decrypt under any other, and
//! a digest computed by one must equal the others byte for byte.
//!
//! Anything not compiled in is skipped rather than failing, so this file is useful under any
//! combination of `default-resolver`, `ring-resolver` and `aws-lc-rs-resolver`.
#![cfg(feature = "std")]
#![cfg(any(
    feature = "default-resolver-crypto",
    feature = "ring-resolver",
    feature = "aws-lc-rs-resolver"
))]

use snow::{
    params::{CipherChoice, HashChoice},
    resolvers::CryptoResolver,
    types::Cipher,
};

const KEY: [u8; 32] = [0x24; 32];
const AD: &[u8] = b"associated data";
const PLAINTEXT: &[u8] = b"the mysterious ether awaits your message";
const TAGLEN: usize = 16;

/// Every resolver compiled into this build, paired with a name for assertion messages.
// The pushes are individually feature-gated, so this can't collapse into a `vec![]` literal.
#[allow(clippy::vec_init_then_push)]
fn resolvers() -> Vec<(&'static str, Box<dyn CryptoResolver>)> {
    let mut out: Vec<(&'static str, Box<dyn CryptoResolver>)> = Vec::new();
    #[cfg(feature = "default-resolver")]
    out.push(("default", Box::new(snow::resolvers::DefaultResolver)));
    #[cfg(feature = "ring-resolver")]
    out.push(("ring", Box::new(snow::resolvers::RingResolver)));
    #[cfg(feature = "aws-lc-rs-resolver")]
    out.push(("aws-lc-rs", Box::new(snow::resolvers::AwsLcRsResolver)));
    out
}

fn seal(cipher: &mut dyn Cipher, nonce: u64) -> Vec<u8> {
    let mut out = vec![0_u8; PLAINTEXT.len() + TAGLEN];
    let len = cipher.encrypt(nonce, AD, PLAINTEXT, &mut out);
    assert_eq!(len, PLAINTEXT.len() + TAGLEN, "unexpected ciphertext length");
    out
}

/// A ciphertext from one resolver must open under every other resolver, byte for byte.
///
/// This is the check that would catch a divergence in nonce byte order (big-endian for AES-GCM,
/// little-endian for ChaChaPoly), in tag placement, or in the two branches of `decrypt`.
#[test]
fn test_ciphertexts_are_interchangeable_across_resolvers() {
    // A nonce near the u64 boundary exercises the full 8 bytes, so an endianness mismatch can't
    // hide behind leading zeros the way it would with a small nonce.
    for nonce in [0_u64, 1, 0x0102_0304_0506_0708] {
        for choice in [CipherChoice::AESGCM, CipherChoice::ChaChaPoly] {
            let mut checked = 0;
            for (sealer_name, sealer_resolver) in resolvers() {
                let Some(mut sealer) = sealer_resolver.resolve_cipher(&choice) else { continue };
                sealer.set(&KEY);
                let ciphertext = seal(&mut *sealer, nonce);

                for (opener_name, opener_resolver) in resolvers() {
                    let Some(mut opener) = opener_resolver.resolve_cipher(&choice) else {
                        continue;
                    };
                    opener.set(&KEY);

                    let mut recovered = vec![0_u8; PLAINTEXT.len()];
                    let len = opener
                        .decrypt(nonce, AD, &ciphertext, &mut recovered)
                        .unwrap_or_else(|_| {
                            panic!(
                                "{sealer_name} ciphertext failed to open under {opener_name} \
                                 ({}, nonce {nonce})",
                                sealer.name()
                            )
                        });
                    assert_eq!(
                        &recovered[..len],
                        PLAINTEXT,
                        "{sealer_name} -> {opener_name} plaintext mismatch ({}, nonce {nonce})",
                        sealer.name()
                    );
                    checked += 1;
                }
            }
            // Guard against the whole loop silently doing nothing.
            let unsupported = resolvers().iter().all(|(_, r)| r.resolve_cipher(&choice).is_none());
            assert!(checked > 0 || unsupported, "no resolver pair was actually compared");
        }
    }
}

/// A wrong key must fail to authenticate on every resolver — otherwise the test above could pass
/// against an implementation that isn't actually checking the tag.
#[test]
fn test_tag_is_rejected_with_the_wrong_key() {
    for choice in [CipherChoice::AESGCM, CipherChoice::ChaChaPoly] {
        for (name, resolver) in resolvers() {
            let Some(mut sealer) = resolver.resolve_cipher(&choice) else { continue };
            sealer.set(&KEY);
            let ciphertext = seal(&mut *sealer, 0);

            let Some(mut opener) = resolver.resolve_cipher(&choice) else { continue };
            opener.set(&[0x42; 32]);
            let mut recovered = vec![0_u8; PLAINTEXT.len()];
            assert!(
                opener.decrypt(0, AD, &ciphertext, &mut recovered).is_err(),
                "{name} accepted a ciphertext under the wrong key ({})",
                sealer.name()
            );
        }
    }
}

/// Digests must agree across resolvers, including the incremental `input`/`result` path and the
/// advertised block/hash lengths that the HKDF in `SymmetricState` depends on.
#[test]
fn test_digests_agree_across_resolvers() {
    for choice in [HashChoice::SHA256, HashChoice::SHA512] {
        let mut reference: Option<(&'static str, Vec<u8>, usize, usize)> = None;

        for (name, resolver) in resolvers() {
            let Some(mut hasher) = resolver.resolve_hash(&choice) else { continue };

            // Feed the input in two chunks so a broken incremental path can't pass.
            hasher.reset();
            hasher.input(&PLAINTEXT[..7]);
            hasher.input(&PLAINTEXT[7..]);
            let mut digest = vec![0_u8; hasher.hash_len()];
            hasher.result(&mut digest);

            let (block_len, hash_len) = (hasher.block_len(), hasher.hash_len());
            match &reference {
                None => reference = Some((name, digest, block_len, hash_len)),
                Some((ref_name, ref_digest, ref_block, ref_hash)) => {
                    assert_eq!(
                        &digest,
                        ref_digest,
                        "{name} digest differs from {ref_name} ({})",
                        hasher.name()
                    );
                    assert_eq!(block_len, *ref_block, "{name} block_len differs from {ref_name}");
                    assert_eq!(hash_len, *ref_hash, "{name} hash_len differs from {ref_name}");
                },
            }
        }
    }
}

/// `reset` has to actually clear state, or a reused hasher would silently mix in old input. Only
/// meaningful across resolvers alongside the digest comparison above.
#[test]
fn test_hasher_reset_clears_state() {
    for choice in [HashChoice::SHA256, HashChoice::SHA512] {
        for (name, resolver) in resolvers() {
            let Some(mut hasher) = resolver.resolve_hash(&choice) else { continue };

            hasher.reset();
            hasher.input(PLAINTEXT);
            let mut first = vec![0_u8; hasher.hash_len()];
            hasher.result(&mut first);

            hasher.reset();
            hasher.input(b"something else entirely");
            hasher.reset();
            hasher.input(PLAINTEXT);
            let mut second = vec![0_u8; hasher.hash_len()];
            hasher.result(&mut second);

            assert_eq!(first, second, "{name} reset left state behind ({})", hasher.name());
        }
    }
}
