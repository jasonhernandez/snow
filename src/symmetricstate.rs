#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

use crate::{
    cipherstate::CipherState,
    constants::{CIPHERKEYLEN, MAXHASHLEN},
    error::Error,
    types::Hash,
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Copy, Clone)]
pub(crate) struct SymmetricStateData {
    h: [u8; MAXHASHLEN],
    ck: [u8; MAXHASHLEN],
    has_key: bool,
}

impl Default for SymmetricStateData {
    fn default() -> Self {
        SymmetricStateData { h: [0_u8; MAXHASHLEN], ck: [0_u8; MAXHASHLEN], has_key: false }
    }
}

// `SymmetricStateData` stays `Copy` (it's snapshotted on every message), so it can't have a
// `Drop` of its own. Implementing `Zeroize` instead lets the snapshots be held in a
// `Zeroizing` wrapper, which does wipe them when they go out of scope.
impl Zeroize for SymmetricStateData {
    fn zeroize(&mut self) {
        self.ck.zeroize();
        self.h.zeroize();
        self.has_key = false;
    }
}

pub(crate) struct SymmetricState {
    cipherstate: CipherState,
    hasher: Box<dyn Hash>,
    inner: SymmetricStateData,
}

impl SymmetricState {
    pub fn new(cipherstate: CipherState, hasher: Box<dyn Hash>) -> SymmetricState {
        SymmetricState { cipherstate, hasher, inner: SymmetricStateData::default() }
    }

    pub fn initialize(&mut self, handshake_name: &str) {
        if handshake_name.len() <= self.hasher.hash_len() {
            copy_slices!(handshake_name.as_bytes(), self.inner.h);
        } else {
            self.hasher.reset();
            self.hasher.input(handshake_name.as_bytes());
            self.hasher.result(&mut self.inner.h);
        }
        copy_slices!(self.inner.h, &mut self.inner.ck);
        self.inner.has_key = false;
    }

    pub fn mix_key(&mut self, data: &[u8]) {
        let hash_len = self.hasher.hash_len();
        // `hkdf_output.0` is the next chaining key and `hkdf_output.1` carries the cipher key,
        // so these buffers hold secret material and are wiped when they leave scope.
        let mut hkdf_output = Zeroizing::new(([0_u8; MAXHASHLEN], [0_u8; MAXHASHLEN]));
        // Deref the wrapper once; splitting the borrow through `DerefMut` twice won't compile.
        let out = &mut *hkdf_output;
        self.hasher.hkdf(&self.inner.ck[..hash_len], data, 2, &mut out.0, &mut out.1, &mut []);

        // TODO(mcginty): use `split_array_ref` once stable to avoid memory inefficiency
        let mut cipher_key = Zeroizing::new([0_u8; CIPHERKEYLEN]);
        cipher_key.copy_from_slice(&hkdf_output.1[..CIPHERKEYLEN]);

        self.inner.ck = hkdf_output.0;
        self.cipherstate.set(&cipher_key, 0);
        self.inner.has_key = true;
    }

    pub fn mix_hash(&mut self, data: &[u8]) {
        let hash_len = self.hasher.hash_len();
        self.hasher.reset();
        self.hasher.input(&self.inner.h[..hash_len]);
        self.hasher.input(data);
        self.hasher.result(&mut self.inner.h);
    }

    pub fn mix_key_and_hash(&mut self, data: &[u8]) {
        let hash_len = self.hasher.hash_len();
        let mut hkdf_output =
            Zeroizing::new(([0_u8; MAXHASHLEN], [0_u8; MAXHASHLEN], [0_u8; MAXHASHLEN]));
        let out = &mut *hkdf_output;
        self.hasher.hkdf(&self.inner.ck[..hash_len], data, 3, &mut out.0, &mut out.1, &mut out.2);
        self.inner.ck = hkdf_output.0;
        self.mix_hash(&hkdf_output.1[..hash_len]);

        // TODO(mcginty): use `split_array_ref` once stable to avoid memory inefficiency
        let mut cipher_key = Zeroizing::new([0_u8; CIPHERKEYLEN]);
        cipher_key.copy_from_slice(&hkdf_output.2[..CIPHERKEYLEN]);
        self.cipherstate.set(&cipher_key, 0);
    }

    pub fn has_key(&self) -> bool {
        self.inner.has_key
    }

    /// Encrypt a message and mixes in the hash of the output
    pub fn encrypt_and_mix_hash(
        &mut self,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let hash_len = self.hasher.hash_len();
        let output_len = if self.inner.has_key {
            self.cipherstate.encrypt_ad(&self.inner.h[..hash_len], plaintext, out)?
        } else {
            copy_slices!(plaintext, out);
            plaintext.len()
        };
        self.mix_hash(&out[..output_len]);
        Ok(output_len)
    }

    pub fn decrypt_and_mix_hash(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        let hash_len = self.hasher.hash_len();
        let payload_len = if self.inner.has_key {
            self.cipherstate.decrypt_ad(&self.inner.h[..hash_len], data, out)?
        } else {
            if out.len() < data.len() {
                return Err(Error::Decrypt);
            }
            copy_slices!(data, out);
            data.len()
        };
        self.mix_hash(data);
        Ok(payload_len)
    }

    pub fn split(&mut self, child1: &mut CipherState, child2: &mut CipherState) {
        // These buffers hold both transport keys, which is the material the resulting
        // `TransportState` exists to protect, so don't leave copies behind on the stack.
        let mut hkdf_output = Zeroizing::new(([0_u8; MAXHASHLEN], [0_u8; MAXHASHLEN]));
        {
            let out = &mut *hkdf_output;
            self.split_raw(&mut out.0, &mut out.1);
        }

        // TODO(mcginty): use `split_array_ref` once stable to avoid memory inefficiency
        let mut cipher_keys = Zeroizing::new(([0_u8; CIPHERKEYLEN], [0_u8; CIPHERKEYLEN]));
        cipher_keys.0.copy_from_slice(&hkdf_output.0[..CIPHERKEYLEN]);
        cipher_keys.1.copy_from_slice(&hkdf_output.1[..CIPHERKEYLEN]);
        child1.set(&cipher_keys.0, 0);
        child2.set(&cipher_keys.1, 0);
    }

    pub fn split_raw(&mut self, out1: &mut [u8], out2: &mut [u8]) {
        let hash_len = self.hasher.hash_len();
        self.hasher.hkdf(&self.inner.ck[..hash_len], &[0_u8; 0], 2, out1, out2, &mut []);
    }

    /// Snapshot the hash and chaining key so a partially-processed message can be rolled back.
    ///
    /// The snapshot contains the chaining key, so it's handed back in a `Zeroizing` wrapper to
    /// be wiped when the caller drops it instead of being left behind on the stack. This is
    /// taken on every message, so it's the most frequently created copy of the chaining key.
    pub(crate) fn checkpoint(&mut self) -> Zeroizing<SymmetricStateData> {
        Zeroizing::new(self.inner)
    }

    /// Roll back to a snapshot taken by [`Self::checkpoint`].
    ///
    /// Takes the snapshot by reference so restoring doesn't produce another unwiped copy;
    /// the state being overwritten is wiped by `SymmetricState`'s own `Drop`.
    pub(crate) fn restore(&mut self, checkpoint: &SymmetricStateData) {
        self.inner = *checkpoint;
    }

    pub fn handshake_hash(&self) -> &[u8] {
        let hash_len = self.hasher.hash_len();
        &self.inner.h[..hash_len]
    }
}

impl Drop for SymmetricState {
    fn drop(&mut self) {
        // The chaining key is secret key material; the hash isn't, but wiping it is cheap.
        self.inner.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Unlike the leaf primitives in `resolvers::default`, `SymmetricState` can't be guarded
    // with `needs_drop` — it owns a `Box<dyn Hash>` and a `CipherState`, so `needs_drop` is
    // true whether or not the manual `Drop` below exists, which makes the assertion vacuous.
    // What's left to guard is the field coverage of the wipe itself.

    /// Guard the field list of `SymmetricStateData`: if a new secret field is added without
    /// being wiped here, or `ck`/`h` are renamed, this fails rather than silently leaking.
    #[test]
    fn test_symmetricstatedata_zeroize_clears_all_fields() {
        let mut data =
            SymmetricStateData { h: [0x24; MAXHASHLEN], ck: [0x42; MAXHASHLEN], has_key: true };
        data.zeroize();
        assert_eq!(data.ck, [0_u8; MAXHASHLEN]);
        assert_eq!(data.h, [0_u8; MAXHASHLEN]);
        assert!(!data.has_key);
    }
}
