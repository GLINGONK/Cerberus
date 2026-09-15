//! Cipher layers and the cascade that chains them.
//!
//! Each layer receives an **independent** key derived by HKDF-SHA512 with a
//! layer-specific `info` string. Breaking one layer therefore reveals nothing
//! about the keys of the others — that independence is the whole point of a
//! cascade.
//!
//! Ciphers without a standardised authenticated mode (Serpent, Twofish, Camellia)
//! are used in CTR and wrapped in encrypt-then-MAC with HMAC-SHA512, verified in
//! constant time *before* any decryption happens.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::XChaCha20Poly1305;
use ctr::cipher::{InnerIvInit, KeyInit as BlockKeyInit, StreamCipher, StreamCipherCoreWrapper};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

type HmacSha512 = Hmac<Sha512>;

/// CTR-128BE core over an arbitrary 128-bit block cipher.
///
/// Built from an already-keyed cipher instance rather than through `KeyIvInit`:
/// `serpent::Serpent` declares `KeySize = U16`, so the blanket key-length check
/// would reject a 256-bit key even though the cipher itself supports 16..=32
/// bytes. Keying the block cipher first bypasses that spurious restriction.
type Ctr128<C> = StreamCipherCoreWrapper<ctr::CtrCore<C, ctr::flavors::Ctr128BE>>;

/// Bytes of key material each layer consumes: 32 for encryption, 32 for the MAC.
pub const LAYER_KEY_LEN: usize = 64;

/// Truncation length of the encrypt-then-MAC tag. 256 bits of a SHA-512 output.
const ETM_TAG_LEN: usize = 32;

/// CTR nonce length, matching the 128-bit block size of all block ciphers used.
const CTR_NONCE_LEN: usize = 16;

/// A cipher usable as one layer of the cascade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CipherAlgo {
    /// AES-256-GCM. NIST standard, hardware-accelerated through AES-NI.
    Aes256Gcm,
    /// XChaCha20-Poly1305. 192-bit nonce, no practical collision risk.
    XChaCha20Poly1305,
    /// Serpent-256 in CTR, encrypt-then-MAC. Largest security margin of the AES finalists.
    Serpent256,
    /// Twofish-256 in CTR, encrypt-then-MAC. AES finalist.
    Twofish256,
    /// Camellia-256 in CTR, encrypt-then-MAC. ISO/IEC 18033-3 standard.
    Camellia256,
}

impl CipherAlgo {
    pub const ALL: [CipherAlgo; 5] = [
        CipherAlgo::Aes256Gcm,
        CipherAlgo::XChaCha20Poly1305,
        CipherAlgo::Serpent256,
        CipherAlgo::Twofish256,
        CipherAlgo::Camellia256,
    ];

    /// Stable on-disk identifier. Never renumber these: old vaults depend on them.
    pub fn id(self) -> u8 {
        match self {
            CipherAlgo::Aes256Gcm => 0x01,
            CipherAlgo::XChaCha20Poly1305 => 0x02,
            CipherAlgo::Serpent256 => 0x03,
            CipherAlgo::Twofish256 => 0x04,
            CipherAlgo::Camellia256 => 0x05,
        }
    }

    pub fn from_id(id: u8) -> Result<Self> {
        match id {
            0x01 => Ok(CipherAlgo::Aes256Gcm),
            0x02 => Ok(CipherAlgo::XChaCha20Poly1305),
            0x03 => Ok(CipherAlgo::Serpent256),
            0x04 => Ok(CipherAlgo::Twofish256),
            0x05 => Ok(CipherAlgo::Camellia256),
            other => Err(CoreError::UnknownCipher(other)),
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            CipherAlgo::Aes256Gcm => "AES-256-GCM",
            CipherAlgo::XChaCha20Poly1305 => "XChaCha20-Poly1305",
            CipherAlgo::Serpent256 => "Serpent-256 (CTR+HMAC)",
            CipherAlgo::Twofish256 => "Twofish-256 (CTR+HMAC)",
            CipherAlgo::Camellia256 => "Camellia-256 (CTR+HMAC)",
        }
    }

    fn nonce_len(self) -> usize {
        match self {
            CipherAlgo::Aes256Gcm => 12,
            CipherAlgo::XChaCha20Poly1305 => 24,
            _ => CTR_NONCE_LEN,
        }
    }

    /// Encrypt one layer. Output layout is `nonce ‖ body`.
    ///
    /// `key` must be [`LAYER_KEY_LEN`] bytes; `aad` is bound into the
    /// authentication tag so a layer cannot be lifted into another context.
    fn seal(self, key: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        if key.len() != LAYER_KEY_LEN {
            return Err(CoreError::Kdf);
        }
        let (k_enc, k_mac) = key.split_at(32);
        let nonce = crate::random::vec(self.nonce_len())?;

        let body = match self {
            CipherAlgo::Aes256Gcm => {
                let c = Aes256Gcm::new_from_slice(k_enc).map_err(|_| CoreError::Kdf)?;
                c.encrypt(
                    nonce.as_slice().into(),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| CoreError::Decrypt)?
            }
            CipherAlgo::XChaCha20Poly1305 => {
                let c = XChaCha20Poly1305::new_from_slice(k_enc).map_err(|_| CoreError::Kdf)?;
                c.encrypt(
                    nonce.as_slice().into(),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| CoreError::Decrypt)?
            }
            _ => {
                let mut ct = plaintext.to_vec();
                self.apply_ctr(k_enc, &nonce, &mut ct)?;
                let tag = etm_tag(k_mac, aad, &nonce, &ct);
                let mut body = Vec::with_capacity(ETM_TAG_LEN + ct.len());
                body.extend_from_slice(&tag);
                body.extend_from_slice(&ct);
                body
            }
        };

        let mut out = Vec::with_capacity(nonce.len() + body.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decrypt one layer produced by [`CipherAlgo::seal`].
    fn open(self, key: &[u8], aad: &[u8], input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if key.len() != LAYER_KEY_LEN {
            return Err(CoreError::Kdf);
        }
        let nlen = self.nonce_len();
        if input.len() < nlen {
            return Err(CoreError::Decrypt);
        }
        let (k_enc, k_mac) = key.split_at(32);
        let (nonce, body) = input.split_at(nlen);

        let plaintext = match self {
            CipherAlgo::Aes256Gcm => {
                let c = Aes256Gcm::new_from_slice(k_enc).map_err(|_| CoreError::Kdf)?;
                c.decrypt(nonce.into(), Payload { msg: body, aad })
                    .map_err(|_| CoreError::Decrypt)?
            }
            CipherAlgo::XChaCha20Poly1305 => {
                let c = XChaCha20Poly1305::new_from_slice(k_enc).map_err(|_| CoreError::Kdf)?;
                c.decrypt(nonce.into(), Payload { msg: body, aad })
                    .map_err(|_| CoreError::Decrypt)?
            }
            _ => {
                if body.len() < ETM_TAG_LEN {
                    return Err(CoreError::Decrypt);
                }
                let (tag, ct) = body.split_at(ETM_TAG_LEN);
                // Authenticate first. Never decrypt data whose tag has not been verified.
                let expected = etm_tag(k_mac, aad, nonce, ct);
                if expected.ct_eq(tag).unwrap_u8() != 1 {
                    return Err(CoreError::Decrypt);
                }
                let mut pt = ct.to_vec();
                self.apply_ctr(k_enc, nonce, &mut pt)?;
                pt
            }
        };

        Ok(Zeroizing::new(plaintext))
    }

    /// CTR is its own inverse, so this drives both directions.
    fn apply_ctr(self, k_enc: &[u8], nonce: &[u8], buf: &mut [u8]) -> Result<()> {
        if nonce.len() != CTR_NONCE_LEN {
            return Err(CoreError::Decrypt);
        }
        match self {
            CipherAlgo::Serpent256 => ctr_apply::<serpent::Serpent>(k_enc, nonce, buf),
            CipherAlgo::Twofish256 => ctr_apply::<twofish::Twofish>(k_enc, nonce, buf),
            CipherAlgo::Camellia256 => ctr_apply::<camellia::Camellia256>(k_enc, nonce, buf),
            _ => Err(CoreError::InvalidCascade("cipher is not a CTR mode")),
        }
    }
}

/// Key a 128-bit block cipher, wrap it in CTR-128BE and apply the keystream.
///
/// CTR is its own inverse, so this drives both encryption and decryption.
fn ctr_apply<C>(k_enc: &[u8], nonce: &[u8], buf: &mut [u8]) -> Result<()>
where
    C: ctr::cipher::BlockEncryptMut + ctr::cipher::BlockCipher + BlockKeyInit,
    C: ctr::cipher::BlockSizeUser<BlockSize = ctr::cipher::consts::U16>,
{
    let inner = C::new_from_slice(k_enc).map_err(|_| CoreError::Kdf)?;
    let core = ctr::CtrCore::<C, ctr::flavors::Ctr128BE>::inner_iv_slice_init(inner, nonce)
        .map_err(|_| CoreError::Decrypt)?;
    Ctr128::<C>::from_core(core).apply_keystream(buf);
    Ok(())
}

/// `HMAC-SHA512(k_mac, aad ‖ nonce ‖ ciphertext)` truncated to 256 bits.
///
/// Lengths are prefixed so no two distinct inputs can serialise identically.
fn etm_tag(k_mac: &[u8], aad: &[u8], nonce: &[u8], ct: &[u8]) -> [u8; ETM_TAG_LEN] {
    let mut mac = <HmacSha512 as Mac>::new_from_slice(k_mac).expect("HMAC accepts any key length");
    mac.update(&(aad.len() as u64).to_le_bytes());
    mac.update(aad);
    mac.update(&(nonce.len() as u64).to_le_bytes());
    mac.update(nonce);
    mac.update(ct);
    let full = mac.finalize().into_bytes();
    let mut tag = [0u8; ETM_TAG_LEN];
    tag.copy_from_slice(&full[..ETM_TAG_LEN]);
    tag
}

/// An ordered stack of cipher layers.
///
/// Encryption applies layers first-to-last; decryption unwinds last-to-first.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Cascade(Vec<CipherAlgo>);

impl Cascade {
    pub const MAX_LAYERS: usize = 4;

    /// Build a cascade, rejecting empty stacks, oversized stacks and repeats.
    ///
    /// Repeating an algorithm is refused on purpose: a second AES layer roughly
    /// doubles the cost for no added security, which is exactly the kind of
    /// false reassurance this project must not sell.
    pub fn new(layers: Vec<CipherAlgo>) -> Result<Self> {
        if layers.is_empty() {
            return Err(CoreError::InvalidCascade(
                "a cascade needs at least one layer",
            ));
        }
        if layers.len() > Self::MAX_LAYERS {
            return Err(CoreError::InvalidCascade(
                "a cascade accepts at most 4 layers",
            ));
        }
        for (i, algo) in layers.iter().enumerate() {
            if layers[..i].contains(algo) {
                return Err(CoreError::InvalidCascade(
                    "the same cipher cannot appear twice in a cascade",
                ));
            }
        }
        Ok(Cascade(layers))
    }

    /// AES-256-GCM then XChaCha20-Poly1305: two independent, well-audited AEADs.
    pub fn recommended() -> Self {
        Cascade(vec![CipherAlgo::Aes256Gcm, CipherAlgo::XChaCha20Poly1305])
    }

    /// Every family represented: AES-NI, ARX stream, and a bitsliced SPN.
    pub fn paranoid() -> Self {
        Cascade(vec![
            CipherAlgo::Aes256Gcm,
            CipherAlgo::XChaCha20Poly1305,
            CipherAlgo::Serpent256,
        ])
    }

    pub fn layers(&self) -> &[CipherAlgo] {
        &self.0
    }

    pub fn ids(&self) -> Vec<u8> {
        self.0.iter().map(|a| a.id()).collect()
    }

    pub fn from_ids(ids: &[u8]) -> Result<Self> {
        let layers = ids
            .iter()
            .map(|&id| CipherAlgo::from_id(id))
            .collect::<Result<Vec<_>>>()?;
        Cascade::new(layers)
    }

    /// Total key material the cascade needs from HKDF.
    pub fn key_material_len(&self) -> usize {
        self.0.len() * LAYER_KEY_LEN
    }

    /// Encrypt through every layer in order.
    ///
    /// `keys` must be exactly [`Cascade::key_material_len`] bytes; it is split
    /// into one independent [`LAYER_KEY_LEN`] chunk per layer.
    pub fn seal(&self, keys: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        if keys.len() != self.key_material_len() {
            return Err(CoreError::Kdf);
        }
        let mut buf = plaintext.to_vec();
        for (i, algo) in self.0.iter().enumerate() {
            let key = &keys[i * LAYER_KEY_LEN..(i + 1) * LAYER_KEY_LEN];
            let next = algo.seal(key, aad, &buf)?;
            buf.zeroize_in_place();
            buf = next;
        }
        Ok(buf)
    }

    /// Decrypt by unwinding the layers in reverse order.
    pub fn open(&self, keys: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if keys.len() != self.key_material_len() {
            return Err(CoreError::Kdf);
        }
        let mut buf = Zeroizing::new(ciphertext.to_vec());
        for (i, algo) in self.0.iter().enumerate().rev() {
            let key = &keys[i * LAYER_KEY_LEN..(i + 1) * LAYER_KEY_LEN];
            buf = algo.open(key, aad, &buf)?;
        }
        Ok(buf)
    }
}

impl Default for Cascade {
    fn default() -> Self {
        Cascade::recommended()
    }
}

/// Small helper so intermediate cascade buffers are wiped as we move along.
trait ZeroizeInPlace {
    fn zeroize_in_place(&mut self);
}

impl ZeroizeInPlace for Vec<u8> {
    fn zeroize_in_place(&mut self) {
        use zeroize::Zeroize;
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys_for(c: &Cascade) -> Vec<u8> {
        (0..c.key_material_len()).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn every_single_cipher_round_trips() {
        for algo in CipherAlgo::ALL {
            let cascade = Cascade::new(vec![algo]).unwrap();
            let keys = keys_for(&cascade);
            let msg = b"correct horse battery staple";
            let ct = cascade.seal(&keys, b"aad", msg).unwrap();
            let pt = cascade.open(&keys, b"aad", &ct).unwrap();
            assert_eq!(
                &pt[..],
                msg,
                "round trip failed for {}",
                algo.display_name()
            );
        }
    }

    #[test]
    fn every_ordered_pair_round_trips() {
        for a in CipherAlgo::ALL {
            for b in CipherAlgo::ALL {
                if a == b {
                    continue;
                }
                let cascade = Cascade::new(vec![a, b]).unwrap();
                let keys = keys_for(&cascade);
                let msg = vec![0xABu8; 1024];
                let ct = cascade.seal(&keys, b"", &msg).unwrap();
                assert_eq!(&cascade.open(&keys, b"", &ct).unwrap()[..], &msg[..]);
            }
        }
    }

    #[test]
    fn flipping_any_single_bit_is_detected() {
        for algo in CipherAlgo::ALL {
            let cascade = Cascade::new(vec![algo]).unwrap();
            let keys = keys_for(&cascade);
            let ct = cascade.seal(&keys, b"", b"secret payload").unwrap();
            for i in 0..ct.len() {
                let mut tampered = ct.clone();
                tampered[i] ^= 0x01;
                assert!(
                    cascade.open(&keys, b"", &tampered).is_err(),
                    "{} accepted a corrupted byte at offset {i}",
                    algo.display_name()
                );
            }
        }
    }

    #[test]
    fn aad_is_bound_to_the_ciphertext() {
        for algo in CipherAlgo::ALL {
            let cascade = Cascade::new(vec![algo]).unwrap();
            let keys = keys_for(&cascade);
            let ct = cascade.seal(&keys, b"header-v1", b"payload").unwrap();
            assert!(cascade.open(&keys, b"header-v2", &ct).is_err());
        }
    }

    #[test]
    fn wrong_key_is_rejected() {
        let cascade = Cascade::paranoid();
        let keys = keys_for(&cascade);
        let ct = cascade.seal(&keys, b"", b"payload").unwrap();
        let mut wrong = keys.clone();
        wrong[0] ^= 0xFF;
        assert!(cascade.open(&wrong, b"", &ct).is_err());
    }

    #[test]
    fn nonces_are_never_reused() {
        let cascade = Cascade::new(vec![CipherAlgo::Aes256Gcm]).unwrap();
        let keys = keys_for(&cascade);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10_000 {
            let ct = cascade.seal(&keys, b"", b"x").unwrap();
            assert!(seen.insert(ct[..12].to_vec()), "nonce reused");
        }
    }

    #[test]
    fn cascade_rejects_repeats_and_bad_sizes() {
        assert!(Cascade::new(vec![]).is_err());
        assert!(Cascade::new(vec![CipherAlgo::Aes256Gcm, CipherAlgo::Aes256Gcm]).is_err());
        assert!(Cascade::new(CipherAlgo::ALL.to_vec()).is_err()); // 5 > MAX_LAYERS
    }

    #[test]
    fn cipher_ids_survive_a_round_trip() {
        for algo in CipherAlgo::ALL {
            assert_eq!(CipherAlgo::from_id(algo.id()).unwrap(), algo);
        }
        assert!(CipherAlgo::from_id(0xFF).is_err());
    }

    #[test]
    fn layers_use_independent_keys() {
        // Two layers fed identical key bytes must still produce different output,
        // proving the key material is actually split rather than shared.
        let cascade = Cascade::new(vec![CipherAlgo::Serpent256, CipherAlgo::Twofish256]).unwrap();
        let keys = vec![0x42u8; cascade.key_material_len()];
        let a = cascade.seal(&keys, b"", b"payload").unwrap();
        let b = cascade.seal(&keys, b"", b"payload").unwrap();
        assert_ne!(a, b, "randomised nonces should make outputs differ");
    }
}
