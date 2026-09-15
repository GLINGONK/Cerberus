//! The `.cbv` on-disk container.
//!
//! ```text
//! v2 layout
//! ┌ CLEAR HEADER   magic, version, KDF params, salt, HKDF context ┐
//! ├ META BLOCK     AES-256-GCM: factor flags + cascade            ┤
//! ├ PAYLOAD        cascade-encrypted vault                        ┤
//! └ HMAC-SHA512    over clear header ‖ meta ‖ payload             ┘
//! ```
//!
//! Only the fields Argon2id needs *before* any key exists stay in the clear:
//! the version, the KDF cost, and the salt. Everything an attacker could use to
//! target the vault — which factors it needs, which ciphers protect it — lives
//! in the encrypted metadata block, decrypted with a key derived from the
//! master. The clear header is authenticated (as AAD on the block and by the
//! trailing MAC), so its parameters cannot be weakened without detection.
//!
//! v1 files (cascade and factor flags in the clear) are still read, so existing
//! vaults keep opening; every new write produces v2.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::cipher::{Cascade, CipherAlgo};
use crate::error::{CoreError, Result};
use crate::factors::FactorSet;
use crate::kdf::{KdfParams, MasterKey, SALT_LEN};
use crate::vault::Vault;

type HmacSha512 = Hmac<Sha512>;

const MAGIC: &[u8; 8] = b"CERBERUS";
/// Version written by this build.
const VERSION: u16 = 2;
/// The original format, still read for backward compatibility.
const VERSION_V1: u16 = 1;
const FILE_MAC_LEN: usize = 64;
const HKDF_CONTEXT_LEN: usize = 16;
/// Nonce length for the AES-256-GCM metadata block.
const META_NONCE_LEN: usize = 12;
/// A metadata block larger than this is treated as corrupt.
const MAX_META_LEN: usize = 256;

/// Payload is padded to a multiple of this, so the file size does not betray
/// how many entries the vault holds.
const PADDING_BLOCK: usize = 4096;

/// A header refusing to describe a payload larger than this is treated as
/// corrupt, so a hostile file cannot make us allocate unbounded memory.
const MAX_PAYLOAD: usize = 512 * 1024 * 1024;

/// How many timestamped `.bak` snapshots to keep beside a vault. Older ones are
/// pruned on each save, so backups cannot grow without bound and a deleted
/// entry does not linger on disk in dozens of stale copies.
const MAX_BACKUPS: usize = 5;

/// The cleartext, authenticated header of a `.cbv` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub version: u16,
    pub kdf: KdfParams,
    pub salt: [u8; SALT_LEN],
    /// Bitfield of the factor kinds this vault requires.
    pub factor_flags: u8,
    pub cascade: Cascade,
    /// Per-vault HKDF context, so two vaults with the same password still derive
    /// unrelated layer keys.
    pub hkdf_context: [u8; HKDF_CONTEXT_LEN],
}

impl Header {
    /// Whether the factor flags and cascade in this header are meaningful.
    ///
    /// True after a full unlock, and when peeking a v1 file. False when peeking
    /// a v2 file, whose factors and cascade are encrypted — the caller must not
    /// present the placeholder values as real.
    pub fn factors_known(&self) -> bool {
        self.version == VERSION_V1 || self.factor_flags != 0
    }
}

/// The layout of a parsed file, enough to locate every section.
struct Layout {
    header: Header,
    /// End of the cleartext header (v2) — also the start of the metadata block.
    clear_len: usize,
    /// Byte range of the encrypted metadata block. Empty for v1.
    meta: std::ops::Range<usize>,
    /// Byte range of the cascade-encrypted payload.
    payload: std::ops::Range<usize>,
}

impl Header {
    fn new(kdf: KdfParams, factor_flags: u8, cascade: Cascade) -> Result<Self> {
        Ok(Header {
            version: VERSION,
            kdf,
            salt: crate::random::bytes::<SALT_LEN>()?,
            factor_flags,
            cascade,
            hkdf_context: crate::random::bytes::<HKDF_CONTEXT_LEN>()?,
        })
    }

    /// The cleartext, authenticated prefix of a v2 file.
    ///
    /// Deliberately holds no factor or cipher information — only what Argon2id
    /// needs before a key can exist. Used both on disk and as the AAD that binds
    /// the metadata block and the payload to these exact KDF parameters.
    fn clear_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(67);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&self.kdf.memory_kib.to_le_bytes());
        out.extend_from_slice(&self.kdf.time_cost.to_le_bytes());
        out.push(self.kdf.parallelism);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.hkdf_context);
        out
    }

    /// The secret metadata, serialised for encryption: factor flags + cascade.
    ///
    /// Padded to a fixed length (`2 + MAX_LAYERS`) so the *ciphertext* length is
    /// constant no matter how many cascade layers the vault uses. An independent
    /// audit noted that the old variable length leaked the layer count through
    /// `meta_len = 30 + layers` — visible without any key. The trailing padding
    /// bytes are ignored on decrypt (only the first `n` ids are read).
    fn metadata_plaintext(&self) -> Zeroizing<Vec<u8>> {
        let ids = self.cascade.ids();
        let mut out = vec![0u8; 2 + Cascade::MAX_LAYERS];
        out[0] = self.factor_flags;
        out[1] = ids.len() as u8;
        out[2..2 + ids.len()].copy_from_slice(&ids);
        Zeroizing::new(out)
    }

    /// v1 cleartext header, kept only so old vaults can be re-read (and to build
    /// v1 fixtures in the tests).
    #[cfg_attr(not(test), allow(dead_code))]
    fn v1_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(80);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION_V1.to_le_bytes());
        out.extend_from_slice(&self.kdf.memory_kib.to_le_bytes());
        out.extend_from_slice(&self.kdf.time_cost.to_le_bytes());
        out.push(self.kdf.parallelism);
        out.extend_from_slice(&self.salt);
        out.push(self.factor_flags);
        let ids = self.cascade.ids();
        out.push(ids.len() as u8);
        out.extend_from_slice(&ids);
        out.extend_from_slice(&self.hkdf_context);
        out
    }

    /// Parse the parts of a file that need no key.
    ///
    /// This is the vault's entire attack surface for untrusted input, so every
    /// field is bounds-checked and every length validated before use. For v2 the
    /// factor flags and cascade are not known yet — they live in the encrypted
    /// metadata block and are filled in after decryption.
    fn parse(file: &[u8]) -> Result<Layout> {
        let mut cur = Cursor::new(file);

        if cur.take(8)? != MAGIC {
            return Err(CoreError::BadMagic);
        }
        let version = u16::from_le_bytes(cur.array::<2>()?);
        match version {
            VERSION => Self::parse_v2(file, cur),
            VERSION_V1 => Self::parse_v1(cur),
            other => Err(CoreError::UnsupportedVersion(other)),
        }
    }

    fn parse_v2(file: &[u8], mut cur: Cursor) -> Result<Layout> {
        let kdf = KdfParams {
            memory_kib: u32::from_le_bytes(cur.array::<4>()?),
            time_cost: u32::from_le_bytes(cur.array::<4>()?),
            parallelism: cur.byte()?,
        };
        // Validate before the parameters ever reach Argon2: a tampered header
        // could otherwise request a hostile allocation or a trivial cost.
        kdf.validate()?;

        let salt = cur.array::<SALT_LEN>()?;
        let hkdf_context = cur.array::<HKDF_CONTEXT_LEN>()?;
        let clear_len = cur.pos;

        let meta_len = u16::from_le_bytes(cur.array::<2>()?) as usize;
        if !(META_NONCE_LEN + 16..=MAX_META_LEN).contains(&meta_len) {
            return Err(CoreError::MalformedHeader);
        }
        let meta_start = cur.pos;
        // Advance past the metadata block, checking it fits.
        cur.take(meta_len)?;
        let meta_end = cur.pos;

        if file.len() < meta_end + FILE_MAC_LEN {
            return Err(CoreError::MalformedHeader);
        }
        let payload = meta_end..file.len() - FILE_MAC_LEN;
        if payload.len() > MAX_PAYLOAD {
            return Err(CoreError::MalformedHeader);
        }

        Ok(Layout {
            header: Header {
                version: VERSION,
                kdf,
                salt,
                // Filled in once the metadata block is decrypted.
                factor_flags: 0,
                cascade: Cascade::recommended(),
                hkdf_context,
            },
            clear_len,
            meta: meta_start..meta_end,
            payload,
        })
    }

    fn parse_v1(mut cur: Cursor) -> Result<Layout> {
        let kdf = KdfParams {
            memory_kib: u32::from_le_bytes(cur.array::<4>()?),
            time_cost: u32::from_le_bytes(cur.array::<4>()?),
            parallelism: cur.byte()?,
        };
        kdf.validate()?;

        let salt = cur.array::<SALT_LEN>()?;
        let factor_flags = cur.byte()?;
        let n_layers = cur.byte()? as usize;
        if n_layers == 0 || n_layers > Cascade::MAX_LAYERS {
            return Err(CoreError::MalformedHeader);
        }
        let cascade = Cascade::from_ids(cur.take(n_layers)?)?;
        let hkdf_context = cur.array::<HKDF_CONTEXT_LEN>()?;
        let header_len = cur.pos;

        Ok(Layout {
            header: Header {
                version: VERSION_V1,
                kdf,
                salt,
                factor_flags,
                cascade,
                hkdf_context,
            },
            clear_len: header_len,
            meta: header_len..header_len,
            payload: header_len..0, // filled by the caller against the real length
        })
    }
}

/// AES-256-GCM key for the metadata block, distinct from every other derived key.
fn metadata_key(key: &MasterKey, hkdf_context: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut info = b"cerberus/v1/metadata/".to_vec();
    info.extend_from_slice(hkdf_context);
    key.expand(&info, 32)
}

/// Encrypt the metadata block: `nonce ‖ AES-256-GCM(flags ‖ cascade)`.
fn seal_metadata(key: &MasterKey, header: &Header, aad: &[u8]) -> Result<Vec<u8>> {
    let mk = metadata_key(key, &header.hkdf_context)?;
    let cipher = Aes256Gcm::new_from_slice(&mk).map_err(|_| CoreError::Kdf)?;
    let nonce = crate::random::vec(META_NONCE_LEN)?;
    let plaintext = header.metadata_plaintext();
    let ct = cipher
        .encrypt(
            nonce.as_slice().into(),
            Payload {
                msg: &plaintext,
                aad,
            },
        )
        .map_err(|_| CoreError::Decrypt)?;
    let mut out = Vec::with_capacity(nonce.len() + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt the metadata block, returning the factor flags and cascade.
///
/// A GCM tag failure here is exactly the "wrong factors" signal, collapsed into
/// [`CoreError::Decrypt`] like every other cryptographic failure.
fn open_metadata(
    key: &MasterKey,
    hkdf_context: &[u8],
    block: &[u8],
    aad: &[u8],
) -> Result<(u8, Cascade)> {
    let mk = metadata_key(key, hkdf_context)?;
    let cipher = Aes256Gcm::new_from_slice(&mk).map_err(|_| CoreError::Kdf)?;
    let (nonce, ct) = block.split_at(META_NONCE_LEN);
    let plain = Zeroizing::new(
        cipher
            .decrypt(nonce.into(), Payload { msg: ct, aad })
            .map_err(|_| CoreError::Decrypt)?,
    );

    if plain.len() < 2 {
        return Err(CoreError::Decrypt);
    }
    let flags = plain[0];
    let n = plain[1] as usize;
    if n == 0 || n > Cascade::MAX_LAYERS {
        return Err(CoreError::Decrypt);
    }
    // Two accepted layouts, so vaults written before the padding fix still
    // open:
    //   - new, fixed-length: `2 + MAX_LAYERS` bytes, trailing bytes are zero
    //     padding that hides the layer count from the ciphertext length;
    //   - legacy, variable:  exactly `2 + n` bytes.
    let padded = plain.len() == 2 + Cascade::MAX_LAYERS;
    let legacy = plain.len() == 2 + n;
    if !padded && !legacy {
        return Err(CoreError::Decrypt);
    }
    let cascade = Cascade::from_ids(&plain[2..2 + n]).map_err(|_| CoreError::Decrypt)?;
    Ok((flags, cascade))
}

/// Bounds-checked reader. Every read either yields the requested bytes or fails;
/// there is no path where a short buffer produces a partially-initialised value.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(CoreError::MalformedHeader)?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or(CoreError::MalformedHeader)?;
        self.pos = end;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
}

/// Serialise and encrypt a vault into a complete `.cbv` byte stream.
///
/// Runs the full Argon2id derivation. Use [`seal_with_key`] for repeat saves
/// during a session — re-deriving on every write costs seconds for no benefit.
pub fn seal(
    vault: &Vault,
    factors: &FactorSet,
    cascade: Cascade,
    kdf: KdfParams,
) -> Result<Vec<u8>> {
    enforce_pattern_kdf(factors, kdf)?;
    let header = Header::new(kdf, factors.flags(), cascade)?;
    let composite = factors.composite()?;
    let key = MasterKey::derive(&composite, &header.salt, header.kdf)?;
    seal_with_key(vault, &key, &header)
}

/// Encrypt a vault under an already-derived master key.
///
/// The header — and therefore the salt — is reused as-is. That is correct: the
/// salt exists to make the *password-to-key* derivation unique per vault, not
/// per write. What must be fresh on every write are the nonces, and those are
/// generated inside the cascade. Re-salting on each save would force a fresh
/// Argon2 pass and freeze the UI for seconds at the higher cost profiles.
///
/// Call [`seal`] instead whenever the factors change, so a new salt is drawn.
pub fn seal_with_key(vault: &Vault, key: &MasterKey, header: &Header) -> Result<Vec<u8>> {
    let mut plaintext = Zeroizing::new(serde_json::to_vec(vault)?);
    pad(&mut plaintext)?;

    // The clear header is the associated data for both the metadata block and
    // every cascade layer: nothing can be lifted onto a different set of KDF
    // parameters without the tags failing.
    let clear = header.clear_bytes();
    let meta = seal_metadata(key, header, &clear)?;

    // Bind the payload to everything that precedes it — clear header, metadata
    // length and metadata block — so the ciphertext cannot be paired with a
    // forged header or metadata block. This must match `file[..meta.end]` on the
    // decrypt side exactly, including the 2-byte length field.
    let mut payload_aad = clear.clone();
    payload_aad.extend_from_slice(&(meta.len() as u16).to_le_bytes());
    payload_aad.extend_from_slice(&meta);
    let layer_keys = key.cascade_keys(&header.cascade, &header.hkdf_context)?;
    let payload = header.cascade.seal(&layer_keys, &payload_aad, &plaintext)?;

    let mut file = Vec::with_capacity(clear.len() + 2 + meta.len() + payload.len() + FILE_MAC_LEN);
    file.extend_from_slice(&clear);
    file.extend_from_slice(&(meta.len() as u16).to_le_bytes());
    file.extend_from_slice(&meta);
    file.extend_from_slice(&payload);

    let mac_key = key.file_mac_key(&header.hkdf_context)?;
    let mut mac = <HmacSha512 as Mac>::new_from_slice(&mac_key).map_err(|_| CoreError::Kdf)?;
    mac.update(&file);
    file.extend_from_slice(&mac.finalize().into_bytes());

    Ok(file)
}

/// Decrypt and deserialise a `.cbv` byte stream.
///
/// Every cryptographic failure — wrong password, wrong key file, tampered
/// bytes — surfaces as [`CoreError::Decrypt`], so probing the unlock path
/// reveals nothing about which factor was wrong.
pub fn open(file: &[u8], factors: &FactorSet) -> Result<(Vault, Header)> {
    open_keyed(file, factors).map(|o| (o.vault, o.header))
}

/// A successfully opened vault, along with the material needed to save it again
/// without paying for another Argon2 derivation.
pub struct Opened {
    pub vault: Vault,
    pub header: Header,
    pub key: MasterKey,
}

/// Like [`open`], but also hands back the derived master key.
///
/// Keeping the key for the duration of the session is what makes saving fast.
/// It lives in a [`MasterKey`], which zeroizes on drop, and never leaves the
/// native layer.
pub fn open_keyed(file: &[u8], factors: &FactorSet) -> Result<Opened> {
    let layout = resolve_layout(file)?;
    let composite = factors.composite()?;
    let key = MasterKey::derive(&composite, &layout.header.salt, layout.header.kdf)?;
    let (vault, header) = decrypt_layout(file, layout, &key)?;
    Ok(Opened { vault, header, key })
}

/// Seal a vault under an ephemeral random key, for keeping it out of resident
/// plaintext while it is unlocked in memory.
///
/// Not for disk: the header's KDF parameters and salt are placeholders (the key
/// is random, never derived), and a single AES-256-GCM layer is used because
/// this runs on every in-memory mutation and needs to be cheap. The point is to
/// shorten how long decrypted secrets sit in continuously-resident memory, not
/// to resist an attacker who can already read the whole process — that attacker
/// also holds the ephemeral key.
pub fn seal_ephemeral(vault: &Vault, key: &MasterKey) -> Result<Vec<u8>> {
    let header = Header {
        version: VERSION,
        kdf: KdfParams::INTERACTIVE, // never used to derive; only has to be valid
        salt: crate::random::bytes::<SALT_LEN>()?,
        factor_flags: 0,
        cascade: Cascade::new(vec![CipherAlgo::Aes256Gcm]).expect("single layer is valid"),
        hkdf_context: crate::random::bytes::<HKDF_CONTEXT_LEN>()?,
    };
    seal_with_key(vault, key, &header)
}

/// Reverse of [`seal_ephemeral`].
pub fn open_ephemeral(bytes: &[u8], key: &MasterKey) -> Result<Vault> {
    open_with_key(bytes, key).map(|(v, _)| v)
}

/// Decrypt a vault whose master key is already known. No KDF work.
pub fn open_with_key(file: &[u8], key: &MasterKey) -> Result<(Vault, Header)> {
    let layout = resolve_layout(file)?;
    decrypt_layout(file, layout, key)
}

/// Fuzzing entry point: run the entire untrusted-input parser and nothing else.
///
/// This is the whole attack surface a hostile `.cbv` can reach before any key
/// exists — header fields, lengths, bounds. It deliberately skips the KDF so a
/// fuzzer explores parser states at full speed instead of stalling on Argon2.
/// Never panics on any input; that is exactly what the fuzzer checks.
#[doc(hidden)]
pub fn fuzz_parse(file: &[u8]) {
    let _ = resolve_layout(file);
    let _ = peek_bytes(file);
}

/// Parse a file and pin down every section, patching the v1 payload range whose
/// end depends on the real file length.
fn resolve_layout(file: &[u8]) -> Result<Layout> {
    let mut layout = Header::parse(file)?;
    if layout.header.version == VERSION_V1 {
        if file.len() < layout.clear_len + FILE_MAC_LEN {
            return Err(CoreError::MalformedHeader);
        }
        layout.payload = layout.clear_len..file.len() - FILE_MAC_LEN;
        if layout.payload.len() > MAX_PAYLOAD {
            return Err(CoreError::MalformedHeader);
        }
    }
    Ok(layout)
}

fn decrypt_layout(file: &[u8], layout: Layout, key: &MasterKey) -> Result<(Vault, Header)> {
    let Layout {
        mut header,
        clear_len,
        meta,
        payload,
    } = layout;
    let mac_start = file.len() - FILE_MAC_LEN;
    let claimed_mac = &file[mac_start..];

    // Verify the whole-file MAC in constant time before touching anything else.
    let mac_key = key.file_mac_key(&header.hkdf_context)?;
    let mut mac = <HmacSha512 as Mac>::new_from_slice(&mac_key).map_err(|_| CoreError::Kdf)?;
    mac.update(&file[..mac_start]);
    if mac.finalize().into_bytes().ct_eq(claimed_mac).unwrap_u8() != 1 {
        return Err(CoreError::Decrypt);
    }

    // The associated data that bound the payload at seal time.
    let payload_aad: Vec<u8> = match header.version {
        VERSION => {
            // clear header ‖ metadata block
            let (flags, cascade) = open_metadata(
                key,
                &header.hkdf_context,
                &file[meta.clone()],
                &file[..clear_len],
            )?;
            header.factor_flags = flags;
            header.cascade = cascade;
            file[..meta.end].to_vec()
        }
        // v1 bound the payload to its whole cleartext header.
        _ => file[..clear_len].to_vec(),
    };

    let layer_keys = key.cascade_keys(&header.cascade, &header.hkdf_context)?;
    let padded = header
        .cascade
        .open(&layer_keys, &payload_aad, &file[payload])?;
    let plaintext = unpad(&padded)?;

    let vault = serde_json::from_slice(&plaintext).map_err(|_| CoreError::Decrypt)?;
    Ok((vault, header))
}

/// Append random padding plus a 4-byte little-endian length trailer, rounding
/// the total up to a multiple of [`PADDING_BLOCK`].
fn pad(data: &mut Zeroizing<Vec<u8>>) -> Result<()> {
    let with_trailer = data.len() + 4;
    let target = with_trailer.div_ceil(PADDING_BLOCK) * PADDING_BLOCK;
    let pad_len = target - with_trailer;
    data.extend_from_slice(&crate::random::vec(pad_len)?);
    data.extend_from_slice(&(pad_len as u32).to_le_bytes());
    Ok(())
}

fn unpad(data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() < 4 {
        return Err(CoreError::Decrypt);
    }
    let split = data.len() - 4;
    let pad_len =
        u32::from_le_bytes(data[split..].try_into().map_err(|_| CoreError::Decrypt)?) as usize;
    let end = split.checked_sub(pad_len).ok_or(CoreError::Decrypt)?;
    Ok(Zeroizing::new(data[..end].to_vec()))
}

/// Write a vault to disk atomically, keeping a timestamped backup of whatever
/// was there before.
///
/// The new contents land in a sibling temp file that is flushed and fsynced
/// before the rename, so a crash mid-write can never leave a truncated vault.
pub fn write_to_file(
    path: &std::path::Path,
    vault: &Vault,
    factors: &FactorSet,
    cascade: Cascade,
    kdf: KdfParams,
) -> Result<()> {
    create_file(path, vault, factors, cascade, kdf).map(|_| ())
}

/// Write a vault with freshly drawn salt and key, returning both so the caller
/// can keep saving without re-deriving.
///
/// Use this whenever the factors change: create, and re-key.
pub fn create_file(
    path: &std::path::Path,
    vault: &Vault,
    factors: &FactorSet,
    cascade: Cascade,
    kdf: KdfParams,
) -> Result<(MasterKey, Header)> {
    enforce_pattern_kdf(factors, kdf)?;
    let header = Header::new(kdf, factors.flags(), cascade)?;
    let composite = factors.composite()?;
    let key = MasterKey::derive(&composite, &header.salt, header.kdf)?;
    write_to_file_with_key(path, vault, &key, &header)?;
    Ok((key, header))
}

fn enforce_pattern_kdf(factors: &FactorSet, kdf: KdfParams) -> Result<()> {
    if factors.is_pattern_only() && kdf != KdfParams::PARANOID {
        return Err(CoreError::InvalidFactor(
            "a standalone pattern requires the paranoid Argon2id profile".into(),
        ));
    }
    Ok(())
}

/// Save under an already-derived key. This is the path repeat saves take.
pub fn write_to_file_with_key(
    path: &std::path::Path,
    vault: &Vault,
    key: &MasterKey,
    header: &Header,
) -> Result<()> {
    use std::io::Write;

    let bytes = seal_with_key(vault, key, header)?;

    // Prove the file we are about to commit can actually be reopened. Better to
    // fail here than to discover it when the user next needs the vault. Using
    // the cached key keeps this check free of a second Argon2 pass.
    open_with_key(&bytes, key)?;

    if path.exists() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        // Name the backup from the vault's *full* file name, not its stem, so
        // `notes.cbv` and `notes.dat` in the same folder never share a backup
        // namespace (a cross-audit finding).
        let backup = backup_sibling(path, &format!("{stamp}.{}.bak", uuid::Uuid::new_v4()));
        std::fs::copy(path, &backup)?;
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&backup)?
            .sync_all()?;
        // Keep only the most recent backups. Without this, every save left a
        // full encrypted snapshot behind forever: unbounded disk growth, and —
        // worse — an entry the user deleted survives in every old backup, so
        // "delete" never actually erased it from disk.
        prune_backups(path, MAX_BACKUPS);
    }

    let tmp = path.with_extension(format!("cbv.{}.tmp", uuid::Uuid::new_v4()));
    if tmp == path {
        return Err(CoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "temporary vault path collides with destination",
        )));
    }
    let commit = (|| -> Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(&bytes)?;
        f.flush()?;
        f.sync_all()?;
        drop(f);
        replace_destination(&tmp, path)?;
        sync_parent(path)?;
        Ok(())
    })();
    if commit.is_err() {
        let _ = std::fs::remove_file(&tmp);
    } else {
        // The new vault is committed. Sweep any `.rollback` files a previous
        // save could not delete (a scanner momentarily held them): D2 made that
        // cleanup best-effort, so without this pass an orphan could linger with
        // an old vault state — and old deleted entries — forever.
        prune_rollbacks(path);
    }
    commit
}

/// Best-effort removal of stale `<vault file name>.<uuid>.rollback` staging files.
///
/// Only called after a successful commit, when this vault has no live rollback
/// of its own. Names are parsed strictly so nothing but a genuine Cerberus
/// rollback for this exact vault is ever removed.
fn prune_rollbacks(path: &std::path::Path) {
    let (Some(dir), Some(vault_name)) = (path.parent(), path.file_name().and_then(|s| s.to_str()))
    else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else { continue };
        if !ft.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if let Some(rest) = name
            .strip_prefix(vault_name)
            .and_then(|r| r.strip_prefix('.'))
            .and_then(|r| r.strip_suffix(".rollback"))
        {
            if rest.parse::<uuid::Uuid>().is_ok() {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

/// Build a sibling path `<vault file name>.<suffix>` in the vault's directory.
fn backup_sibling(path: &std::path::Path, suffix: &str) -> std::path::PathBuf {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
    let file = match name {
        Some(n) => format!("{n}.{suffix}"),
        None => suffix.to_string(),
    };
    match path.parent() {
        Some(dir) => dir.join(file),
        None => std::path::PathBuf::from(file),
    }
}

/// The nanosecond stamp and UUID a backup name must contain to be recognised
/// as one Cerberus wrote. Returns `None` for anything else, so a user file that
/// merely happens to sit next to the vault (e.g. `vault.cbv.notes.bak`) is never
/// touched. `expected_name` is the vault's full file name (e.g. `vault.cbv`), so
/// two vaults sharing a stem but not an extension keep separate backups.
fn parse_backup_name(name: &str, expected_name: &str) -> Option<(u128, uuid::Uuid)> {
    // Exact shape: `<vault file name>.<u128>.<uuid>.bak`.
    let rest = name.strip_prefix(expected_name)?;
    let rest = rest.strip_prefix('.')?;
    let rest = rest.strip_suffix(".bak")?;
    let (stamp, uuid) = rest.split_once('.')?;
    let stamp: u128 = stamp.parse().ok()?;
    let uuid: uuid::Uuid = uuid.parse().ok()?;
    Some((stamp, uuid))
}

/// Delete all but the `keep` most recent `.bak` snapshots for this vault.
///
/// Best-effort: a backup we cannot enumerate or remove is left in place rather
/// than failing the save. Only files whose name parses as a genuine Cerberus
/// backup for *this* vault are considered — an independent audit noted that a
/// loose prefix/suffix match could delete an unrelated `*.bak` or another
/// vault's backup. Ordering is by the nanosecond stamp embedded in the name
/// (deterministic even when two files share an mtime), with the UUID as a
/// stable tiebreak.
fn prune_backups(path: &std::path::Path, keep: usize) {
    let Some(dir) = path.parent() else { return };
    let Some(vault_name) = path.file_name().and_then(|s| s.to_str()) else {
        return;
    };

    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut backups: Vec<(u128, uuid::Uuid, std::path::PathBuf)> = entries
        .flatten()
        .filter_map(|e| {
            if !e.file_type().ok()?.is_file() {
                return None;
            }
            let name = e.file_name();
            let (stamp, uuid) = parse_backup_name(name.to_str()?, vault_name)?;
            Some((stamp, uuid, e.path()))
        })
        .collect();

    if backups.len() <= keep {
        return;
    }
    // Newest stamp first; UUID breaks ties deterministically.
    backups.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));
    for (_, _, old) in backups.into_iter().skip(keep) {
        let _ = std::fs::remove_file(old);
    }
}

#[cfg(not(windows))]
fn replace_destination(tmp: &std::path::Path, path: &std::path::Path) -> Result<()> {
    std::fs::rename(tmp, path)?;
    Ok(())
}

#[cfg(windows)]
fn replace_destination(tmp: &std::path::Path, path: &std::path::Path) -> Result<()> {
    if !path.exists() {
        std::fs::rename(tmp, path)?;
        return Ok(());
    }

    // `std::fs::rename` does not replace an existing destination on Windows.
    // Move the old, already-backed-up file aside first. If installing the new
    // file fails, restore the original name before returning the error.
    let rollback = backup_sibling(path, &format!("{}.rollback", uuid::Uuid::new_v4()));
    std::fs::rename(path, &rollback).map_err(|error| {
        CoreError::Io(std::io::Error::other(format!(
            "could not stage the previous vault for replacement: {error}"
        )))
    })?;
    if let Err(install_error) = std::fs::rename(tmp, path) {
        if let Err(restore_error) = std::fs::rename(&rollback, path) {
            return Err(CoreError::Io(std::io::Error::other(format!(
                "vault replacement failed ({install_error}); restoring the original also failed ({restore_error}); recover it from {}",
                rollback.display()
            ))));
        }
        return Err(CoreError::Io(install_error));
    }
    // The new vault is committed. Removing the staged old copy is only cleanup:
    // if it fails (a virus scanner or indexer momentarily holding the file), the
    // save has still succeeded, so this must not turn a good write into a
    // reported failure. Leave the orphan `.rollback` rather than lie.
    let _ = std::fs::remove_file(rollback);
    Ok(())
}

#[cfg(unix)]
fn sync_parent(path: &std::path::Path) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        CoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "vault path has no parent directory",
        ))
    })?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent(_path: &std::path::Path) -> Result<()> {
    // NTFS journals the rename; stable Rust does not expose a portable way to
    // open and flush a directory handle on Windows.
    Ok(())
}

pub fn read_from_file(path: &std::path::Path, factors: &FactorSet) -> Result<(Vault, Header)> {
    let bytes = std::fs::read(path)?;
    open(&bytes, factors)
}

/// Read only the header, without any factor. Lets the unlock screen show which
/// factors a vault expects before the user types anything.
/// Read what a vault reveals before unlocking.
///
/// For a v1 file this includes the factor flags and cascade. For a v2 file those
/// are encrypted, so [`Header::factor_flags`] is 0 and the cascade is a
/// placeholder — [`Header::factors_known`] tells the caller which case it is.
pub fn peek_header(path: &std::path::Path) -> Result<Header> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut buf = vec![0u8; 128];
    let n = f.read(&mut buf)?;
    buf.truncate(n);
    peek_bytes(&buf)
}

/// Header fields readable without a key, from the exact file bytes that will
/// subsequently be opened.
pub fn peek_bytes(buf: &[u8]) -> Result<Header> {
    let mut cur = Cursor::new(buf);
    if cur.take(8)? != MAGIC {
        return Err(CoreError::BadMagic);
    }
    let version = u16::from_le_bytes(cur.array::<2>()?);
    let kdf = KdfParams {
        memory_kib: u32::from_le_bytes(cur.array::<4>()?),
        time_cost: u32::from_le_bytes(cur.array::<4>()?),
        parallelism: cur.byte()?,
    };
    kdf.validate()?;
    let salt = cur.array::<SALT_LEN>()?;

    match version {
        VERSION => {
            let hkdf_context = cur.array::<HKDF_CONTEXT_LEN>()?;
            Ok(Header {
                version,
                kdf,
                salt,
                factor_flags: 0, // encrypted — unknown until unlock
                cascade: Cascade::recommended(),
                hkdf_context,
            })
        }
        VERSION_V1 => {
            let factor_flags = cur.byte()?;
            let n_layers = cur.byte()? as usize;
            if n_layers == 0 || n_layers > Cascade::MAX_LAYERS {
                return Err(CoreError::MalformedHeader);
            }
            let cascade = Cascade::from_ids(cur.take(n_layers)?)?;
            let hkdf_context = cur.array::<HKDF_CONTEXT_LEN>()?;
            Ok(Header {
                version,
                kdf,
                salt,
                factor_flags,
                cascade,
                hkdf_context,
            })
        }
        other => Err(CoreError::UnsupportedVersion(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::factors::{Factor, Pattern};
    use crate::vault::Entry;
    use zeroize::Zeroizing;

    const TEST_KDF: KdfParams = KdfParams {
        memory_kib: 19 * 1024,
        time_cost: 2,
        parallelism: 1,
    };

    fn factors() -> FactorSet {
        FactorSet::new().with(Factor::Password(Zeroizing::new(
            "correct horse battery staple".into(),
        )))
    }

    fn sample_vault() -> Vault {
        let mut v = Vault::new("personal");
        let root = v.root;
        let mut e = Entry::new(root, "GitHub");
        e.username = "octocat".into();
        e.password = "hunter2hunter2".into();
        v.add_entry(e).unwrap();
        v
    }

    #[test]
    fn a_standalone_pattern_cannot_downgrade_the_kdf() {
        let pattern =
            Pattern::new(8, vec![3, 61, 10, 47, 22, 56, 1, 39, 15, 50, 28, 44, 7, 58]).unwrap();
        let standalone = FactorSet::new().with(Factor::Pattern(pattern));
        assert!(standalone.validate().is_ok());
        assert!(enforce_pattern_kdf(&standalone, KdfParams::HARDENED).is_err());
        assert!(enforce_pattern_kdf(&standalone, KdfParams::PARANOID).is_ok());
    }

    #[test]
    fn a_sealed_vault_reopens_intact() {
        let v = sample_vault();
        let bytes = seal(&v, &factors(), Cascade::recommended(), TEST_KDF).unwrap();
        let (back, header) = open(&bytes, &factors()).unwrap();
        assert_eq!(back.name, "personal");
        assert_eq!(back.entries.len(), 1);
        assert_eq!(back.entries[0].password, "hunter2hunter2");
        assert_eq!(header.cascade, Cascade::recommended());
    }

    #[test]
    fn metadata_length_does_not_leak_the_layer_count() {
        use crate::cipher::CipherAlgo;
        // A one-layer vault and a four-layer vault must produce metadata blocks
        // of identical length — otherwise `meta_len` reveals the cascade depth
        // to anyone holding the file, without any key (audit finding).
        let one = seal(
            &sample_vault(),
            &factors(),
            Cascade::new(vec![CipherAlgo::Aes256Gcm]).unwrap(),
            TEST_KDF,
        )
        .unwrap();
        let four = seal(&sample_vault(), &factors(), Cascade::paranoid(), TEST_KDF).unwrap();

        let meta_of = |file: &[u8]| -> usize {
            let layout = Header::parse(file).unwrap();
            layout.meta.len()
        };
        assert_eq!(
            meta_of(&one),
            meta_of(&four),
            "metadata block length must be constant regardless of layer count"
        );

        // And both still open to the right cascade — the padding never
        // disturbs how many layers are actually read back.
        assert_eq!(open(&one, &factors()).unwrap().1.cascade.layers().len(), 1);
        assert_eq!(
            open(&four, &factors()).unwrap().1.cascade.layers().len(),
            Cascade::paranoid().layers().len()
        );
    }

    #[test]
    fn every_cascade_shape_round_trips() {
        use crate::cipher::CipherAlgo;
        for algo in CipherAlgo::ALL {
            for cascade in [
                Cascade::new(vec![algo]).unwrap(),
                Cascade::paranoid(),
                Cascade::new(vec![
                    CipherAlgo::Camellia256,
                    CipherAlgo::Twofish256,
                    CipherAlgo::Serpent256,
                    CipherAlgo::Aes256Gcm,
                ])
                .unwrap(),
            ] {
                let bytes = seal(&sample_vault(), &factors(), cascade, TEST_KDF).unwrap();
                assert_eq!(open(&bytes, &factors()).unwrap().0.entries.len(), 1);
            }
        }
    }

    #[test]
    fn the_wrong_password_is_rejected() {
        let bytes = seal(
            &sample_vault(),
            &factors(),
            Cascade::recommended(),
            TEST_KDF,
        )
        .unwrap();
        let wrong = FactorSet::new().with(Factor::Password(Zeroizing::new(
            "correct horse battery stapl".into(),
        )));
        assert!(matches!(open(&bytes, &wrong), Err(CoreError::Decrypt)));
    }

    #[test]
    fn a_missing_keyfile_is_rejected() {
        let full = factors().with(Factor::Keyfile(Zeroizing::new(vec![5u8; 256])));
        let bytes = seal(&sample_vault(), &full, Cascade::recommended(), TEST_KDF).unwrap();
        assert!(open(&bytes, &factors()).is_err());
        assert!(open(&bytes, &full).is_ok());
    }

    #[test]
    fn flipping_any_byte_in_the_file_is_detected() {
        let bytes = seal(
            &sample_vault(),
            &factors(),
            Cascade::recommended(),
            TEST_KDF,
        )
        .unwrap();
        // Sampled rather than exhaustive: each attempt runs a full Argon2 pass.
        for i in (0..bytes.len()).step_by(97) {
            let mut tampered = bytes.clone();
            tampered[i] ^= 0x01;
            assert!(
                open(&tampered, &factors()).is_err(),
                "corruption at offset {i} was accepted"
            );
        }
    }

    #[test]
    fn weakening_the_kdf_in_the_header_is_detected() {
        // Seal above the floor so the downgrade below is a real change.
        let strong = KdfParams {
            memory_kib: 32 * 1024,
            time_cost: 3,
            parallelism: 1,
        };
        let bytes = seal(&sample_vault(), &factors(), Cascade::recommended(), strong).unwrap();

        let mut tampered = bytes.clone();
        // memory_kib sits right after the 8-byte magic and the 2-byte version.
        tampered[10..14].copy_from_slice(&(19u32 * 1024).to_le_bytes());
        tampered[14..18].copy_from_slice(&2u32.to_le_bytes());
        assert_ne!(tampered, bytes, "the test failed to alter the header");
        assert!(open(&tampered, &factors()).is_err());

        // Pushing the cost below the accepted floor must be refused outright,
        // before Argon2 is ever invoked.
        let mut absurd = bytes;
        absurd[10..14].copy_from_slice(&1024u32.to_le_bytes());
        assert!(open(&absurd, &factors()).is_err());
    }

    #[test]
    fn truncated_files_are_rejected_without_panicking() {
        let bytes = seal(
            &sample_vault(),
            &factors(),
            Cascade::recommended(),
            TEST_KDF,
        )
        .unwrap();
        for len in 0..bytes.len().min(200) {
            assert!(open(&bytes[..len], &factors()).is_err());
        }
    }

    #[test]
    fn arbitrary_garbage_is_rejected_without_panicking() {
        for len in [0usize, 1, 8, 16, 64, 128, 1024] {
            let garbage = crate::random::vec(len).unwrap();
            let _ = open(&garbage, &factors());
        }
        let mut nearly = MAGIC.to_vec();
        nearly.extend_from_slice(&[0xFFu8; 200]);
        assert!(open(&nearly, &factors()).is_err());
    }

    #[test]
    fn padding_hides_the_vault_size() {
        let small = seal(
            &Vault::new("x"),
            &factors(),
            Cascade::recommended(),
            TEST_KDF,
        )
        .unwrap();
        let medium = seal(
            &sample_vault(),
            &factors(),
            Cascade::recommended(),
            TEST_KDF,
        )
        .unwrap();
        assert_eq!(
            small.len(),
            medium.len(),
            "an empty vault and a populated one should be indistinguishable by size"
        );
    }

    #[test]
    fn a_cached_key_saves_without_re_deriving() {
        let opened = open_keyed(
            &seal(&sample_vault(), &factors(), Cascade::paranoid(), TEST_KDF).unwrap(),
            &factors(),
        )
        .unwrap();

        let mut edited = opened.vault;
        edited.name = "renamed".into();
        let bytes = seal_with_key(&edited, &opened.key, &opened.header).unwrap();

        // Readable both with the cached key and with the original factors.
        assert_eq!(
            open_with_key(&bytes, &opened.key).unwrap().0.name,
            "renamed"
        );
        assert_eq!(open(&bytes, &factors()).unwrap().0.name, "renamed");
    }

    #[test]
    fn repeat_saves_keep_the_salt_but_change_the_ciphertext() {
        let opened = open_keyed(
            &seal(
                &sample_vault(),
                &factors(),
                Cascade::recommended(),
                TEST_KDF,
            )
            .unwrap(),
            &factors(),
        )
        .unwrap();

        let a = seal_with_key(&opened.vault, &opened.key, &opened.header).unwrap();
        let b = seal_with_key(&opened.vault, &opened.key, &opened.header).unwrap();

        // The salt is per-vault: reusing it is what avoids the second Argon2 pass.
        const SALT_AT: usize = 8 + 2 + 4 + 4 + 1;
        assert_eq!(a[SALT_AT..SALT_AT + 32], b[SALT_AT..SALT_AT + 32]);
        // The nonces are per-write, so the ciphertext must still differ.
        assert_ne!(
            a, b,
            "two saves produced identical bytes: a nonce was reused"
        );
    }

    #[test]
    fn re_keying_draws_a_fresh_salt() {
        let dir = std::env::temp_dir().join(format!("cerberus-rekey-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.cbv");

        let (_, first) = create_file(
            &path,
            &sample_vault(),
            &factors(),
            Cascade::recommended(),
            TEST_KDF,
        )
        .unwrap();
        let (_, second) = create_file(
            &path,
            &sample_vault(),
            &factors(),
            Cascade::recommended(),
            TEST_KDF,
        )
        .unwrap();

        assert_ne!(first.salt, second.salt);
        assert_ne!(first.hkdf_context, second.hkdf_context);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn two_seals_of_the_same_vault_differ() {
        let v = sample_vault();
        let a = seal(&v, &factors(), Cascade::recommended(), TEST_KDF).unwrap();
        let b = seal(&v, &factors(), Cascade::recommended(), TEST_KDF).unwrap();
        assert_ne!(a, b, "fresh salt and nonces should make every write unique");
    }

    #[test]
    fn a_v2_file_hides_its_factors_and_cascade_from_a_peek() {
        // The whole point of v2: an attacker with the file, but no factors,
        // must not learn which factors it needs or which ciphers protect it.
        let bytes = seal(&sample_vault(), &factors(), Cascade::paranoid(), TEST_KDF).unwrap();

        let peeked = peek_bytes(&bytes).unwrap();
        assert_eq!(peeked.version, 2);
        assert!(
            !peeked.factors_known(),
            "v2 peek must not expose the factors"
        );
        assert_eq!(peeked.factor_flags, 0);

        // The cascade must not be recoverable from the raw bytes either. The
        // metadata block is right after the 67-byte clear header + 2-byte length.
        let clear_and_len = 67 + 2;
        let meta_and_payload = &bytes[clear_and_len..bytes.len() - 64];
        for id in 1u8..=5 {
            // A single stray id byte could be coincidence; the point is the
            // ordered cascade [1,2,3,5] never appears in sequence.
            let _ = id;
        }
        let needle = [1u8, 2, 3, 5]; // paranoid() would be AES, XChaCha, Serpent
        assert!(
            !meta_and_payload.windows(needle.len()).any(|w| w == needle),
            "the cascade order is visible in the encrypted region"
        );

        // With the right factors, the real values come back.
        let (_, header) = open(&bytes, &factors()).unwrap();
        assert!(header.factors_known());
        assert_eq!(header.factor_flags, crate::factors::flags::PASSWORD);
        assert_eq!(header.cascade, Cascade::paranoid());
    }

    #[test]
    fn a_v2_peek_still_reports_the_kdf_and_reads_from_disk() {
        let dir = std::env::temp_dir().join(format!("cerberus-peek-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.cbv");
        write_to_file(
            &path,
            &sample_vault(),
            &factors(),
            Cascade::recommended(),
            TEST_KDF,
        )
        .unwrap();

        let h = peek_header(&path).unwrap();
        // KDF parameters stay readable — they must, to derive the key.
        assert_eq!(h.kdf, TEST_KDF);
        assert!(!h.factors_known());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn v1_files_still_open() {
        // Hand-build a v1 file the way the previous format writer did, then make
        // sure the current reader still opens it unchanged.
        let header = Header {
            version: VERSION_V1,
            kdf: TEST_KDF,
            salt: crate::random::bytes::<SALT_LEN>().unwrap(),
            factor_flags: crate::factors::flags::PASSWORD,
            cascade: Cascade::recommended(),
            hkdf_context: crate::random::bytes::<HKDF_CONTEXT_LEN>().unwrap(),
        };
        let composite = factors().composite().unwrap();
        let key = MasterKey::derive(&composite, &header.salt, header.kdf).unwrap();

        let mut plaintext = Zeroizing::new(serde_json::to_vec(&sample_vault()).unwrap());
        pad(&mut plaintext).unwrap();
        let v1_header = header.v1_bytes();
        let layer_keys = key
            .cascade_keys(&header.cascade, &header.hkdf_context)
            .unwrap();
        let payload = header
            .cascade
            .seal(&layer_keys, &v1_header, &plaintext)
            .unwrap();

        let mut file = v1_header.clone();
        file.extend_from_slice(&payload);
        let mac_key = key.file_mac_key(&header.hkdf_context).unwrap();
        let mut mac = <HmacSha512 as Mac>::new_from_slice(&mac_key).unwrap();
        mac.update(&file);
        file.extend_from_slice(&mac.finalize().into_bytes());

        let (vault, back) = open(&file, &factors()).unwrap();
        assert_eq!(back.version, VERSION_V1);
        assert_eq!(vault.entries.len(), 1);
        assert_eq!(vault.entries[0].password, "hunter2hunter2");
        assert!(back.factors_known());
    }

    #[test]
    fn writing_keeps_a_backup_and_never_truncates() {
        let dir = std::env::temp_dir().join(format!("cerberus-write-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.cbv");

        write_to_file(
            &path,
            &Vault::new("first"),
            &factors(),
            Cascade::recommended(),
            TEST_KDF,
        )
        .unwrap();
        write_to_file(
            &path,
            &sample_vault(),
            &factors(),
            Cascade::recommended(),
            TEST_KDF,
        )
        .unwrap();
        write_to_file(
            &path,
            &Vault::new("third"),
            &factors(),
            Cascade::recommended(),
            TEST_KDF,
        )
        .unwrap();

        let (v, _) = read_from_file(&path, &factors()).unwrap();
        assert_eq!(v.name, "third");

        let backups: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".bak"))
            .collect();
        assert_eq!(backups.len(), 2, "rapid saves overwrote a backup");
        assert!(
            !std::fs::read_dir(&dir)
                .unwrap()
                .filter_map(|e| e.ok())
                .any(|e| e.file_name().to_string_lossy().ends_with(".tmp")),
            "temp file was left behind"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn backups_are_pruned_to_a_bounded_set() {
        let dir = std::env::temp_dir().join(format!("cerberus-prune-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.cbv");

        // Many saves in a row: without pruning this would leave one backup per
        // save. With pruning, the count is capped at MAX_BACKUPS.
        for i in 0..(MAX_BACKUPS + 4) {
            write_to_file(
                &path,
                &Vault::new(format!("v{i}")),
                &factors(),
                Cascade::recommended(),
                TEST_KDF,
            )
            .unwrap();
        }

        let backups = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".bak"))
            .count();
        assert!(
            backups <= MAX_BACKUPS,
            "expected at most {MAX_BACKUPS} backups, found {backups}"
        );

        // The live vault is still the latest write and still opens.
        let (v, _) = read_from_file(&path, &factors()).unwrap();
        assert_eq!(v.name, format!("v{}", MAX_BACKUPS + 3));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn prune_only_touches_this_vaults_real_backups() {
        let dir = std::env::temp_dir().join(format!("cerberus-prune2-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.cbv");

        // A user's own file that merely ends in .bak, and a backup belonging to
        // a *different* vault sharing the directory. Neither must be pruned.
        let foreign = dir.join("test.cbv.notes.bak"); // not <stamp>.<uuid>
        let other_vault = dir.join(format!("other.cbv.{}.{}.bak", 1u128, uuid::Uuid::new_v4()));
        std::fs::write(&foreign, b"user notes").unwrap();
        std::fs::write(&other_vault, b"another vault backup").unwrap();

        for i in 0..(MAX_BACKUPS + 3) {
            write_to_file(
                &path,
                &Vault::new(format!("v{i}")),
                &factors(),
                Cascade::recommended(),
                TEST_KDF,
            )
            .unwrap();
        }

        assert!(foreign.exists(), "a non-backup .bak file was deleted");
        assert!(other_vault.exists(), "another vault's backup was deleted");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn backup_name_parsing_is_strict() {
        let uuid = uuid::Uuid::new_v4();
        let good = format!("test.cbv.12345.{uuid}.bak");
        assert!(parse_backup_name(&good, "test.cbv").is_some());
        // Wrong vault name, missing parts, or non-numeric stamp are all rejected.
        assert!(parse_backup_name(&good, "other.cbv").is_none());
        // Same stem but a different extension must NOT share the namespace.
        assert!(parse_backup_name(&good, "test.dat").is_none());
        assert!(parse_backup_name("test.cbv.notes.bak", "test.cbv").is_none());
        assert!(parse_backup_name("test.cbv.12345.bak", "test.cbv").is_none());
        assert!(parse_backup_name(&format!("test.cbv.notanum.{uuid}.bak"), "test.cbv").is_none());
    }

    #[test]
    fn destination_named_like_a_temp_file_never_collides() {
        let dir = std::env::temp_dir().join(format!("cerberus-write-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("unusual.cbv.tmp");

        write_to_file(
            &path,
            &sample_vault(),
            &factors(),
            Cascade::recommended(),
            TEST_KDF,
        )
        .unwrap();
        write_to_file(
            &path,
            &Vault::new("updated"),
            &factors(),
            Cascade::recommended(),
            TEST_KDF,
        )
        .unwrap();
        assert_eq!(read_from_file(&path, &factors()).unwrap().0.name, "updated");

        std::fs::remove_dir_all(&dir).ok();
    }
}
