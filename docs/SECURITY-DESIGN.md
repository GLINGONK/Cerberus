# Cerberus — Security Design

> Guiding principle: **Kerckhoffs's principle**. Vault security depends on the
> user's authentication factors, never on hiding the source or file format.

## 1. Cryptographic pipeline

```text
password / PIN / key files / pattern / Shamir shares
                    │
                    ▼  normalization and domain separation
              BLAKE3 contributions
                    │
                    ▼  canonical composition + keyed BLAKE3
              32-byte composite
                    │
                    ▼  Argon2id (random salt, calibrated m/t/p)
              64-byte master key
                    │
                    ▼  HKDF-SHA512 with distinct context per use
       layer keys / metadata key / file-MAC key
                    │
                    ▼  selected cipher cascade
              encrypted .cbv payload
```

### Available ciphers

| Algorithm | Construction | Notes |
|---|---|---|
| AES-256-GCM | AEAD / GCM | NIST standard; commonly hardware accelerated |
| XChaCha20-Poly1305 | AEAD | 192-bit nonce |
| Serpent-256 | CTR + HMAC-SHA512 | AES finalist |
| Twofish-256 | CTR + HMAC-SHA512 | AES finalist |
| Camellia-256 | CTR + HMAC-SHA512 | ISO-standardized block cipher |

A vault uses one to four layers in a user-selected order. Each layer receives
an independent HKDF key. A cascade is defence in depth against a future break
in one algorithm; it does not improve a weak password.

Serpent, Twofish and Camellia use encrypt-then-MAC: CTR encryption with a
32-byte encryption key and 16-byte nonce, followed by HMAC-SHA512 over nonce
and ciphertext, truncated to 32 bytes. The MAC is checked in constant time
before decryption. Encryption and MAC keys are separate HKDF outputs.

### Argon2id profiles

| Profile | Memory | Iterations | Parallelism | Approximate target |
|---|---:|---:|---:|---:|
| Interactive | 256 MiB | 3 | 4 | 0.5 s |
| Hardened (default) | 1 GiB | 4 | 4 | 2 s |
| Paranoid | 4 GiB | 8 | 8 | 15 s |

The parameters and random 32-byte salt are visible because they are needed
before a key exists. A fresh salt is generated when factors change.

## 2. Authentication factors

All selected factors are combined with logical **AND**, not OR. Each
contribution has a distinct domain tag before canonical composition, preventing
one factor type from being confused with another.

### Pattern

- Configurable 3×3 to 8×8 grid.
- Ordered points and direction are part of the secret.
- Minimum length: `max(5, grid_size)`.
- The UI estimates entropy and rejects a weak pattern as the only factor.
- A large grid does not compensate for a predictable human choice.

### Key files and PIN

The key-file contribution is BLAKE3 of the complete contents. Empty files and
files shorter than 32 bytes are rejected; the generator produces 256 CSPRNG
bytes. A PIN is treated as low entropy and cannot be the only factor.

### Shamir shares

K-of-N shares reconstruct one random secret contribution. Reaching the
threshold supplies that factor but does not replace any other selected factor.

## 3. The `.cbv` format

Version 2 encrypts the required-factor description and cipher cascade. Only
fields needed to run Argon2id remain visible. Version 1 remains readable; every
subsequent write uses version 2.

```text
┌ CLEAR, AUTHENTICATED HEADER ─────────────────────────┐
│ magic / version / KDF parameters / salt / context    │
├ ENCRYPTED METADATA (AES-256-GCM) ────────────────────┤
│ required factors / ordered cipher identifiers        │
├ ENCRYPTED PAYLOAD ───────────────────────────────────┤
│ serialized vault / random padding                    │
└ HMAC-SHA512 over every preceding byte ───────────────┘
```

Metadata, layers and file authentication use separate HKDF outputs. Clear
metadata is authenticated and bound as associated data, so parts from different
files cannot be recombined. Padding uses 4 KiB buckets to reduce size leakage.

### Memory protection

An unlocked vault is not kept as a long-lived plaintext object. It remains
sealed under a random in-memory session key, opens for one command, then is
resealed. Plaintext and key material are zeroized. Windows locks sensitive
allocations where supported to reduce paging.

This cannot defeat a privileged live-process dump: an attacker able to read the
whole process can obtain both sealed data and its session key.

### Integrity and writes

The complete file is authenticated. Writes use a create-new temporary file,
flush it, preserve an encrypted backup, and replace the destination with a
Windows rollback path. Inter-process locking prevents two Cerberus instances
from knowingly writing the same vault together.

## 4. Application hardening

| Measure | Status |
|---|---|
| Encrypted factor and cascade metadata | Implemented |
| Command-scoped plaintext lifetime | Implemented |
| Persistent failed-attempt delay | Implemented |
| Key and secret zeroization | Implemented |
| Windows page locking for key allocations | Implemented |
| Constant-time authentication comparison | Implemented |
| Crash-recoverable writes and encrypted backups | Implemented |
| Idle, session-lock and suspend/resume locking | Implemented |
| Clipboard ownership guard and timed clearing | Implemented |
| Independent nonce material on every write | Implemented |
| Master key never sent to the WebView | Implemented |
| Header-parser fuzzing | Implemented |
| Dependency and licence policy in CI | Implemented |

## 5. Threat-model exclusions

Cerberus does not claim to stop keyloggers or malware with user privileges, a
privileged dump of the unlocked process, kernel or firmware compromise, loss of
every required factor and backup, or offline guessing made practical by a weak
password. Binary obfuscation is not a security control. Full-disk encryption is
recommended for operating-system files, crash dumps and local metadata outside
the `.cbv` format.

## 6. Random generation

Primary randomness comes from the operating-system CSPRNG (`getrandom`, backed
by `BCryptGenRandom` on Windows). Optional mouse entropy is only additive and
is mixed with OS randomness through BLAKE3; hostile user entropy cannot weaken
the result. Password generation uses rejection sampling to avoid modulo bias.

## 7. Verification

The public suite covers round trips, corruption, truncation, hostile headers,
KDF bounds, exact factor matching, nonce reuse, padding, ciphertext
distribution, Shamir reconstruction, RFC 6238 vectors and concurrent writes.
The parser also has a `cargo-fuzz` target.

See [SECURITY-TESTING.md](SECURITY-TESTING.md) and
[AUDITING.md](../AUDITING.md) for reproducible commands and test limitations.
