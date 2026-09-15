# Cerberus

A local, offline password manager for Windows. Configurable encryption cascade,
several authentication factors you can stack, Tauri interface. No server, no
cloud, no telemetry — nothing ever leaves your machine.

> **This repository is public by design.** A vault's security rests entirely on
> the factors its owner chooses, never on this code being secret. See
> [docs/SECURITY-DESIGN.md](docs/SECURITY-DESIGN.md).

## What it does

| | |
|---|---|
| **Encryption** | 1 to 4 layers among AES-256-GCM, XChaCha20-Poly1305, Serpent-256, Twofish-256, Camellia-256 — free ordering, an independent key per layer |
| **Key derivation** | Argon2id, 3 profiles (256 MiB / 1 GiB / 4 GiB), calibratable |
| **Factors** | Password, PIN, multiple key files, pattern on a 3×3 to 8×8 grid, Shamir K-of-N shares — combinable, all required together |
| **Organisation** | Tree folders, instant search, tags, password history, trash |
| **Custom fields** | Per-entry custom fields, markable secret (masked, out of search, auto-cleared copy) |
| **Migration** | CSV import (KeePass, Bitwarden, 1Password, Chrome, Firefox, Edge — comma/semicolon/tab, UTF-8/UTF-16), CSV export, encrypted backup |
| **TOTP** | RFC 6238 (SHA-1/256/512), `otpauth://` import, QR export |
| **Generation** | Passwords and passphrases, uniform sampling, real entropy shown |
| **Auto-type** | Simulated Unicode typing into the active window, window-title patterns |
| **Hygiene** | Auto-cleared clipboard, idle lock, native lock on session-lock/suspend, progressive back-off after failures, reuse audit |

## Download

Prebuilt Windows x64 binaries are attached to each
[GitHub Release](../../releases):

- **Installer** — `Cerberus_0.1.0_x64-setup.exe` (NSIS)
- **Portable** — `cerberus-app.exe`, run directly, no install

> The binaries are **not code-signed**. Windows SmartScreen will show an
> "unknown publisher" warning the first time you run them — expected for an
> independent project. If you prefer, build from source (below): the result is
> byte-for-byte what ships.

## Security & audit

The cryptographic core is `#![forbid(unsafe_code)]`, has a documented design
([docs/SECURITY-DESIGN.md](docs/SECURITY-DESIGN.md)), a continuous fuzzing
harness, and a large security-focused test suite. It has been through several
rounds of independent cross-review — see
[docs/SECURITY-AUDIT.md](docs/SECURITY-AUDIT.md) for the methodology, findings,
and how each was resolved.

**Honest disclaimer:** Cerberus has **not** undergone a paid professional
security audit. The review to date is the author's test/fuzz suite plus multiple
independent AI-model code reviews. That is a strong signal, not a formal proof.
Use it with that context in mind.

Want to review the code independently? Start with [`AUDITING.md`](AUDITING.md),
which documents the audit scope, reproducible commands, safe-test rules and
responsible reporting format.

## Architecture

```
core/            Rust crate — all cryptography, zero unsafe
  cipher.rs        cascade and cipher layers
  kdf.rs           Argon2id + HKDF-SHA512
  factors.rs       authentication factors and composite
  container.rs     the .cbv file format
  vault.rs         data model
  shamir.rs        Shamir secret sharing (GF(256))
  generator.rs     password generation
  totp.rs          RFC 6238
  porting.rs       CSV import / export
  session.rs       locking, anti-bruteforce, clipboard
app/
  src-tauri/     application layer — IPC, auto-type, QR
  dist/          HTML/CSS/JS interface, zero npm dependencies
installer/       Inno Setup script
tools/           build + icon generation
```

**The frontend holds no secret.** It receives entry metadata, and one secret at
a time, only on an explicit action (reveal, copy, auto-type). The master key
never crosses the IPC boundary.

## Build from source

Requires the Rust toolchain and the Tauri CLI.

```bash
cargo tauri build
```

Produces `target/release/bundle/nsis/Cerberus_0.1.0_x64-setup.exe`.

To build reproducibly without leaking the build machine's paths into the binary,
use the wrapper (rewrites Cargo/rustup/home path prefixes):

```bash
pwsh tools/build.ps1
```

Inno Setup variant, after the build above:

```bash
iscc installer\cerberus.iss
```

## Test

```bash
cargo test --workspace
```

177 tests. The most significant, in
[core/tests/security.rs](core/tests/security.rs):

- no plaintext or password-derived material survives in the sealed file
- any single-bit corruption is detected, on every cascade
- truncation at any length: an error, never a panic
- 20,000 hostile headers generated: no panic
- absurd Argon2 parameters: refused before allocation
- only the exact factor set opens the vault — a reversed pattern, resized grid,
  or a key file altered by one byte all fail
- two vaults under the same password share no bytes after the header
- MAC verification with no measurable timing gradient

Dependency audit:

```bash
cargo audit
cargo deny check
```

## Assumed limits

A local password manager does not protect against everything. Out of scope:

- **Keylogger or malware running as you** — reads the master password as you
  type it. No local software defence resists this. Same limit as KeePass,
  Bitwarden, and every local manager.
- **Memory dump of the unlocked process** — auto-lock shrinks the window, it
  does not close it.
- **Kernel or firmware compromise** — out of scope.
- **Binary obfuscation** — slows reverse engineering, protects no data. It is
  not a security measure.

A direct consequence of the model: **there is no recovery**. Lose a factor, lose
the vault. Keep an encrypted backup (same factors as the original).

**CSV export is plaintext.** Inherent to the format — there is no encrypted CSV.
It exists to migrate to another manager, nothing else. For a backup, use the
encrypted backup.

## Deliberately left out

Considered and rejected, with the reason:

- **Breach checking (HIBP)** — would require network calls. Cerberus makes none,
  and that is verifiable: no HTTP crate is in the dependency tree. Trading that
  away for a checking service would be a bad deal.
- **Site icons** — fetching them means a request to every registered domain,
  which discloses your account list to the network. Title-derived colour dots do
  the same visual job, offline.
- **Native KDBX import** — the KeePass format needs a full parser (XML, inner
  stream cipher, compression) to cover a single application. KeePass exports CSV,
  which import already handles.
- **Decoy vault** — badly done plausible deniability is worse than none: file
  size, timestamps, and backups betray the real vault's existence. Done right or
  not at all.

## License

[PolyForm Noncommercial License 1.0.0](LICENSE).

Free to use, study, modify, and share for **noncommercial** purposes. **Selling
it — or a fork — is not permitted**, and any fork inherits the same
noncommercial terms. This is *source-available*, not OSI "open source"
(that label requires allowing commercial use, which is exactly what this
project chooses to forbid). The code stays free, for everyone, permanently.

Copyright © 2026 **GLINGONK**. Commercial use, commercial distribution and
commercial licensing are reserved exclusively to GLINGONK. Contact GLINGONK
through the GitHub repository before any commercial use.
