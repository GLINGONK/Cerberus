# Testing Cerberus Security

Run the standard audit suite from the repository root:

```powershell
pwsh tools/audit.ps1
```

## 1. Automated tests

```powershell
cargo test --workspace --all-targets
```

The suite covers cipher round trips, independent keys, authentication of every
file byte, hostile headers, truncation, KDF bounds, factor separation, Shamir
shares, RFC 6238 vectors, padding, backups, atomic writes, session behaviour and
Windows concurrency controls.

Passing tests show only that tested properties hold for tested inputs. They do
not prove the absence of defects or a mistake in the design.

The wall-clock KDF measurement is deliberately opt-in:

```powershell
cargo test -p cerberus-core --release --test properties -- --ignored --nocapture
```

## 2. Static and dependency checks

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo audit
cargo deny check
node --check app/dist/app.js
```

`cargo audit` checks RustSec advisories. `cargo deny` enforces allowed
sources and licences and reports duplicates. An ignored advisory must identify
the crate and explain why it cannot affect the shipped Windows build.

The frontend has no npm dependency tree. A core test mechanically rejects
networking crates in the cryptographic core.

## 3. Fuzzing

```powershell
rustup toolchain install nightly
cargo install cargo-fuzz --locked
cargo +nightly fuzz run header -- -max_total_time=600
```

The target exercises the unauthenticated `.cbv` header parser. Preserve any
minimized crashing input with the exact commit, toolchain and command. A panic
is a security-relevant denial of service even though the core forbids unsafe
Rust.

## 4. Manual runtime checks

Use synthetic vaults only.

- **File inspection:** no plaintext or password derivative should appear after
  encryption. Corrupting or truncating a copy must fail closed.
- **Network isolation:** after exercising the application, run
  `Get-NetTCPConnection -OwningProcess (Get-Process cerberus-app).Id`; the
  result should be empty.
- **Clipboard:** copied test secrets must clear after the configured delay.
  Unrelated clipboard content must survive.
- **Session:** verify idle lock, Win+L, suspend and resume.
- **Attempts:** verify the failed-attempt delay survives restart.
- **Concurrency:** a second process must not write an already-open test vault;
  only genuinely stale locks may be reclaimed.
- **Distribution:** build with `pwsh tools/build.ps1`, scan for developer home
  paths and verify SHA-256 hashes. Describe unsigned binaries as unsigned.

## 5. Limits of automation

Tests cannot prove that the threat model is complete, that the design has no
conceptual flaw, that a compiler or dependency is trustworthy, or that
plaintext never appears elsewhere in a compromised OS. Independent design
review, professional cryptographic review and controlled post-lock memory
analysis remain valuable.

Cerberus does not claim to stop keyloggers, malware with user privileges,
kernel or firmware compromise, or a privileged dump of an unlocked process.
An offline attacker bypasses UI delays; resistance comes from factor entropy
and Argon2id cost.

See [AUDITING.md](../AUDITING.md) for safe-testing rules and reporting format,
and [SECURITY-DESIGN.md](SECURITY-DESIGN.md) for the design under test.
