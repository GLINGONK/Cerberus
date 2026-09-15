# Auditing Cerberus

Independent defensive review is welcome. This file gives reviewers a
reproducible starting point and defines the responsible boundaries of an audit.

Cerberus has not undergone a paid professional security audit. Existing reviews,
including AI-assisted cross-reviews, are summarized in
[`docs/SECURITY-AUDIT.md`](docs/SECURITY-AUDIT.md). They are evidence, not proof.

## Scope

The most valuable review targets are:

- the unauthenticated `.cbv` header parser and resource limits;
- factor composition, KDF parameters and domain separation;
- authenticated encryption, nonces, key separation and file-format binding;
- atomic writes, backups, rollback recovery and concurrent Windows processes;
- session locking, clipboard clearing, secret lifetime and WebView IPC;
- CSV import/export, auto-type targeting and hostile input handling;
- dependency, build and release integrity.

The design and threat model are documented in
[`docs/SECURITY-DESIGN.md`](docs/SECURITY-DESIGN.md). Test rationale and manual
checks are in [`docs/SECURITY-TESTING.md`](docs/SECURITY-TESTING.md).

## Reproduce the baseline

On a Windows development machine with stable Rust and PowerShell 7:

```powershell
pwsh tools/audit.ps1
```

The individual blocking checks are:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo audit
cargo deny check
node --check app/dist/app.js
```

The intentionally slow wall-clock KDF measurement is opt-in:

```powershell
cargo test -p cerberus-core --release --test properties -- --ignored --nocapture
```

## Fuzzing

The public fuzz target covers the only bytes parsed before authentication:

```powershell
rustup toolchain install nightly
cargo install cargo-fuzz --locked
cargo +nightly fuzz run header -- -max_total_time=600
```

Do not report a crash without preserving the minimized input and the exact
commit, Rust version and command used to reproduce it.

## Safe test rules

- Use only synthetic vaults created specifically for the audit.
- Never request, publish or test another person's real `.cbv`, password,
  pattern, PIN, key file, Shamir share or exported CSV.
- Do not perform denial-of-service, phishing, credential collection or malware
  deployment against users.
- Remove test secrets from logs, screenshots, crash dumps and issue attachments.
- A local anti-bruteforce delay is not a defence against an offline copy; assess
  offline resistance through the documented KDF and synthetic fixtures.

## Reporting a finding

For a suspected vulnerability, avoid publishing exploitable details before the
maintainer has had a reasonable opportunity to respond. Contact **GLINGONK**
through the GitHub repository and include:

1. affected commit and Cerberus version;
2. severity and attacker prerequisites;
3. exact affected file and lines;
4. minimal reproduction using synthetic data;
5. expected versus actual result;
6. proposed minimal fix and regression test, if known.

Ordinary hardening ideas and non-sensitive bugs may be filed as public issues.
Do not claim that a report is a professional audit unless it actually was one.

## Licence

Reviewing the public source does not change its licence. Cerberus is distributed
under the [PolyForm Noncommercial License 1.0.0](LICENSE). Noncommercial study,
modification and sharing are allowed under its terms. Commercial use, sale or
commercial distribution requires prior written authorization from **GLINGONK**.
