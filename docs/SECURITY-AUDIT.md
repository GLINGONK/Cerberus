# Security audit summary

This document records the independent review Cerberus has been through. It is a
public, honest account — including what was **not** done.

## What kind of review this is

Cerberus has **not** had a paid professional security audit. Its assurance comes
from three sources:

1. A large, security-focused automated test suite (`core/tests/security.rs`,
   `core/tests/properties.rs`) and a continuous fuzzing harness on the untrusted
   `.cbv` parser.
2. `#![forbid(unsafe_code)]` on the entire cryptographic core, so no memory-safety
   bug can originate there.
3. **Several rounds of independent cross-review by different frontier AI models**,
   deliberately from different families so their blind spots do not overlap.

Treat this as a strong signal, not a formal proof. A professional human audit
would still be valuable and is welcome.

## Methodology: adversarial cross-review

Each round followed the same loop:

1. One model performed a hostile, independent review of the current code with a
   defensive mandate (find flaws; do not trust code comments or prior
   conclusions).
2. Every reported finding was **verified against the code** before any change —
   real bugs were separated from false positives and from residuals already
   documented as accepted.
3. Fixes were applied with a regression test where feasible.
4. A **different** model re-reviewed, both to check the fixes held and to look
   for what the previous pass missed.

Reviewers used, across rounds: Claude (Opus-class), OpenAI GPT-5-class, and
Google Gemini (3.1 Pro and Flash, high reasoning). The cryptographic core was
examined by all and no reviewer broke it.

## Representative findings and resolutions

The findings below are illustrative of the classes of issue found and fixed. All
were in the **application/session layer**, not in the cryptographic primitives.

| Area | Issue | Resolution |
|---|---|---|
| CSV export | Re-authentication verified the supplied factors against the on-disk file, then exported the in-memory vault — a TOCTOU letting a swapped disk file bypass the re-auth | Re-derive the key from the supplied factors against the **open vault's** header and compare it, in constant time, to the in-memory key; export the same object that was verified |
| Inter-process locking | Two instances could open the same vault and race their writes, silently discarding one's changes | Exclusive lock file per open vault (`create_new`), reclaimed via process-liveness check; the liveness check also verifies the holding process is actually Cerberus, so a recycled PID cannot lock the owner out |
| Anti-bruteforce counter | The persisted failure counter used a best-effort lock that could drop an increment under contention | A strict lock for the security counter that waits for a genuinely-live writer instead of proceeding best-effort |
| App-config gate | A corrupt/truncated config was treated as "absent" and could be reconfigured without the current phrase | Distinguish absent / plaintext / gated / corrupt states explicitly and refuse to reconfigure a corrupt one |
| Windows file replace | `rename` does not overwrite on Windows, so every save after the first silently failed | Windows-safe stage-aside replacement with rollback, mirrored across vault, config, and attempts files |
| Session hardening | Auto-lock relied on the webview polling; a frozen/suspended webview left secrets resident | Native message-only window registered for session-lock and suspend/resume notifications, independent of the webview |
| Memory hygiene | A lock guard leak could exhaust the lockable-page quota across key clones | Each key on its own page-aligned allocation, holding and releasing its own `VirtualLock` guard |
| Reuse audit | On a CSPRNG failure the keyed hash fell back to a fixed zero key (an unsalted hash) | Fail closed — report nothing rather than offer a degraded audit |

## Accepted residuals

These are inherent to the threat model and are the same posture as mainstream
managers (KeePass, Bitwarden). They are documented, not fixed, because "fixing"
them is either impossible or theatre:

- A compromised webview on an **already-unlocked** vault can read any single
  secret through the normal reveal path. This is true of every local manager
  with a UI.
- A sub-millisecond TOCTOU between focus check and simulated keypress in
  auto-type.
- The Windows two-`rename` replacement has a brief window with no final-named
  file; it is recoverable from the backup/rollback.
- Backup retention deliberately keeps a bounded number of prior encrypted
  snapshots, so a deleted secret survives in older backups until they rotate out.

## Reproducing the baseline

```
cargo test --workspace          # full suite
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo audit
cargo deny check
```
