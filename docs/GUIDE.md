# Cerberus — User Guide

This guide explains in plain language how Cerberus protects passwords and what
its limits are. No cryptography background is required.

## 1. The basic idea

A vault is a `.cbv` file containing encrypted credentials. It may be copied,
stolen or placed on removable media; without every required factor it remains
unreadable. Security comes from those factors, not from hiding the code.

## 2. Authentication factors

Every selected factor is required when opening the vault.

| Factor | Meaning | Guidance |
|---|---|---|
| Password | Something you know | Use a long, unique one |
| PIN | Something you know | Low entropy; never accepted alone |
| Key file | Something you possess | Keep independent backup copies |
| Pattern | Something you know | 3×3 to 8×8; order and direction matter |
| Shamir shares | Distributed possession | The configured threshold reconstructs one factor |

Factors can be combined, for example password + pattern + key file. A key file
or pattern can be copied; a strong password remembered only by you remains the
primary defence against theft of the other material.

## 3. Key derivation

Each factor is normalized and domain-separated before composition. Argon2id
deliberately makes every guess slow and memory-intensive. The result derives
independent keys for file authentication, metadata and each encryption layer.

Profiles range from Interactive to Paranoid. Higher profiles consume much more
memory and time for every legitimate unlock as well as every guess. Choose one
your machine can reliably complete.

## 4. Encryption cascade

Cerberus supports one to four ordered layers using AES-256-GCM,
XChaCha20-Poly1305, Serpent, Twofish and Camellia. Each receives an independent
key. AES-256 alone is already beyond practical brute force; the cascade is
defence in depth, not a substitute for a strong password.

## 5. What the file reveals

The clear header contains only version, Argon2 parameters and a random salt.
Required factors, cipher order and vault contents are encrypted. The complete
file is authenticated, so alteration is detected. Random padding reduces
information leaked by the number of entries.

## 6. Memory protection

Cerberus keeps an unlocked vault sealed under a random session key and opens
plaintext only for individual commands. Secret buffers are zeroized afterward.
This reduces exposure but cannot protect a machine already compromised while
the vault is open.

## 7. Everyday protections

| Protection | Behaviour |
|---|---|
| Clipboard clearing | Removes copied secrets after the delay or first paste |
| Automatic lock | Locks after inactivity, session lock or suspend/resume |
| Guess delay | Increasing delay after failures, persisted across restarts |
| Trash | Normal deletion is recoverable until explicitly purged |
| Backups | An encrypted snapshot is retained before writes |
| Concurrent access | A vault lock prevents two Cerberus writers |

## 8. Backup and recovery

Data loss is more likely than cryptographic failure:

1. Keep independent copies of the `.cbv` file.
2. Never keep the only key-file copy beside the vault.
3. Separate Shamir shares according to their threshold.
4. Test recovery using copies and the exact required factors.

There is no hidden recovery key. GLINGONK cannot open a vault without its
factors. Losing every valid factor copy makes the vault permanently inaccessible.

## 9. What Cerberus cannot protect

| Threat | Protected? |
|---|---|
| Theft of the `.cbv` alone | Yes, subject to factor strength |
| Theft of one factor while others remain secret | Yes |
| File corruption | Detected; recovery still requires a backup |
| Loss of every backup or required factor | No |
| Malware or keylogger active during unlock | No local manager can prevent it |
| Privileged live-memory inspection | No |

Keep Windows updated, use full-disk encryption, avoid untrusted software and use
a dedicated offline machine for exceptionally sensitive material.

## 10. In one sentence

Cerberus protects a vault at rest and states its limits honestly: use a strong
unique password, maintain tested backups and keep the host trustworthy.
