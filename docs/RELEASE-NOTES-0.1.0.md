# Cerberus 0.1.0

First public release of Cerberus, an offline, local-first password manager for
Windows.

## Downloads

- **`Cerberus_0.1.0_x64-setup.exe`** — Windows x64 installer.
- **`cerberus-app.exe`** — portable Windows x64 executable; no installation
  required.

## Highlights

- Local encrypted `.cbv` vaults with no server, cloud or telemetry.
- Configurable authenticated-encryption cascade.
- Password, PIN, key-file, pattern and Shamir factors.
- Password generation, TOTP, import/export, backups and auto-type.
- Automatic clipboard clearing and session locking.
- Public security design, test suite and independent-audit guide.
- PolyForm Noncommercial 1.0.0 licence, copyright GLINGONK. Commercial use,
  sale and commercial distribution require prior written authorization from
  GLINGONK.

## Verification

SHA-256:

```text
46EAB99E0372234C8B836B22B8BF8D241C54E48AA1311B1CD167DCC19B262977  cerberus-app.exe
5FE7FCB7848CF80E7319EECEA9A33B24247C7D5639E01A3646B7A19800490525  Cerberus_0.1.0_x64-setup.exe
```

These binaries are not code-signed. Windows SmartScreen may display an
“unknown publisher” warning. Build from source if you prefer to verify the
complete toolchain yourself.
