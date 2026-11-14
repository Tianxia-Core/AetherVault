# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `2.0.x` | Yes |
| `< 2.0.0` | No |

## Threat Model & Cryptographic Controls

- **At-Rest Confidentiality & Integrity**: Master keys, vault envelopes, and individual secret items are independently encrypted with AES-256-GCM using distinct HKDF-SHA256 subkeys and domain-bound Additional Authenticated Data (AAD).
- **Zero Plaintext Persistence**: Secrets are never written to disk in cleartext; state updates use `0600` temporary files with `fsync` followed by atomic rename.
- **Tamper-Evident Audit Trail**: Every operation appends an HMAC-SHA256 chained record to `vault_audit.jsonl`, validated end-to-end by `AetherVault verify`.

## Reporting a Vulnerability

Do **not** open public GitHub issues for suspected cryptographic or security vulnerabilities. Report privately to [Encrypted Security Dispatch](https://rasaxmachina.com/collins#encrypted-dispatch) with reproduction steps; acknowledgement is provided within 48 hours.
