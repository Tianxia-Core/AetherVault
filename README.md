<p align="center">
  <img src="./brand-kit/01-logos/lockups-and-social/dual-lockup-rxm-x-tianxiaos.svg" alt="RASA-X-MACHINA · tianxiaOS" width="680"/>
</p>

# AetherVault

**Zero-Dependency AES-256-GCM Cryptographic AetherVault with HMAC-Chained Audit Ledger (MIT)**

`AetherVault` provides both a **zero-CGO static executable** (`cmd/aethervault`, 100% Go standard library) and a **Python library & CLI** (`tx_secrets_vault.py`) for authenticated at-rest secret storage across Linux (`x86_64`, `aarch64`), Windows (`x86_64`), and Android (`aarch64`).

---

## Cryptographic Architecture

| Layer | Static Go Executable (`AetherVault`) | Python Library & CLI (`tx_secrets_vault.py`) |
| :--- | :--- | :--- |
| **FFP Classification** | `FFP-SECRETS-VAULT` (`crypto-signer`, Go) | `FFP-SECRETS-VAULT-PY` (`crypto-signer`, Python) |
| **External Dependencies** | **Zero** (`CGO_ENABLED=0`, Go stdlib only) | `cryptography` (OpenSSL AEAD + Scrypt + HKDF) |
| **Password KDF** | PBKDF2-HMAC-SHA256 (`210,000` OWASP iterations) | Scrypt (`N=65536, r=8, p=1`) |
| **Subkey Derivation** | RFC 5869 HKDF-SHA256 (per-purpose & per-secret) | RFC 5869 HKDF-SHA256 (per-purpose & per-secret) |
| **Authenticated Cipher** | AES-256-GCM (96-bit CSPRNG nonces + domain AAD) | AES-256-GCM (96-bit CSPRNG nonces + domain AAD) |
| **Tamper-Evident Audit** | Append-only HMAC-SHA256 hash chain (`vault_audit.jsonl`) | Append-only HMAC-SHA256 hash chain (`vault_audit.jsonl`) |
| **Filesystem Safety** | Atomic `0600` temp-file `fsync` + `rename` | Atomic `0600` temp-file `fsync` + `os.replace` |
| **Erasure (`shred`)** | Multi-pass CSPRNG overwrite + envelope re-keying | CSPRNG overwrite + envelope re-keying |

---

## Quickstart (Static Binary)

```bash
export SECRETS_VAULT_DIR="$HOME/.local/share/AetherVault"
export SECRETS_VAULT_PASSPHRASE="your-high-entropy-passphrase"

# 1. Initialize vault
./AetherVault-v2.0.0-linux-x86_64 init

# 2. Store & retrieve secrets
./AetherVault-v2.0.0-linux-x86_64 set -key db_url -value "postgres://app@db.internal:5432/prod"
./AetherVault-v2.0.0-linux-x86_64 get -key db_url

# 3. List metadata (never prints secret values) & verify full cryptographic integrity
./AetherVault-v2.0.0-linux-x86_64 list
./AetherVault-v2.0.0-linux-x86_64 verify

# 4. Crypto-shred an individual secret
./AetherVault-v2.0.0-linux-x86_64 shred -key db_url
```

## Python Library Usage

```python
from pathlib import Path
import tx_secrets_vault as sv

with sv.create_vault("your-high-entropy-passphrase", Path("./my-vault")) as vault:
    vault.set_secret("signing_key", "ed25519-seed-material", {"service": "api"})
    assert vault.get_secret("signing_key") == "ed25519-seed-material"
    assert vault.verify()["verified"] is True
```

---

## Release Signature Verification

Every `v2.0.0` executable and `SHA256SUMS` manifest is signed with Ed25519 (`keys/RELEASE_SIGNING_KEY.pub.pem`):

```bash
sha256sum -c SHA256SUMS
openssl pkeyutl -verify -pubin -inkey keys/RELEASE_SIGNING_KEY.pub.pem -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
```

---

## Governance & Attribution

Maintained by **RASA-X-MACHINA** *(Proposed Estonian Deep-Tech Entity — Startup Committee application in preparation)* · [`rasaxmachina.com`](https://rasaxmachina.com). Licensed under the [MIT License](LICENSE).
