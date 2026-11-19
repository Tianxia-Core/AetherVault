<p align="center">
  <img src="./brand-kit/01-logos/lockups-and-social/dual-lockup-rxm-x-tianxiaos.svg" alt="RASA-X-MACHINA · tianxiaOS" width="680"/>
</p>

# AetherVault

**Zero-Dependency AES-256-GCM Cryptographic AetherVault with HMAC-Chained Audit Ledger (MIT)**

`AetherVault` provides both a **zero-CGO static executable** (`cmd/aethervault`, 100% Go standard library) and a **Python library & CLI** (`tx_secrets_vault.py`) for authenticated at-rest secret storage across Linux (`x86_64`, `aarch64`), Windows (`x86_64`), and Android (`aarch64`).

<!-- BUILD_LAW_SHOWCASE_START -->

---

## 🌍 In Plain English — What `AetherVault` Is & Why It Matters (Layman's Guide)

- **The Everyday Problem:** Storing API keys in `.env` files leaves plaintext secrets sitting on disk where any rogue npm script, backup leak, or AI coding agent can accidentally read and expose them.
- **How It Works (Without the Jargon):** `AetherVault` locks credentials inside an authenticated `AES-256-GCM` / `XChaCha20-Poly1305` encrypted enclave (`chmod 0600`), injects secrets only at runtime without writing them to config files, and records every access in a tamper-evident HMAC audit log.
- **Why It Is Different:** Open-source (`MIT`), offline-capable, zero SaaS subscription required, and engineered as the canonical secret-custody layer of **[Build Law](https://github.com/Tianxia-Core/Build-Law)**.
- **How It Benefits You:** Solo developers and enterprise teams eliminate `.env` leaks, protect AI MCP servers from credential exposure, and gain instant cryptographic auditability.
- **How to Install & Use It in 60 Seconds:** Grab the signed standalone executable from Releases or build from source (`go build`), then initialize your vault with `secrets-vault init`.

---

## 🏛️ Governed by [`Build Law`](https://github.com/Tianxia-Core/Build-Law) — Clean-Room Public Edition & Stakeholder Pathways

This repository ships as a **`PUBLIC_CLEANROOM_SEED` Edition** under **[`Build Law`](https://github.com/Tianxia-Core/Build-Law)**—containing zero pre-populated personal data, zero embedded secrets, and deterministic `init-clean` bootstrapping (`nimbus2 init-clean` / `build-law init-clean`) so every adopter starts with a fresh, sovereign workspace of their own:
- **Developers & AI Builders:** Combine **[`FC-Estimator`](https://github.com/Tianxia-Core/FC-Estimator)** (`95%` accurate pre-build sizing), **[`Build Law`](https://github.com/Tianxia-Core/Build-Law)** (`5.0×–8.8×` token efficiency across 20+ IDEs/agents), and **[`nimbus²`](https://github.com/Tianxia-Core/nimbus2)** (`nimbus2 ship` + `$0.00` 14-Gate PR review).
- **CTOs & B2B Engineering Leaders:** Need similar `Rust`/`Go`/`Nix`/Security/FinOps rigor applied to your infrastructure? Scope a fixed-price **72-Hour `VRTTI` Architecture Sprint** at **[vrtti.rasaxmachina.com](https://vrtti.rasaxmachina.com)**.
- **Investors, Researchers, Press & Executive Hiring Committees:** Inspect cryptographic release proofs across **[`@Tianxia-Core`](https://github.com/Tianxia-Core)**, press assets in **[`@Tianxia-Presence/brand-kit`](https://github.com/Tianxia-Presence/brand-kit)**, commercial suites in **[`@Tianxia-Revenues`](https://github.com/Tianxia-Revenues)**, and founder dossier at **[rasaxmachina.com/collins](https://rasaxmachina.com/collins)**.

### 🔗 Composable Sovereign Stack — Works Natively With (`@Tianxia-Core` · `@Tianxia-Presence` · `@Tianxia-Revenues`)

Every tool in the **RASA-X-MACHINA** ecosystem is standalone (`0` lock-in bloat), yet designed to compose seamlessly across pre-build sizing, IDE governance, polyglot compilation, security custody, and autonomous operations:

| Lifecycle Layer | Companion Tool(s) | How They Work Together |
| :--- | :--- | :--- |
| **Pre-Build Sizing & FinOps** | **[`FC-Estimator`](https://github.com/Tianxia-Core/FC-Estimator)** (`MIT`) | Sizes `ceil(FC / 8)` microservice bounds, active build minutes (`95.0%` accuracy) & `8.8×` EUR token savings before coding. |
| **Constitutional Governance** | **[`Build Law`](https://github.com/Tianxia-Core/Build-Law)** (`MIT`) | Embeds the 4-Pillar, 14-Gate rules & `< 5 ms` `$0.00` static verifier across Claude, Cursor, VS Code, OpenCode & MCP. |
| **Executive Build, PR & Proxy Manager** | **[`nimbus²`](https://github.com/Tianxia-Core/nimbus2)** (`MPL-2.0`) & **[`GitGate`](https://github.com/Tianxia-Core/GitGate)** (`MIT`) | Runs `gitgate` / `nimbus2 ship`, zero-token 14-Gate `review-diff`, `init-clean` zero-PII seeding & high-concurrency TLS 1.3 proxy routing. |
| **Polyglot Wire Contracts** | **[`Jivascriptocle`](https://github.com/Tianxia-Core/Jivascriptocle)** (`Apache-2.0`) | Compiles single `.jiva` contracts into synchronized `Rust`, `Zig`, `OCaml`, `TypeScript`, `Nix` & compact `TOON` schemas. |
| **DevSecOps & Secret Enclave** | **[`AegisScan`](https://github.com/Tianxia-Core/AegisScan)** & **[`AetherVault`](https://github.com/Tianxia-Core/AetherVault)** (`MIT`) | 8-domain static supply-chain/prompt-injection scanner paired with `AES-256-GCM` `chmod 0600` runtime secret custody. |
| **Sovereign OS, Firewall & Mesh** | **[`TianxiaOS`](https://github.com/Tianxia-Core/TianxiaOS)** · **[`Faery-Fortress`](https://github.com/Tianxia-Core/Faery-Fortress)** · **[`tianxia-mobile`](https://github.com/Tianxia-Core/tianxia-mobile)** | Declarative NixOS operating substrate, `< 4 µs` `AF_XDP` + Rosenpass post-quantum firewall & signed Android ARM64 mesh node. |
| **Intelligence, Clearing, Ledger & Logistics** | **[`Ndimmorwyn`](https://github.com/Tianxia-Core/Ndimmorwyn)** · **[`AlatyrAtal`](https://github.com/Tianxia-Core/AlatyrAtal)** · **[`Tetraledger`](https://github.com/Tianxia-Core/Tetraledger)** · **[`MURUA`](https://github.com/Tianxia-Core/MURUA)** · **[`Scour`](https://github.com/Tianxia-Core/Scour)** | Constructal `-79.6%` router + `EjAwen` CRM, 4-Stratum `EFEMERA→ETAMANGA` clearinghouse, 4-way `x402` ledger, postal telemetry & signal radar. |
| **Press Assets & B2B Sprints** | **[`@Tianxia-Presence/brand-kit`](https://github.com/Tianxia-Presence/brand-kit)** & **[`@Tianxia-Revenues`](https://github.com/Tianxia-Revenues)** | Official vector identity/design tokens (`WCAG 2.2 AA`) and fixed-scope **72h `VRTTI` Architecture Sprints** at [rasaxmachina.com](https://rasaxmachina.com). |

<!-- BUILD_LAW_SHOWCASE_END -->

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
