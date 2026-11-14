# Changelog

All notable changes to `AetherVault` are documented in this file.

## [2.0.0] - 2026-11-12

### Added
- Zero-dependency static Go CLI (`cmd/aethervault`, `CGO_ENABLED=0`) implementing AES-256-GCM + PBKDF2-HMAC-SHA256 (`210,000` iterations) + RFC 5869 HKDF-SHA256 + HMAC-SHA256 chained audit logs across `init`, `set`, `get`, `list`, `shred`, `verify`, `rotate`, and `version`.
- Signed cross-platform release executables for Linux (`x86_64`, `aarch64`), Windows (`x86_64.exe`), and Android (`aarch64`), accompanied by `SHA256SUMS` and CycloneDX `SBOM.cdx.json`.
- End-to-end Python & Go unit test suites covering lifecycle operations and fail-closed tamper detection.
- Full Enterprise Governance (`SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, GitHub Actions CI, Dependabot).

### Fixed
- Fixed `export_backup()` salt variable bug and `restore_backup()` master-key initialization in `tx_secrets_vault.py`.
- Scoped `vault_audit.jsonl` inside the target `vault_dir` rather than a hardcoded host path, and switched all file persistence to atomic `0600` `os.replace()` swaps.
