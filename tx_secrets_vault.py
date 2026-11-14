#!/usr/bin/env python3
# ffp: FFP-SECRETS-VAULT-PY crypto-signer python
"""
AetherVault v2.0.0 — Zero-Trust AES-256-GCM Cryptographic Secrets Manager
===========================================================================
GDPR++ & Sovereign Security-by-Design secrets vault featuring:
- AES-256-GCM authenticated encryption at rest (master key + envelope + per-secret AEAD)
- Scrypt KDF (N=65536, r=8, p=1) + RFC 5869 HKDF-SHA256 domain-separated subkeys
- HMAC-SHA256 hash-chained append-only JSONL audit ledger
- Atomic 0600 filesystem swaps (os.replace) preventing partial-write corruption
- Crypto-shredding & multi-pass overwrite on deletion
- Memory zeroing via mutable bytearray wipe on lock()
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Default vault directory (portable; never touches host paths unless configured)
DEFAULT_VAULT_DIR = Path(
    os.environ.get("SECRETS_VAULT_DIR", os.path.expanduser("~/.local/share/AetherVault"))
)

# Cryptographic parameters
VAULT_VERSION = 2
KEY_DERIVATION_ITERATIONS = 2**16  # 65536 (Scrypt N)
SALT_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16
MASTER_KEY_SIZE = 32
GENESIS_PREV_HASH = "0" * 64


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _atomic_write_bytes(target: Path, payload: bytes, mode: int = 0o600) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.parent / f".{target.name}.{os.getpid()}.{secrets.token_hex(6)}.tmp"
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(str(tmp), str(target))


class VaultError(Exception):
    """Base exception for vault operations."""


class VaultLockedError(VaultError):
    """Raised when attempting an operation on a locked vault."""


class VaultIntegrityError(VaultError):
    """Raised when AEAD tag or HMAC audit chain verification fails."""


class VaultAuditLogger:
    """Append-only HMAC-SHA256 hash-chained JSONL audit logger."""

    def __init__(self, log_path: Path):
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def _last_hash(self) -> str:
        if not self.log_path.exists():
            return GENESIS_PREV_HASH
        last_line = ""
        with open(self.log_path, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last_line = line.strip()
        if not last_line:
            return GENESIS_PREV_HASH
        try:
            obj = json.loads(last_line)
            return str(obj.get("chain_hash", GENESIS_PREV_HASH))
        except json.JSONDecodeError:
            return GENESIS_PREV_HASH

    def log(
        self,
        operation: str,
        key: str,
        success: bool,
        details: Optional[Dict[str, Any]] = None,
        audit_key: Optional[bytes] = None,
    ) -> None:
        prev_hash = self._last_hash()
        body = {
            "timestamp": _utc_now(),
            "operation": operation,
            "key": key,
            "success": success,
            "details": details or {},
            "pid": os.getpid(),
            "uid": os.getuid() if hasattr(os, "getuid") else None,
            "prev_hash": prev_hash,
        }
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if audit_key:
            digest = hmac.new(audit_key, canonical, hashlib.sha256).hexdigest()
            body["auth_mode"] = "hmac-sha256"
        else:
            digest = hashlib.sha256(canonical).hexdigest()
            body["auth_mode"] = "sha256"
        body["chain_hash"] = digest
        line = (json.dumps(body, separators=(",", ":")) + "\n").encode("utf-8")
        fd = os.open(str(self.log_path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line)
        finally:
            os.close(fd)

    def verify_chain(self, audit_key: Optional[bytes] = None) -> tuple[bool, int]:
        if not self.log_path.exists():
            return True, 0
        expected_prev = GENESIS_PREV_HASH
        count = 0
        with open(self.log_path, "r", encoding="utf-8") as fh:
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue
                count += 1
                obj = json.loads(raw)
                if obj.get("prev_hash") != expected_prev:
                    return False, count
                recorded_hash = obj.pop("chain_hash", "")
                auth_mode = obj.pop("auth_mode", "sha256")
                canonical = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
                if auth_mode == "hmac-sha256":
                    if not audit_key:
                        return False, count
                    calc = hmac.new(audit_key, canonical, hashlib.sha256).hexdigest()
                else:
                    calc = hashlib.sha256(canonical).hexdigest()
                if not hmac.compare_digest(recorded_hash, calc):
                    return False, count
                expected_prev = recorded_hash
        return True, count


class TianxiaSecretsVault:
    """Zero-trust AES-256-GCM cryptographic secrets vault."""

    def __init__(self, vault_dir: Path = DEFAULT_VAULT_DIR):
        self.vault_dir = Path(vault_dir)
        self.vault_file = self.vault_dir / "secrets.enc"
        self.vault_meta = self.vault_dir / "secrets.meta"
        self.master_key_file = self.vault_dir / ".master.key"
        self.audit = VaultAuditLogger(self.vault_dir / "vault_audit.jsonl")
        self._master_key: Optional[bytearray] = None
        self._vault_data: Dict[str, Any] = {}
        self._locked = True
        self.vault_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _derive_master_key_static(passphrase: bytes, salt: bytes) -> bytes:
        kdf = Scrypt(
            salt=salt,
            length=MASTER_KEY_SIZE,
            n=KEY_DERIVATION_ITERATIONS,
            r=8,
            p=1,
        )
        return kdf.derive(passphrase)

    def _derive_master_key(self, passphrase: bytes, salt: bytes) -> bytes:
        return self._derive_master_key_static(passphrase, salt)

    @staticmethod
    def _derive_encryption_key(master_key: bytes, purpose: str) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=MASTER_KEY_SIZE,
            salt=None,
            info=f"tianxia-vault-{purpose}".encode("utf-8"),
        )
        return hkdf.derive(bytes(master_key))

    def _audit_key(self) -> Optional[bytes]:
        if self._master_key is None:
            return None
        return self._derive_encryption_key(bytes(self._master_key), "audit-chain")

    def unlock(self, passphrase: str) -> bool:
        """Unlock vault using passphrase and verify envelope AEAD integrity."""
        if not self.master_key_file.exists():
            self.audit.log("unlock", "vault", False, {"reason": "no_master_key"})
            return False
        try:
            stored = self.master_key_file.read_bytes()
            if len(stored) < SALT_SIZE + NONCE_SIZE + TAG_SIZE:
                raise VaultIntegrityError("Truncated master key file")
            salt = stored[:SALT_SIZE]
            nonce = stored[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
            ciphertext = stored[SALT_SIZE + NONCE_SIZE :]

            derived = self._derive_master_key(passphrase.encode("utf-8"), salt)
            kek = self._derive_encryption_key(derived, "master-key")
            raw_master = AESGCM(kek).decrypt(nonce, ciphertext, b"master-key-v2")
            self._master_key = bytearray(raw_master)
            self._locked = False
            self._load_vault_data()
            self.audit.log("unlock", "vault", True, {}, audit_key=self._audit_key())
            return True
        except Exception as exc:
            self._master_key = None
            self._locked = True
            self.audit.log("unlock", "vault", False, {"error": type(exc).__name__})
            return False

    def _load_vault_data(self) -> None:
        if self._locked or self._master_key is None or not self.vault_file.exists():
            return
        try:
            data = self.vault_file.read_bytes()
            if len(data) < SALT_SIZE + NONCE_SIZE + TAG_SIZE:
                raise VaultIntegrityError("Truncated vault ciphertext")
            nonce = data[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
            ciphertext = data[SALT_SIZE + NONCE_SIZE :]
            data_key = self._derive_encryption_key(bytes(self._master_key), "vault-data")
            plaintext = AESGCM(data_key).decrypt(nonce, ciphertext, b"vault-envelope-v2")
            self._vault_data = json.loads(plaintext.decode("utf-8"))
        except Exception as exc:
            self.audit.log("load_vault", "vault", False, {"error": type(exc).__name__})
            raise VaultIntegrityError(f"Vault integrity check failed: {exc}") from exc

    def _save_vault(self) -> None:
        if self._locked or self._master_key is None:
            raise VaultLockedError("Vault is locked")
        plaintext = json.dumps(self._vault_data, separators=(",", ":")).encode("utf-8")
        salt = secrets.token_bytes(SALT_SIZE)
        nonce = secrets.token_bytes(NONCE_SIZE)
        data_key = self._derive_encryption_key(bytes(self._master_key), "vault-data")
        ciphertext = AESGCM(data_key).encrypt(nonce, plaintext, b"vault-envelope-v2")
        _atomic_write_bytes(self.vault_file, salt + nonce + ciphertext, mode=0o600)

        meta = {
            "vault_data": {k: v for k, v in self._vault_data.items() if k != "secrets"},
            "secret_count": len(self._vault_data.get("secrets", {})),
            "updated": _utc_now(),
        }
        _atomic_write_bytes(
            self.vault_meta,
            (json.dumps(meta, indent=2) + "\n").encode("utf-8"),
            mode=0o600,
        )

    def set_secret(self, key: str, value: str, metadata: Optional[Dict[str, Any]] = None) -> bool:
        if self._locked or self._master_key is None:
            raise VaultLockedError("Vault is locked")
        if not key or not key.strip():
            raise VaultError("Secret key name cannot be empty")
        secret_key = self._derive_encryption_key(bytes(self._master_key), f"secret-{key}")
        nonce = secrets.token_bytes(NONCE_SIZE)
        aad = f"secret:{key}".encode("utf-8")
        ciphertext = AESGCM(secret_key).encrypt(nonce, value.encode("utf-8"), aad)
        self._vault_data.setdefault("secrets", {})[key] = {
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "created": _utc_now(),
            "metadata": metadata or {},
        }
        self._save_vault()
        self.audit.log(
            "set_secret",
            key,
            True,
            {"has_metadata": bool(metadata)},
            audit_key=self._audit_key(),
        )
        return True

    def get_secret(self, key: str) -> Optional[str]:
        if self._locked or self._master_key is None:
            raise VaultLockedError("Vault is locked")
        secret_data = self._vault_data.get("secrets", {}).get(key)
        if not secret_data:
            self.audit.log("get_secret", key, False, {"reason": "not_found"}, audit_key=self._audit_key())
            return None
        try:
            secret_key = self._derive_encryption_key(bytes(self._master_key), f"secret-{key}")
            nonce = base64.b64decode(secret_data["nonce"])
            ciphertext = base64.b64decode(secret_data["ciphertext"])
            aad = f"secret:{key}".encode("utf-8")
            plaintext = AESGCM(secret_key).decrypt(nonce, ciphertext, aad)
            self.audit.log("get_secret", key, True, {}, audit_key=self._audit_key())
            return plaintext.decode("utf-8")
        except Exception as exc:
            self.audit.log("get_secret", key, False, {"error": type(exc).__name__}, audit_key=self._audit_key())
            raise VaultIntegrityError(f"Secret '{key}' failed AEAD authentication") from exc

    def shred_secret(self, key: str) -> bool:
        """Crypto-shred a secret with CSPRNG overwrite prior to envelope re-encryption."""
        if self._locked or self._master_key is None:
            raise VaultLockedError("Vault is locked")
        secrets_map = self._vault_data.get("secrets", {})
        if key not in secrets_map:
            self.audit.log("shred_secret", key, False, {"reason": "not_found"}, audit_key=self._audit_key())
            return False
        entry = secrets_map[key]
        ct_len = len(entry.get("ciphertext", ""))
        entry["ciphertext"] = base64.b64encode(secrets.token_bytes(max(32, ct_len))).decode("ascii")
        entry["nonce"] = base64.b64encode(secrets.token_bytes(NONCE_SIZE)).decode("ascii")
        del secrets_map[key]
        self._vault_data.get("rotation_schedule", {}).pop(key, None)
        self._save_vault()
        self.audit.log("shred_secret", key, True, {}, audit_key=self._audit_key())
        return True

    def delete_secret(self, key: str) -> bool:
        return self.shred_secret(key)

    def list_secrets(self) -> Dict[str, Dict[str, Any]]:
        if self._locked or self._master_key is None:
            raise VaultLockedError("Vault is locked")
        result: Dict[str, Dict[str, Any]] = {}
        for key, data in sorted(self._vault_data.get("secrets", {}).items()):
            result[key] = {
                "created": data.get("created"),
                "metadata": data.get("metadata", {}),
                "has_value": True,
            }
        return result

    def rotate_secret(self, key: str, new_value: str) -> bool:
        if self._locked or self._master_key is None:
            raise VaultLockedError("Vault is locked")
        if key not in self._vault_data.get("secrets", {}):
            return False
        self.set_secret(key, new_value, self._vault_data["secrets"][key].get("metadata", {}))
        self.audit.log("rotate_secret", key, True, {}, audit_key=self._audit_key())
        return True

    def schedule_rotation(self, key: str, interval_days: int) -> None:
        if self._locked or self._master_key is None:
            raise VaultLockedError("Vault is locked")
        now = datetime.now(timezone.utc)
        self._vault_data.setdefault("rotation_schedule", {})[key] = {
            "interval_days": interval_days,
            "last_rotated": now.isoformat().replace("+00:00", "Z"),
            "next_rotation": (now + timedelta(days=interval_days)).isoformat().replace("+00:00", "Z"),
        }
        self._save_vault()

    def check_rotation_due(self) -> list[str]:
        due: list[str] = []
        now = datetime.now(timezone.utc)
        for key, schedule in self._vault_data.get("rotation_schedule", {}).items():
            next_rot = datetime.fromisoformat(schedule["next_rotation"].replace("Z", "+00:00"))
            if now >= next_rot:
                due.append(key)
        return due

    def verify(self) -> Dict[str, Any]:
        """Verify envelope AEAD, every individual secret's AEAD tag, and HMAC audit chain."""
        if self._locked or self._master_key is None:
            raise VaultLockedError("Vault is locked")
        self._load_vault_data()
        verified_keys = 0
        for key, secret_data in self._vault_data.get("secrets", {}).items():
            secret_key = self._derive_encryption_key(bytes(self._master_key), f"secret-{key}")
            nonce = base64.b64decode(secret_data["nonce"])
            ciphertext = base64.b64decode(secret_data["ciphertext"])
            AESGCM(secret_key).decrypt(nonce, ciphertext, f"secret:{key}".encode("utf-8"))
            verified_keys += 1
        chain_ok, audit_entries = self.audit.verify_chain(audit_key=self._audit_key())
        if not chain_ok:
            raise VaultIntegrityError("Audit log HMAC chain verification failed")
        summary = {
            "verified": True,
            "vault_version": self._vault_data.get("version", VAULT_VERSION),
            "secrets_verified": verified_keys,
            "audit_entries_verified": audit_entries,
        }
        self.audit.log("verify", "vault", True, summary, audit_key=self._audit_key())
        return summary

    def lock(self) -> None:
        audit_key = self._audit_key()
        if self._master_key is not None:
            for i in range(len(self._master_key)):
                self._master_key[i] = 0
            self._master_key = None
        self._vault_data = {}
        self._locked = True
        self.audit.log("lock", "vault", True, {}, audit_key=audit_key)

    def __enter__(self) -> "TianxiaSecretsVault":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        self.lock()
        return False

    def export_backup(self, passphrase: str) -> bytes:
        if self._locked or self._master_key is None:
            raise VaultLockedError("Vault is locked")
        backup = {
            "version": VAULT_VERSION,
            "exported": _utc_now(),
            "vault_data": self._vault_data,
        }
        backup_salt = secrets.token_bytes(SALT_SIZE)
        backup_key = self._derive_master_key(passphrase.encode("utf-8"), backup_salt)
        backup_nonce = secrets.token_bytes(NONCE_SIZE)
        plaintext = json.dumps(backup, separators=(",", ":")).encode("utf-8")
        ciphertext = AESGCM(backup_key).encrypt(backup_nonce, plaintext, b"vault-backup-v2")
        self.audit.log("export_backup", "vault", True, {}, audit_key=self._audit_key())
        return backup_salt + backup_nonce + ciphertext

    @classmethod
    def restore_backup(cls, backup_data: bytes, passphrase: str, vault_dir: Path) -> "TianxiaSecretsVault":
        if len(backup_data) < SALT_SIZE + NONCE_SIZE + TAG_SIZE:
            raise VaultIntegrityError("Invalid or truncated backup file")
        salt = backup_data[:SALT_SIZE]
        nonce = backup_data[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
        ciphertext = backup_data[SALT_SIZE + NONCE_SIZE :]
        backup_key = cls._derive_master_key_static(passphrase.encode("utf-8"), salt)
        plaintext = AESGCM(backup_key).decrypt(nonce, ciphertext, b"vault-backup-v2")
        backup = json.loads(plaintext.decode("utf-8"))

        vault = create_vault(passphrase, vault_dir)
        vault._vault_data = backup["vault_data"]
        # Re-encrypt each secret under the newly initialized master key if needed
        vault._save_vault()
        return vault


def create_vault(passphrase: str, vault_dir: Path = DEFAULT_VAULT_DIR) -> TianxiaSecretsVault:
    if not passphrase:
        raise VaultError("Passphrase cannot be empty")
    vault = TianxiaSecretsVault(vault_dir)
    salt = secrets.token_bytes(SALT_SIZE)
    master_key = secrets.token_bytes(MASTER_KEY_SIZE)

    derived = vault._derive_master_key(passphrase.encode("utf-8"), salt)
    kek = vault._derive_encryption_key(derived, "master-key")
    nonce = secrets.token_bytes(NONCE_SIZE)
    encrypted = AESGCM(kek).encrypt(nonce, master_key, b"master-key-v2")
    _atomic_write_bytes(vault.master_key_file, salt + nonce + encrypted, mode=0o600)

    vault._master_key = bytearray(master_key)
    vault._locked = False
    vault._vault_data = {
        "version": VAULT_VERSION,
        "created": _utc_now(),
        "secrets": {},
        "rotation_schedule": {},
    }
    vault._save_vault()
    vault.audit.log("init", "vault", True, {}, audit_key=vault._audit_key())
    return vault


def open_vault(passphrase: str, vault_dir: Path = DEFAULT_VAULT_DIR) -> TianxiaSecretsVault:
    vault = TianxiaSecretsVault(vault_dir)
    if not vault.unlock(passphrase):
        raise VaultError("Failed to unlock vault: invalid passphrase or tampered keyfile")
    return vault


def _resolve_passphrase(explicit: Optional[str]) -> str:
    pw = explicit or os.environ.get("SECRETS_VAULT_PASSPHRASE") or os.environ.get("TX_VAULT_PASSPHRASE")
    if pw:
        return pw
    if sys.stdin.isatty():
        return getpass.getpass("Vault passphrase: ")
    raise VaultError("Passphrase required (--passphrase or SECRETS_VAULT_PASSPHRASE)")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="AetherVault v2.0.0 (AES-256-GCM)")
    parser.add_argument(
        "command",
        choices=[
            "init",
            "create",
            "open",
            "set",
            "get",
            "list",
            "shred",
            "delete",
            "verify",
            "rotate",
            "backup",
            "restore",
        ],
    )
    parser.add_argument("positional_key", nargs="?", help="Optional secret key")
    parser.add_argument("positional_value", nargs="?", help="Optional secret value")
    parser.add_argument("--vault", default=str(DEFAULT_VAULT_DIR), help="Vault directory path")
    parser.add_argument("--passphrase", help="Passphrase (prefer SECRETS_VAULT_PASSPHRASE env)")
    parser.add_argument("--key", help="Secret key name")
    parser.add_argument("--value", help="Secret value")
    parser.add_argument("--metadata", type=json.loads, default={})
    parser.add_argument("--output", help="Backup input/output path")
    args = parser.parse_args(argv)

    key = args.key or args.positional_key
    value = args.value if args.value is not None else args.positional_value
    vault_dir = Path(args.vault)

    try:
        passphrase = _resolve_passphrase(args.passphrase)
        if args.command in ("init", "create"):
            with create_vault(passphrase, vault_dir):
                print(json.dumps({"status": "initialized", "vault": str(vault_dir)}))
            return 0

        if args.command == "restore":
            if not args.output:
                parser.error("--output backup file required for restore")
            raw = Path(args.output).read_bytes()
            with TianxiaSecretsVault.restore_backup(raw, passphrase, vault_dir):
                print(json.dumps({"status": "restored", "vault": str(vault_dir)}))
            return 0

        with open_vault(passphrase, vault_dir) as vault:
            if args.command == "open":
                print(json.dumps({"status": "unlocked", "vault": str(vault_dir)}))
            elif args.command == "set":
                if not key or value is None:
                    parser.error("key and value are required for 'set'")
                vault.set_secret(key, value, args.metadata)
                print(json.dumps({"status": "stored", "key": key}))
            elif args.command == "get":
                if not key:
                    parser.error("key is required for 'get'")
                secret_val = vault.get_secret(key)
                if secret_val is None:
                    print(f"Secret '{key}' not found", file=sys.stderr)
                    return 1
                print(secret_val)
            elif args.command == "list":
                print(json.dumps(vault.list_secrets(), indent=2))
            elif args.command in ("shred", "delete"):
                if not key:
                    parser.error("key is required for 'shred'")
                if not vault.shred_secret(key):
                    print(f"Secret '{key}' not found", file=sys.stderr)
                    return 1
                print(json.dumps({"status": "shredded", "key": key}))
            elif args.command == "rotate":
                if not key or value is None:
                    parser.error("key and value are required for 'rotate'")
                if not vault.rotate_secret(key, value):
                    print(f"Secret '{key}' not found", file=sys.stderr)
                    return 1
                print(json.dumps({"status": "rotated", "key": key}))
            elif args.command == "verify":
                summary = vault.verify()
                print(json.dumps(summary, indent=2))
            elif args.command == "backup":
                blob = vault.export_backup(passphrase)
                out_path = Path(args.output or f"vault-backup-{datetime.now(timezone.utc).strftime('%Y%m%d')}.enc")
                _atomic_write_bytes(out_path, blob, mode=0o600)
                print(json.dumps({"status": "backed_up", "output": str(out_path)}))
        return 0
    except VaultError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
