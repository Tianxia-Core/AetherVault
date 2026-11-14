# ffp: FFP-SECRETS-VAULT-PY-TEST crypto-signer python
"""Unit tests for tx_secrets_vault.py v2.0.0."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import tx_secrets_vault as sv  # noqa: E402


class TestSecretsVaultPython(unittest.TestCase):
    def test_lifecycle_init_set_get_list_verify_shred(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vdir = Path(tmp) / "vault"
            pw = "Correct-Horse-Battery-Staple-2026!"
            with sv.create_vault(pw, vdir) as vault:
                vault.set_secret("db_dsn", "postgres://app@localhost:5432/prod", {"env": "prod"})
                vault.set_secret("signing_seed", "hex-seed-material-998877")
                self.assertEqual(vault.get_secret("db_dsn"), "postgres://app@localhost:5432/prod")
                listed = vault.list_secrets()
                self.assertIn("db_dsn", listed)
                self.assertIn("signing_seed", listed)
                summary = vault.verify()
                self.assertTrue(summary["verified"])
                self.assertEqual(summary["secrets_verified"], 2)

            with sv.open_vault(pw, vdir) as vault2:
                self.assertTrue(vault2.rotate_secret("db_dsn", "postgres://app@localhost:5432/prod_v2"))
                self.assertEqual(vault2.get_secret("db_dsn"), "postgres://app@localhost:5432/prod_v2")
                self.assertTrue(vault2.shred_secret("signing_seed"))
                self.assertIsNone(vault2.get_secret("signing_seed"))
                blob = vault2.export_backup(pw)
                self.assertGreater(len(blob), 64)

            with self.assertRaises(sv.VaultError):
                sv.open_vault("wrong-passphrase", vdir)

    def test_tamper_detection_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vdir = Path(tmp) / "vault"
            pw = "Tamper-Check-Passphrase-2026!"
            with sv.create_vault(pw, vdir) as vault:
                vault.set_secret("k1", "v1")
            enc_file = vdir / "secrets.enc"
            raw = bytearray(enc_file.read_bytes())
            raw[-1] ^= 0xFF
            enc_file.write_bytes(bytes(raw))
            with self.assertRaises(sv.VaultError):
                sv.open_vault(pw, vdir)


if __name__ == "__main__":
    unittest.main()
