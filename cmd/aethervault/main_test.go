// ffp: FFP-SECRETS-VAULT-TEST crypto-signer go
package main

import (
	"os"
	"testing"
)

func TestVaultLifecycleAndAuditIntegrity(t *testing.T) {
	dir := t.TempDir()
	store := NewVaultStore(dir)
	pw := "Sovereign-Vault-UnitTest-Passphrase-2026!"

	if err := store.Init(pw, false); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	if err := store.Set(pw, "api_token", "live-value-987654", map[string]string{"tier": "core"}); err != nil {
		t.Fatalf("Set failed: %v", err)
	}
	if err := store.Set(pw, "db_url", "postgres://db.internal:5432/vault", nil); err != nil {
		t.Fatalf("Set 2 failed: %v", err)
	}

	got, err := store.Get(pw, "api_token")
	if err != nil || got != "live-value-987654" {
		t.Fatalf("Get mismatch: got=%q err=%v", got, err)
	}

	items, err := store.List(pw)
	if err != nil || len(items) != 2 {
		t.Fatalf("List expected 2 items, got %d (err=%v)", len(items), err)
	}

	summary, err := store.Verify(pw)
	if err != nil || !summary.Verified || summary.SecretsChecked != 2 {
		t.Fatalf("Verify failed: %+v err=%v", summary, err)
	}

	if err := store.Shred(pw, "db_url", false); err != nil {
		t.Fatalf("Shred failed: %v", err)
	}
	if _, err := store.Get(pw, "db_url"); err == nil {
		t.Fatal("expected deleted secret Get to fail")
	}

	if _, err := store.Get("wrong-passphrase", "api_token"); err == nil {
		t.Fatal("expected wrong passphrase to fail")
	}
}

func TestTamperDetectionOnEnvelopeAndAudit(t *testing.T) {
	dir := t.TempDir()
	store := NewVaultStore(dir)
	pw := "Tamper-Detection-Passphrase-2026!"

	if err := store.Init(pw, false); err != nil {
		t.Fatal(err)
	}
	if err := store.Set(pw, "root_seed", "seed-material-xyz", nil); err != nil {
		t.Fatal(err)
	}

	// Corrupt audit log and verify fail-closed detection
	f, err := os.OpenFile(store.AuditPath, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("{\"timestamp\":\"2026-01-01T00:00:00Z\",\"operation\":\"forged\",\"key\":\"x\",\"success\":true,\"prev_hmac\":\"bad\",\"entry_hmac\":\"bad\"}\n")
	_ = f.Close()

	if _, err := store.Verify(pw); err == nil {
		t.Fatal("expected Verify to detect tampered audit log")
	}

	// Corrupt envelope ciphertext and verify fail-closed detection
	raw, err := os.ReadFile(store.EnvelopePath)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xff
	if err := os.WriteFile(store.EnvelopePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(pw, "root_seed"); err == nil {
		t.Fatal("expected Get to fail on corrupted AEAD tag")
	}
}
