// ffp: FFP-SECRETS-VAULT crypto-signer go
package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	Version            = "2.1.0"
	SaltSize           = 32
	NonceSize          = 12
	KeySize            = 32
	PBKDF2Iterations   = 210000 // OWASP 2026 PBKDF2-HMAC-SHA256 baseline
	MagicHeader        = "SVLT2\x00"
	GenesisAuditDigest = "0000000000000000000000000000000000000000000000000000000000000000"
)

type SecretRecord struct {
	Nonce      string            `json:"nonce"`
	Ciphertext string            `json:"ciphertext"`
	Created    string            `json:"created"`
	Updated    string            `json:"updated"`
	Rotations  int               `json:"rotations"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type VaultEnvelope struct {
	Version int                     `json:"version"`
	Created string                  `json:"created"`
	Updated string                  `json:"updated"`
	Secrets map[string]SecretRecord `json:"secrets"`
}

type AuditRecord struct {
	Timestamp string `json:"timestamp"`
	Operation string `json:"operation"`
	Key       string `json:"key"`
	Success   bool   `json:"success"`
	PrevHMAC  string `json:"prev_hmac"`
	EntryHMAC string `json:"entry_hmac"`
}

type VerifySummary struct {
	Verified       bool   `json:"verified"`
	VaultPath      string `json:"vault_path"`
	VaultVersion   int    `json:"vault_version"`
	SecretsChecked int    `json:"secrets_checked"`
	AuditEntries   int    `json:"audit_entries"`
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// pbkdf2SHA256 implements RFC 8018 PBKDF2-HMAC-SHA256 using 100% Go standard library.
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := func(key, data []byte) []byte {
		mac := hmac.New(sha256.New, key)
		mac.Write(data)
		return mac.Sum(nil)
	}
	hashLen := sha256.Size
	numBlocks := (keyLen + hashLen - 1) / hashLen
	out := make([]byte, 0, numBlocks*hashLen)
	var blockIdx [4]byte
	u := make([]byte, hashLen)
	t := make([]byte, hashLen)

	saltBlock := make([]byte, len(salt)+4)
	copy(saltBlock, salt)

	for block := 1; block <= numBlocks; block++ {
		binary.BigEndian.PutUint32(blockIdx[:], uint32(block))
		copy(saltBlock[len(salt):], blockIdx[:])
		first := prf(password, saltBlock)
		copy(u, first)
		copy(t, first)
		zeroBytes(first)
		for i := 2; i <= iter; i++ {
			next := prf(password, u)
			copy(u, next)
			zeroBytes(next)
			for j := 0; j < hashLen; j++ {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	zeroBytes(u)
	zeroBytes(t)
	return out[:keyLen]
}

// hkdfSHA256 implements RFC 5869 HKDF Extract-and-Expand using 100% Go standard library.
func hkdfSHA256(ikm, salt, info []byte, length int) ([]byte, error) {
	if length <= 0 || length > 255*sha256.Size {
		return nil, errors.New("invalid HKDF output length")
	}
	actualSalt := salt
	if len(actualSalt) == 0 {
		actualSalt = make([]byte, sha256.Size)
	}
	extract := hmac.New(sha256.New, actualSalt)
	extract.Write(ikm)
	prk := extract.Sum(nil)
	defer zeroBytes(prk)

	var okm []byte
	var prev []byte
	counter := byte(1)
	for len(okm) < length {
		expand := hmac.New(sha256.New, prk)
		expand.Write(prev)
		expand.Write(info)
		expand.Write([]byte{counter})
		prev = expand.Sum(nil)
		okm = append(okm, prev...)
		counter++
	}
	res := make([]byte, length)
	copy(res, okm[:length])
	zeroBytes(okm)
	zeroBytes(prev)
	return res, nil
}

func sealAESGCM(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = aead.Seal(nil, nonce, plaintext, aad)
	return nonce, ciphertext, nil
}

func openAESGCM(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("invalid GCM nonce length")
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}

func atomicWrite0600(target string, data []byte) error {
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var rnd [6]byte
	_, _ = rand.Read(rnd[:])
	tmp := filepath.Join(dir, fmt.Sprintf(".%s.%x.tmp", filepath.Base(target), rnd[:]))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, target)
}

type VaultStore struct {
	Dir           string
	MasterKeyPath string
	EnvelopePath  string
	AuditPath     string
}

func NewVaultStore(dir string) VaultStore {
	return VaultStore{
		Dir:           dir,
		MasterKeyPath: filepath.Join(dir, ".master.key"),
		EnvelopePath:  filepath.Join(dir, "vault.svlt"),
		AuditPath:     filepath.Join(dir, "vault_audit.jsonl"),
	}
}

func computeAuditMAC(auditKey []byte, ts, op, key string, success bool, prev string) string {
	mac := hmac.New(sha256.New, auditKey)
	fmt.Fprintf(mac, "%s|%s|%s|%t|%s", ts, op, key, success, prev)
	return hex.EncodeToString(mac.Sum(nil))
}

func (vs VaultStore) appendAudit(masterKey []byte, op, key string, success bool) error {
	auditKey, err := hkdfSHA256(masterKey, nil, []byte("AetherVault-audit-v2"), KeySize)
	if err != nil {
		return err
	}
	defer zeroBytes(auditKey)

	prev := GenesisAuditDigest
	if raw, err := os.ReadFile(vs.AuditPath); err == nil {
		lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
		for i := len(lines) - 1; i >= 0; i-- {
			l := strings.TrimSpace(lines[i])
			if l == "" {
				continue
			}
			var rec AuditRecord
			if json.Unmarshal([]byte(l), &rec) == nil && rec.EntryHMAC != "" {
				prev = rec.EntryHMAC
				break
			}
		}
	}

	ts := time.Now().UTC().Format(time.RFC3339)
	entryMAC := computeAuditMAC(auditKey, ts, op, key, success, prev)
	rec := AuditRecord{
		Timestamp: ts,
		Operation: op,
		Key:       key,
		Success:   success,
		PrevHMAC:  prev,
		EntryHMAC: entryMAC,
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(vs.AuditPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(b, '\n'))
	return err
}

func (vs VaultStore) verifyAuditChain(masterKey []byte) (int, error) {
	f, err := os.Open(vs.AuditPath)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()

	auditKey, err := hkdfSHA256(masterKey, nil, []byte("AetherVault-audit-v2"), KeySize)
	if err != nil {
		return 0, err
	}
	defer zeroBytes(auditKey)

	prev := GenesisAuditDigest
	count := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		count++
		var rec AuditRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return count, fmt.Errorf("corrupt audit entry at line %d: %w", count, err)
		}
		if rec.PrevHMAC != prev {
			return count, fmt.Errorf("broken audit chain link at line %d", count)
		}
		expected := computeAuditMAC(auditKey, rec.Timestamp, rec.Operation, rec.Key, rec.Success, rec.PrevHMAC)
		if !hmac.Equal([]byte(expected), []byte(rec.EntryHMAC)) {
			return count, fmt.Errorf("audit HMAC mismatch at line %d", count)
		}
		prev = rec.EntryHMAC
	}
	return count, sc.Err()
}

func (vs VaultStore) Init(passphrase string, force bool) error {
	if passphrase == "" {
		return errors.New("passphrase must not be empty")
	}
	if !force {
		if _, err := os.Stat(vs.EnvelopePath); err == nil {
			return errors.New("vault already exists (pass -force to re-initialize)")
		}
	}
	if err := os.MkdirAll(vs.Dir, 0o700); err != nil {
		return err
	}

	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	masterKey := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, masterKey); err != nil {
		return err
	}
	defer zeroBytes(masterKey)

	pwBytes := []byte(passphrase)
	derived := pbkdf2SHA256(pwBytes, salt, PBKDF2Iterations, KeySize)
	zeroBytes(pwBytes)
	defer zeroBytes(derived)

	kek, err := hkdfSHA256(derived, salt, []byte("AetherVault-kek-v2"), KeySize)
	if err != nil {
		return err
	}
	defer zeroBytes(kek)

	nonce, ct, err := sealAESGCM(kek, masterKey, []byte(MagicHeader+"master-key"))
	if err != nil {
		return err
	}
	keyBlob := make([]byte, 0, len(MagicHeader)+SaltSize+NonceSize+len(ct))
	keyBlob = append(keyBlob, []byte(MagicHeader)...)
	keyBlob = append(keyBlob, salt...)
	keyBlob = append(keyBlob, nonce...)
	keyBlob = append(keyBlob, ct...)
	if err := atomicWrite0600(vs.MasterKeyPath, keyBlob); err != nil {
		return err
	}

	if force {
		_ = os.Remove(vs.AuditPath)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	env := VaultEnvelope{
		Version: 2,
		Created: now,
		Updated: now,
		Secrets: map[string]SecretRecord{},
	}
	if err := vs.saveEnvelope(masterKey, env); err != nil {
		return err
	}
	return vs.appendAudit(masterKey, "init", "vault", true)
}

func (vs VaultStore) unlockMasterKey(passphrase string) ([]byte, error) {
	raw, err := os.ReadFile(vs.MasterKeyPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read master key: %w", err)
	}
	hdrLen := len(MagicHeader)
	if len(raw) < hdrLen+SaltSize+NonceSize+16 || string(raw[:hdrLen]) != MagicHeader {
		return nil, errors.New("invalid or unsupported master key format")
	}
	salt := raw[hdrLen : hdrLen+SaltSize]
	nonce := raw[hdrLen+SaltSize : hdrLen+SaltSize+NonceSize]
	ct := raw[hdrLen+SaltSize+NonceSize:]

	pwBytes := []byte(passphrase)
	derived := pbkdf2SHA256(pwBytes, salt, PBKDF2Iterations, KeySize)
	zeroBytes(pwBytes)
	defer zeroBytes(derived)

	kek, err := hkdfSHA256(derived, salt, []byte("AetherVault-kek-v2"), KeySize)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(kek)

	mk, err := openAESGCM(kek, nonce, ct, []byte(MagicHeader+"master-key"))
	if err != nil {
		return nil, errors.New("authentication failed: invalid passphrase or tampered master key")
	}
	return mk, nil
}

func (vs VaultStore) saveEnvelope(masterKey []byte, env VaultEnvelope) error {
	env.Updated = time.Now().UTC().Format(time.RFC3339)
	plain, err := json.Marshal(env)
	if err != nil {
		return err
	}
	defer zeroBytes(plain)

	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	dek, err := hkdfSHA256(masterKey, salt, []byte("AetherVault-envelope-v2"), KeySize)
	if err != nil {
		return err
	}
	defer zeroBytes(dek)

	nonce, ct, err := sealAESGCM(dek, plain, []byte(MagicHeader+"envelope"))
	if err != nil {
		return err
	}
	blob := make([]byte, 0, len(MagicHeader)+SaltSize+NonceSize+len(ct))
	blob = append(blob, []byte(MagicHeader)...)
	blob = append(blob, salt...)
	blob = append(blob, nonce...)
	blob = append(blob, ct...)
	return atomicWrite0600(vs.EnvelopePath, blob)
}

func (vs VaultStore) loadEnvelope(masterKey []byte) (VaultEnvelope, error) {
	raw, err := os.ReadFile(vs.EnvelopePath)
	if err != nil {
		return VaultEnvelope{}, fmt.Errorf("cannot read vault envelope: %w", err)
	}
	hdrLen := len(MagicHeader)
	if len(raw) < hdrLen+SaltSize+NonceSize+16 || string(raw[:hdrLen]) != MagicHeader {
		return VaultEnvelope{}, errors.New("invalid or corrupted vault header")
	}
	salt := raw[hdrLen : hdrLen+SaltSize]
	nonce := raw[hdrLen+SaltSize : hdrLen+SaltSize+NonceSize]
	ct := raw[hdrLen+SaltSize+NonceSize:]

	dek, err := hkdfSHA256(masterKey, salt, []byte("AetherVault-envelope-v2"), KeySize)
	if err != nil {
		return VaultEnvelope{}, err
	}
	defer zeroBytes(dek)

	plain, err := openAESGCM(dek, nonce, ct, []byte(MagicHeader+"envelope"))
	if err != nil {
		return VaultEnvelope{}, errors.New("envelope AEAD integrity check failed (tampering detected)")
	}
	defer zeroBytes(plain)

	var env VaultEnvelope
	if err := json.Unmarshal(plain, &env); err != nil {
		return VaultEnvelope{}, err
	}
	if env.Secrets == nil {
		env.Secrets = map[string]SecretRecord{}
	}
	return env, nil
}

func (vs VaultStore) Set(passphrase, key, value string, meta map[string]string) error {
	if strings.TrimSpace(key) == "" {
		return errors.New("secret key name cannot be empty")
	}
	mk, err := vs.unlockMasterKey(passphrase)
	if err != nil {
		return err
	}
	defer zeroBytes(mk)

	env, err := vs.loadEnvelope(mk)
	if err != nil {
		return err
	}
	sKey, err := hkdfSHA256(mk, nil, []byte("secret-item:"+key), KeySize)
	if err != nil {
		return err
	}
	defer zeroBytes(sKey)

	valBytes := []byte(value)
	nonce, ct, err := sealAESGCM(sKey, valBytes, []byte("secret-aad:"+key))
	zeroBytes(valBytes)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	prev, existed := env.Secrets[key]
	created := now
	rotations := 0
	if existed {
		created = prev.Created
		rotations = prev.Rotations + 1
	}
	env.Secrets[key] = SecretRecord{
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
		Created:    created,
		Updated:    now,
		Rotations:  rotations,
		Metadata:   meta,
	}
	if err := vs.saveEnvelope(mk, env); err != nil {
		return err
	}
	return vs.appendAudit(mk, "set", key, true)
}

func (vs VaultStore) Get(passphrase, key string) (string, error) {
	mk, err := vs.unlockMasterKey(passphrase)
	if err != nil {
		return "", err
	}
	defer zeroBytes(mk)

	env, err := vs.loadEnvelope(mk)
	if err != nil {
		return "", err
	}
	rec, ok := env.Secrets[key]
	if !ok {
		_ = vs.appendAudit(mk, "get", key, false)
		return "", fmt.Errorf("secret %q not found", key)
	}
	sKey, err := hkdfSHA256(mk, nil, []byte("secret-item:"+key), KeySize)
	if err != nil {
		return "", err
	}
	defer zeroBytes(sKey)

	nonce, err := base64.StdEncoding.DecodeString(rec.Nonce)
	if err != nil {
		return "", err
	}
	ct, err := base64.StdEncoding.DecodeString(rec.Ciphertext)
	if err != nil {
		return "", err
	}
	plain, err := openAESGCM(sKey, nonce, ct, []byte("secret-aad:"+key))
	if err != nil {
		_ = vs.appendAudit(mk, "get", key, false)
		return "", errors.New("secret AEAD authentication failed")
	}
	out := string(plain)
	zeroBytes(plain)
	_ = vs.appendAudit(mk, "get", key, true)
	return out, nil
}

func (vs VaultStore) List(passphrase string) ([]map[string]any, error) {
	mk, err := vs.unlockMasterKey(passphrase)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(mk)

	env, err := vs.loadEnvelope(mk)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(env.Secrets))
	for k := range env.Secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		r := env.Secrets[k]
		out = append(out, map[string]any{
			"key":       k,
			"created":   r.Created,
			"updated":   r.Updated,
			"rotations": r.Rotations,
			"metadata":  r.Metadata,
		})
	}
	_ = vs.appendAudit(mk, "list", "vault", true)
	return out, nil
}

func (vs VaultStore) Shred(passphrase, key string, wipeAll bool) error {
	mk, err := vs.unlockMasterKey(passphrase)
	if err != nil {
		return err
	}
	defer zeroBytes(mk)

	if wipeAll {
		for _, p := range []string{vs.EnvelopePath, vs.MasterKeyPath, vs.AuditPath} {
			if st, err := os.Stat(p); err == nil && st.Size() > 0 {
				noise := make([]byte, st.Size())
				for pass := 0; pass < 3; pass++ {
					_, _ = rand.Read(noise)
					_ = os.WriteFile(p, noise, 0o600)
				}
				zeroBytes(noise)
				_ = os.Remove(p)
			}
		}
		return nil
	}

	env, err := vs.loadEnvelope(mk)
	if err != nil {
		return err
	}
	if _, ok := env.Secrets[key]; !ok {
		_ = vs.appendAudit(mk, "shred", key, false)
		return fmt.Errorf("secret %q not found", key)
	}
	noise := make([]byte, 64)
	_, _ = rand.Read(noise)
	env.Secrets[key] = SecretRecord{Ciphertext: base64.StdEncoding.EncodeToString(noise)}
	zeroBytes(noise)
	delete(env.Secrets, key)
	if err := vs.saveEnvelope(mk, env); err != nil {
		return err
	}
	return vs.appendAudit(mk, "shred", key, true)
}

func (vs VaultStore) Verify(passphrase string) (VerifySummary, error) {
	mk, err := vs.unlockMasterKey(passphrase)
	if err != nil {
		return VerifySummary{}, err
	}
	defer zeroBytes(mk)

	env, err := vs.loadEnvelope(mk)
	if err != nil {
		return VerifySummary{}, err
	}
	checked := 0
	for k, rec := range env.Secrets {
		sKey, err := hkdfSHA256(mk, nil, []byte("secret-item:"+k), KeySize)
		if err != nil {
			return VerifySummary{}, err
		}
		nonce, err := base64.StdEncoding.DecodeString(rec.Nonce)
		if err != nil {
			zeroBytes(sKey)
			return VerifySummary{}, fmt.Errorf("corrupt nonce for %q", k)
		}
		ct, err := base64.StdEncoding.DecodeString(rec.Ciphertext)
		if err != nil {
			zeroBytes(sKey)
			return VerifySummary{}, fmt.Errorf("corrupt ciphertext for %q", k)
		}
		plain, err := openAESGCM(sKey, nonce, ct, []byte("secret-aad:"+k))
		zeroBytes(sKey)
		zeroBytes(plain)
		if err != nil {
			return VerifySummary{}, fmt.Errorf("AEAD integrity check failed on secret %q", k)
		}
		checked++
	}
	auditCount, err := vs.verifyAuditChain(mk)
	if err != nil {
		return VerifySummary{}, err
	}
	_ = vs.appendAudit(mk, "verify", "vault", true)
	return VerifySummary{
		Verified:       true,
		VaultPath:      vs.Dir,
		VaultVersion:   env.Version,
		SecretsChecked: checked,
		AuditEntries:   auditCount,
	}, nil
}

func resolveVaultDir(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if env := os.Getenv("SECRETS_VAULT_DIR"); env != "" {
		return env
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".AetherVault"
	}
	return filepath.Join(home, ".local", "share", "AetherVault")
}

func resolvePassphrase(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if env := os.Getenv("SECRETS_VAULT_PASSPHRASE"); env != "" {
		return env, nil
	}
	if env := os.Getenv("TX_VAULT_PASSPHRASE"); env != "" {
		return env, nil
	}
	return "", errors.New("passphrase required via SECRETS_VAULT_PASSPHRASE or -passphrase")
}

func usage() {
	fmt.Fprintf(os.Stderr, `AetherVault v%s — Zero-Dependency AES-256-GCM Cryptographic Vault (MIT)

Usage:
  AetherVault <command> [flags]

Commands:
  init      Initialize a new AES-256-GCM vault
  set       Encrypt and store a secret (-key <k> -value <v>)
  get       Decrypt and print a secret (-key <k>)
  list      List stored secret keys and metadata (never values)
  shred     Crypto-shred a secret (-key <k>) or entire vault (-all)
  verify    Verify master key, envelope AEAD, every secret tag, and HMAC audit chain
  rotate    Rotate an existing secret (-key <k> -value <new>)
  version   Print version and cryptographic suite details
`, Version)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	sub := os.Args[1]
	if sub == "-h" || sub == "--help" || sub == "help" {
		usage()
		return
	}
	if sub == "version" || sub == "--version" || sub == "-v" {
		out, _ := json.MarshalIndent(map[string]any{
			"name":    "AetherVault",
			"version": Version,
			"cipher":  "AES-256-GCM",
			"kdf":     "PBKDF2-HMAC-SHA256 (210000 iterations) + HKDF-SHA256",
			"audit":   "HMAC-SHA256 hash chain",
			"cgo":     false,
		}, "", "  ")
		fmt.Println(string(out))
		return
	}

	fs := flag.NewFlagSet(sub, flag.ExitOnError)
	vaultDir := fs.String("vault", "", "Vault directory (default: $SECRETS_VAULT_DIR or ~/.local/share/AetherVault)")
	passFlag := fs.String("passphrase", "", "Vault passphrase (prefer SECRETS_VAULT_PASSPHRASE)")
	keyFlag := fs.String("key", "", "Secret key identifier")
	valFlag := fs.String("value", "", "Secret plaintext value")
	forceFlag := fs.Bool("force", false, "Force vault re-initialization")
	allFlag := fs.Bool("all", false, "Crypto-shred entire vault directory")
	_ = fs.Parse(os.Args[2:])

	args := fs.Args()
	key := *keyFlag
	val := *valFlag
	if key == "" && len(args) >= 1 {
		key = args[0]
	}
	if val == "" && len(args) >= 2 {
		val = args[1]
	}

	passphrase, err := resolvePassphrase(*passFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(2)
	}
	store := NewVaultStore(resolveVaultDir(*vaultDir))

	switch sub {
	case "init":
		if err := store.Init(passphrase, *forceFlag); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		b, _ := json.Marshal(map[string]any{"status": "initialized", "vault": store.Dir})
		fmt.Println(string(b))
	case "set", "rotate":
		if key == "" || val == "" {
			fmt.Fprintln(os.Stderr, "ERROR: both -key and -value are required")
			os.Exit(2)
		}
		if err := store.Set(passphrase, key, val, nil); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		b, _ := json.Marshal(map[string]any{"status": sub + "_ok", "key": key})
		fmt.Println(string(b))
	case "get":
		if key == "" {
			fmt.Fprintln(os.Stderr, "ERROR: -key is required")
			os.Exit(2)
		}
		secretVal, err := store.Get(passphrase, key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(secretVal)
	case "list":
		items, err := store.List(passphrase)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		b, _ := json.MarshalIndent(items, "", "  ")
		fmt.Println(string(b))
	case "shred", "delete":
		if !*allFlag && key == "" {
			fmt.Fprintln(os.Stderr, "ERROR: specify -key <name> or -all")
			os.Exit(2)
		}
		if err := store.Shred(passphrase, key, *allFlag); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		b, _ := json.Marshal(map[string]any{"status": "shredded", "key": key, "all": *allFlag})
		fmt.Println(string(b))
	case "verify":
		summary, err := store.Verify(passphrase)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		b, _ := json.MarshalIndent(summary, "", "  ")
		fmt.Println(string(b))
	default:
		fmt.Fprintf(os.Stderr, "ERROR: unknown command %q\n", sub)
		usage()
		os.Exit(2)
	}
}
