// Package config: encrypted_env.go loads configuration into the process
// environment before config.go reads it with os.Getenv. Three sources,
// highest priority first -- any one of them is enough on its own:
//
//  1. Real environment variables, from anywhere: docker run -e, Compose
//     environment:, a Kubernetes Secret/ConfigMap, a systemd unit, your
//     shell. Always win.
//  2. A .env file: INFRAHUB_ENV_FILE, or .env in INFRAHUB_CONFIG_DIR (default
//     the working directory). Plain KEY=VALUE lines; a value may be
//     ENC(...)-wrapped (see cmd/encrypt-config-value).
//  3. The stage's encrypted config file, <stage>.ini.enc in
//     INFRAHUB_CONFIG_DIR. The whole file is one line of AES-256-GCM
//     ciphertext ("IHCENC1:..."), so not even its key names are readable.
//     Opening it takes two things:
//     - the stage: STAGE = development | staging |
//     production -- picks the file, and is bound into the encryption,
//     so a staging file can't be loaded as production;
//     - the secret: SECRET (or SECRET_FILE, a mounted file holding it;
//     in development only, a gitignored .master.key file).
//     Create/inspect one with: infrahub-config encrypt|decrypt (cmd/infrahub-config).
//     Older files with individually ENC(...)-wrapped values still load.
//
// A source that doesn't exist is simply skipped. Every value only fills in
// a variable nothing higher up has already set.
//
// Strict mode: setting STAGE means "this deployment runs from its
// encrypted config". The API then refuses to start unless STAGE is a
// known stage, SECRET (or SECRET_FILE) is given
// explicitly -- no .master.key fallback -- and <stage>.ini.enc exists and
// decrypts. Without STAGE, configuration from plain environment
// variables alone (e.g. Docker Compose, Kubernetes) keeps working.
//
// This file deliberately implements its own small AES-256-GCM
// encrypt/decrypt rather than importing services.EncryptionService: this
// package has zero internal dependencies (it runs before any service
// exists), and depending on services would invert every other dependency
// direction in this app.
package config

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const masterKeyLen = 32 // AES-256

// encPrefix/encSuffix wrap a single encrypted value, e.g.
// JWT_SECRET=ENC(kY3f...==), in a .env file or a legacy ini file.
const (
	encPrefix = "ENC("
	encSuffix = ")"
)

// fileHeader starts a whole-file-encrypted config file.
const fileHeader = "IHCENC1:"

// Stages a config file can be encrypted for.
var Stages = []string{"development", "staging", "production"}

// masterKeyFile is the development-only fallback location for the master
// key -- see resolveMasterKey. Always gitignored.
const masterKeyFile = ".master.key"

// The older names INFRAHUB_ENV / INFRAHUB_MASTER_KEY / INFRAHUB_MASTER_KEY_FILE
// still work in place of STAGE / SECRET / SECRET_FILE.

// firstEnv returns the first non-empty variable among names.
func firstEnv(names ...string) string {
	for _, n := range names {
		if v := strings.TrimSpace(os.Getenv(n)); v != "" {
			return v
		}
	}
	return ""
}

// stageEnv is the explicitly given stage (STAGE, or the older INFRAHUB_ENV).
func stageEnv() string { return firstEnv("STAGE", "INFRAHUB_ENV") }

// SecretFromEnv returns the master key from SECRET (or INFRAHUB_MASTER_KEY),
// or read from the file named by SECRET_FILE (or INFRAHUB_MASTER_KEY_FILE).
// Empty when none is set.
func SecretFromEnv() (string, error) {
	if key := firstEnv("SECRET", "INFRAHUB_MASTER_KEY"); key != "" {
		return key, nil
	}
	if path := firstEnv("SECRET_FILE", "INFRAHUB_MASTER_KEY_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read SECRET_FILE (%s): %w", path, err)
		}
		return strings.TrimSpace(string(data)), nil
	}
	return "", nil
}

// Stage is the deployment stage: STAGE, else APP_ENV, else
// "development". It must come from the real process environment -- it
// picks which file to open, so it can't live inside that file.
func Stage() string {
	if s := stageEnv(); s != "" {
		return s
	}
	return getEnv("APP_ENV", "development")
}

// resolveMasterKey finds the key that decrypts <stage>.ini.enc and any
// ENC(...) value. Staging and production must provide it as a real
// environment variable or a mounted secret file (SECRET_FILE);
// only development falls back to a local .master.key, so a key file can't
// end up on a server by copying a dev setup.
func resolveMasterKey(stage, dir string, strict bool) (string, error) {
	if key, err := SecretFromEnv(); err != nil || key != "" {
		return key, err
	}
	if strict || stage != "development" {
		return "", nil
	}
	for _, path := range []string{filepath.Join(dir, masterKeyFile), masterKeyFile} {
		data, err := os.ReadFile(path)
		if err == nil {
			return strings.TrimSpace(string(data)), nil
		}
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("read %s: %w", path, err)
		}
	}
	return "", nil
}

func newGCM(base64Key string) (cipher.AEAD, error) {
	key, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, fmt.Errorf("decode master key: %w", err)
	}
	if len(key) != masterKeyLen {
		return nil, fmt.Errorf("master key must decode to %d bytes, got %d", masterKeyLen, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

func seal(base64Key string, plaintext, aad []byte) (string, error) {
	gcm, err := newGCM(base64Key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	return base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, plaintext, aad)), nil
}

func open(base64Key, encoded string, aad []byte) ([]byte, error) {
	gcm, err := newGCM(base64Key)
	if err != nil {
		return nil, err
	}
	sealed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	plaintext, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], aad)
	if err != nil {
		return nil, fmt.Errorf("wrong master key, wrong stage, or the data was tampered with")
	}
	return plaintext, nil
}

func stageAAD(stage string) []byte { return []byte("infrahub-config:" + stage) }

// EncryptValue returns plaintext as ENC(...), for a single value in a .env file.
func EncryptValue(base64Key, plaintext string) (string, error) {
	out, err := seal(base64Key, []byte(plaintext), nil)
	if err != nil {
		return "", err
	}
	return encPrefix + out + encSuffix, nil
}

func decryptValue(base64Key, encoded string) (string, error) {
	out, err := open(base64Key, encoded, nil)
	return string(out), err
}

// EncryptFile encrypts a whole plaintext config (INI / KEY=VALUE text) for
// one stage, returning the single line to store in <stage>.ini.enc.
func EncryptFile(base64Key, stage string, plaintext []byte) (string, error) {
	out, err := seal(base64Key, plaintext, stageAAD(stage))
	if err != nil {
		return "", err
	}
	return fileHeader + out + "\n", nil
}

// DecryptFile reverses EncryptFile. It fails unless both the key and the
// stage match the ones the file was encrypted with.
func DecryptFile(base64Key, stage string, content []byte) ([]byte, error) {
	text := strings.TrimSpace(string(content))
	if !strings.HasPrefix(text, fileHeader) {
		return nil, fmt.Errorf("not a whole-file encrypted config (missing %s header)", fileHeader)
	}
	return open(base64Key, strings.TrimPrefix(text, fileHeader), stageAAD(stage))
}

// IsEncryptedFile reports whether content is whole-file encrypted.
func IsEncryptedFile(content []byte) bool {
	return bytes.HasPrefix(bytes.TrimSpace(content), []byte(fileHeader))
}

// LoadEnv fills the process environment from .env and <stage>.ini.enc (see
// the package comment). Called by config.Load; cmd/migrate calls it
// directly.
func LoadEnv() error {
	return loadEnvFile(Stage())
}

func configDir() string {
	if dir := os.Getenv("INFRAHUB_CONFIG_DIR"); dir != "" {
		return dir
	}
	return "."
}

// StrictMode reports whether STAGE is set (see the package comment).
func StrictMode() bool {
	return stageEnv() != ""
}

func loadEnvFile(stage string) error {
	dir := configDir()
	strict := StrictMode()
	if strict {
		known := false
		for _, s := range Stages {
			known = known || s == stage
		}
		if !known {
			return fmt.Errorf("STAGE=%q: must be one of %s", stage, strings.Join(Stages, ", "))
		}
		if firstEnv("SECRET", "INFRAHUB_MASTER_KEY", "SECRET_FILE", "INFRAHUB_MASTER_KEY_FILE") == "" {
			return fmt.Errorf("STAGE=%s is set, so SECRET (or SECRET_FILE) is required -- the API won't start without the stage's secret", stage)
		}
		encPath := filepath.Join(dir, stage+".ini.enc")
		content, err := os.ReadFile(encPath)
		if err != nil {
			return fmt.Errorf("STAGE=%s is set, so %s is required: %w", stage, encPath, err)
		}
		if !IsEncryptedFile(content) {
			return fmt.Errorf("%s must be an encrypted config file (infrahub-config encrypt --stage %s)", encPath, stage)
		}
	}
	// Everything else reads the stage from APP_ENV, so record it (an
	// explicit STAGE wins over the image's default APP_ENV).
	if _, ok := os.LookupEnv("APP_ENV"); !ok || stageEnv() != "" {
		_ = os.Setenv("APP_ENV", stage)
	}

	// 2. .env
	envPath := os.Getenv("INFRAHUB_ENV_FILE")
	if envPath == "" {
		envPath = filepath.Join(dir, ".env")
	}
	if err := applyFile(envPath, stage, dir, false, strict); err != nil {
		return err
	}

	// 3. <stage>.ini.enc
	return applyFile(filepath.Join(dir, stage+".ini.enc"), stage, dir, true, strict)
}

// applyFile sets every KEY=VALUE in path that isn't already set. A
// whole-file encrypted file is decrypted first (only allowed for the
// stage's .ini.enc); ENC(...) values are decrypted one by one.
func applyFile(path, stage, dir string, allowWholeFile, strict bool) error {
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %w", path, err)
	}

	var masterKey string
	var keyResolved bool
	needKey := func(what string) (string, error) {
		if !keyResolved {
			masterKey, err = resolveMasterKey(stage, dir, strict)
			if err != nil {
				return "", err
			}
			keyResolved = true
		}
		if masterKey == "" {
			hint := "set SECRET (or SECRET_FILE)"
			if stage == "development" {
				hint += ", or create " + filepath.Join(dir, masterKeyFile)
			}
			return "", fmt.Errorf("%s: %s needs the master key -- %s", path, what, hint)
		}
		return masterKey, nil
	}

	if IsEncryptedFile(content) {
		if !allowWholeFile {
			return fmt.Errorf("%s is an encrypted config file; name it %s.ini.enc instead", path, stage)
		}
		// Without STAGE this deployment is configured some other way (plain
		// environment variables, .env): an encrypted file it holds no secret
		// for -- e.g. the ones baked into the public image -- is not for it.
		if !strict {
			if key, err := resolveMasterKey(stage, dir, false); err != nil || key == "" {
				return err
			}
		}
		key, err := needKey("decrypting the file")
		if err != nil {
			return err
		}
		content, err = DecryptFile(key, stage, content)
		if err != nil {
			return fmt.Errorf("%s (stage %q): %w", path, stage, err)
		}
	}

	values, err := parseINI(content, path)
	if err != nil {
		return err
	}
	for _, kv := range values {
		if _, exists := os.LookupEnv(kv.key); exists {
			continue
		}
		value := kv.value
		if strings.HasPrefix(value, encPrefix) && strings.HasSuffix(value, encSuffix) {
			key, err := needKey("the encrypted value of " + kv.key)
			if err != nil {
				return err
			}
			value, err = decryptValue(key, strings.TrimSuffix(strings.TrimPrefix(value, encPrefix), encSuffix))
			if err != nil {
				return fmt.Errorf("%s: decrypt %s: %w", path, kv.key, err)
			}
		}
		if err := os.Setenv(kv.key, value); err != nil {
			return fmt.Errorf("set %s: %w", kv.key, err)
		}
	}
	return nil
}

// DecryptValues returns content (KEY=VALUE text) with every ENC(...) value
// replaced by its plaintext and comments kept -- used to convert an older
// per-value encrypted file to the whole-file format.
func DecryptValues(base64Key string, content []byte) ([]byte, error) {
	var out strings.Builder
	for _, line := range strings.SplitAfter(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		idx := strings.IndexByte(trimmed, '=')
		if idx > 0 && !strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, ";") {
			value := strings.TrimSpace(trimmed[idx+1:])
			if strings.HasPrefix(value, encPrefix) && strings.HasSuffix(value, encSuffix) {
				plain, err := decryptValue(base64Key, strings.TrimSuffix(strings.TrimPrefix(value, encPrefix), encSuffix))
				if err != nil {
					return nil, fmt.Errorf("decrypt %s: %w", strings.TrimSpace(trimmed[:idx]), err)
				}
				out.WriteString(strings.TrimSpace(trimmed[:idx]) + "=" + plain + "\n")
				continue
			}
		}
		out.WriteString(line)
	}
	return []byte(out.String()), nil
}
