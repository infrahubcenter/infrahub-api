// Package config: encrypted_env.go replaces the old plaintext .env file
// with per-environment INI files (development.ini.enc/production.ini.enc) whose
// secret values are individually AES-256-GCM encrypted, wrapped as
// ENC(base64...). Everything else about how configuration reaches the
// rest of this package is unchanged: this only replaces godotenv.Load()
// (which populated the process environment from a plaintext .env) with
// loadEnvFile (which populates it from a decrypted .ini) -- every
// existing os.Getenv/getEnv* call below in config.go keeps working
// verbatim.
//
// Why this is actually safer than .env, not just differently-shaped: a
// plaintext .env has to be kept OUT of version control entirely, so every
// deployment/developer ends up with their own untracked copy, manually
// kept in sync, with no history and no diff review. Once every secret
// VALUE in development.ini.enc/production.ini.enc is ciphertext, the file itself
// is safe to commit -- it's useless without the one master key, which is
// the only thing that still needs to be distributed out-of-band (a
// password manager, a CI/CD secret, ...) instead of N separate secrets.
//
// This file deliberately implements its own small AES-256-GCM
// encrypt/decrypt rather than importing services.EncryptionService: this
// package has zero internal dependencies today (it's the first thing
// that runs, before any service exists) and reusing that type would make
// config depend on services -- backwards from every other dependency
// direction in this app. The scheme is identical (same
// base64(nonce‖ciphertext‖tag) shape), just duplicated in ~20 lines
// rather than imported.
package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

const masterKeyLen = 32 // AES-256

// encPrefix/encSuffix wrap an encrypted value in the INI file, e.g.
// JWT_SECRET = ENC(kY3f...==). Anything not wrapped this way is used as a
// literal plaintext value -- non-secret config (ports, intervals, public
// URLs) never needs to be encrypted at all.
const (
	encPrefix = "ENC("
	encSuffix = ")"
)

// masterKeyFile is the local-development-only fallback location for the
// master key -- see resolveMasterKey. Never read when APP_ENV is
// "production", and always gitignored (see .gitignore).
const masterKeyFile = ".master.key"

// resolveMasterKey finds the one key that decrypts every ENC(...) value.
// Production/staging must set INFRAHUB_MASTER_KEY as a real environment
// variable (systemd/Docker/CI secret) -- this never reads a file when
// appEnv is "production", specifically so a key file can never end up
// sitting on a production host by habit or by copying a dev setup
// verbatim. Local development additionally falls back to a small
// gitignored file next to the ini files, so `go run ./cmd/server` just
// works without exporting anything by hand every session.
func resolveMasterKey(appEnv string) (string, error) {
	if key := os.Getenv("INFRAHUB_MASTER_KEY"); key != "" {
		return key, nil
	}
	if path := os.Getenv("INFRAHUB_MASTER_KEY_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read INFRAHUB_MASTER_KEY_FILE (%s): %w", path, err)
		}
		return strings.TrimSpace(string(data)), nil
	}
	if appEnv == "production" {
		return "", nil // no file fallback in production -- see doc comment above
	}
	data, err := os.ReadFile(masterKeyFile)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read %s: %w", masterKeyFile, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// decryptValue reverses the AES-256-GCM encryption cmd/encrypt-config-value
// produces. base64Key must decode to exactly 32 bytes.
func decryptValue(base64Key, encoded string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return "", fmt.Errorf("decode master key: %w", err)
	}
	if len(key) != masterKeyLen {
		return "", fmt.Errorf("master key must decode to %d bytes, got %d", masterKeyLen, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}
	sealed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(sealed) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := sealed[:nonceSize], sealed[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: wrong master key, or the value was tampered with")
	}
	return string(plaintext), nil
}

// EncryptValue is decryptValue's inverse -- exported so cmd/encrypt-config-value
// is the only other caller, keeping the AES-256-GCM implementation itself
// in exactly one place in this package.
func EncryptValue(base64Key, plaintext string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return "", fmt.Errorf("decode master key: %w", err)
	}
	if len(key) != masterKeyLen {
		return "", fmt.Errorf("master key must decode to %d bytes, got %d", masterKeyLen, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return encPrefix + base64.StdEncoding.EncodeToString(sealed) + encSuffix, nil
}

// LoadEnv resolves APP_ENV and loads its .ini file into the process
// environment -- exported so standalone commands that need env vars
// before they can do anything else (cmd/migrate, most notably: it needs
// DATABASE_URL to even open a connection) call exactly this instead of
// duplicating Load()'s own first two lines or, worse, going back to
// godotenv.
func LoadEnv() error {
	return loadEnvFile(getEnv("APP_ENV", "development"))
}

// loadEnvFile is godotenv.Load's replacement: parses <appEnv>.ini.enc
// (development.ini.enc or production.ini.enc, resolved relative to the
// current working directory, or INFRAHUB_CONFIG_DIR if set), decrypts
// every ENC(...)-wrapped value, and sets each key in the process
// environment -- but only if that key isn't already set, exactly
// matching godotenv's own "a real deployment env var always wins over
// the file" precedent. A missing ini file is not an error (mirrors the
// old `_ = godotenv.Load()` best-effort call it replaces); a present
// file with an ENC(...) value but no resolvable master key is a hard
// error, since silently setting the raw ciphertext as the env var's
// value would fail in a far more confusing place (e.g. an unparseable
// DATABASE_URL) than right here.
func loadEnvFile(appEnv string) error {
	dir := os.Getenv("INFRAHUB_CONFIG_DIR")
	path := appEnv + ".ini.enc"
	if dir != "" {
		path = dir + string(os.PathSeparator) + path
	}

	values, err := parseINIFile(path)
	if err != nil {
		return err
	}
	if values == nil {
		return nil
	}

	var masterKey string
	var masterKeyResolved bool
	for key, raw := range values {
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		value := raw
		if strings.HasPrefix(raw, encPrefix) && strings.HasSuffix(raw, encSuffix) {
			if !masterKeyResolved {
				masterKey, err = resolveMasterKey(appEnv)
				if err != nil {
					return err
				}
				masterKeyResolved = true
			}
			if masterKey == "" {
				return fmt.Errorf(
					"%s contains an encrypted value for %s, but no master key is available -- "+
						"set INFRAHUB_MASTER_KEY (or, for local development only, create %s next to %s). "+
						"Generate one with: go run ./cmd/gen-encryption-key",
					path, key, masterKeyFile, path,
				)
			}
			decoded, err := decryptValue(masterKey, strings.TrimSuffix(strings.TrimPrefix(raw, encPrefix), encSuffix))
			if err != nil {
				return fmt.Errorf("%s: decrypt %s: %w", path, key, err)
			}
			value = decoded
		}
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("set %s: %w", key, err)
		}
	}
	return nil
}
