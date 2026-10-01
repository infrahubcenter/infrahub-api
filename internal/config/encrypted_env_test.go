package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=" // 32 bytes

// isolate points the loader at an empty temp dir and clears every variable
// the tests touch, restoring them afterwards.
func isolate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("INFRAHUB_CONFIG_DIR", dir)
	for _, k := range []string{"STAGE", "SECRET", "SECRET_FILE", "INFRAHUB_ENV", "APP_ENV", "INFRAHUB_ENV_FILE", "INFRAHUB_MASTER_KEY", "INFRAHUB_MASTER_KEY_FILE", "DEMO_A", "DEMO_B", "DEMO_C", "DEMO_SECRET"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	return dir
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestEncryptFileIsOneOpaqueLine(t *testing.T) {
	plain := "# comment\nDATABASE_URL=postgres://user:pw@db:5432/app\nADMIN_EMAIL=owner@example.com\n"
	enc, err := EncryptFile(testKey, "production", []byte(plain))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(strings.TrimSpace(enc), "\n") != 0 || !strings.HasPrefix(enc, fileHeader) {
		t.Fatalf("want a single %s line, got %q", fileHeader, enc)
	}
	for _, leak := range []string{"DATABASE_URL", "postgres", "owner@example.com"} {
		if strings.Contains(enc, leak) {
			t.Fatalf("ciphertext leaks %q", leak)
		}
	}
	got, err := DecryptFile(testKey, "production", []byte(enc))
	if err != nil || string(got) != plain {
		t.Fatalf("round trip failed: %v %q", err, got)
	}
}

func TestEncryptedFileNeedsMatchingStageAndKey(t *testing.T) {
	enc, _ := EncryptFile(testKey, "staging", []byte("A=1\n"))
	if _, err := DecryptFile(testKey, "production", []byte(enc)); err == nil {
		t.Fatal("a staging file must not open as production")
	}
	other := "HyEeHRwbGhkYFxYVFBMSERAPDg0MCwoJCAcGBQQDAgE="
	if _, err := DecryptFile(other, "staging", []byte(enc)); err == nil {
		t.Fatal("a different key must not open the file")
	}
}

func TestPrecedenceEnvThenDotEnvThenIniEnc(t *testing.T) {
	dir := isolate(t)
	t.Setenv("STAGE", "staging")
	t.Setenv("SECRET", testKey)
	t.Setenv("DEMO_A", "from-real-env")
	enc, _ := EncryptFile(testKey, "staging", []byte("DEMO_A=from-ini\nDEMO_B=from-ini\nDEMO_C=from-ini\n"))
	writeFile(t, filepath.Join(dir, "staging.ini.enc"), enc)
	writeFile(t, filepath.Join(dir, ".env"), "export DEMO_A=from-dotenv\nDEMO_B='from-dotenv'\n")

	if err := LoadEnv(); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{"DEMO_A": "from-real-env", "DEMO_B": "from-dotenv", "DEMO_C": "from-ini", "APP_ENV": "staging"} {
		if got := os.Getenv(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

func TestDotEnvAloneWorksWithEncryptedValue(t *testing.T) {
	dir := isolate(t)
	t.Setenv("SECRET", testKey)
	secret, _ := EncryptValue(testKey, "s3cr3t")
	writeFile(t, filepath.Join(dir, "custom.env"), "DEMO_SECRET="+secret+"\n")
	t.Setenv("INFRAHUB_ENV_FILE", filepath.Join(dir, "custom.env"))
	if err := LoadEnv(); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("DEMO_SECRET"); got != "s3cr3t" {
		t.Fatalf("DEMO_SECRET = %q", got)
	}
}

func TestMissingKeyIsAClearError(t *testing.T) {
	dir := isolate(t)
	t.Setenv("STAGE", "production")
	enc, _ := EncryptFile(testKey, "production", []byte("DEMO_A=1\n"))
	writeFile(t, filepath.Join(dir, "production.ini.enc"), enc)
	writeFile(t, filepath.Join(dir, masterKeyFile), testKey) // never used outside development
	err := LoadEnv()
	if err == nil || !strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("want a master-key error, got %v", err)
	}
}

func TestLegacyPerValueFileStillLoadsAndConverts(t *testing.T) {
	dir := isolate(t)
	t.Setenv("SECRET", testKey)
	secret, _ := EncryptValue(testKey, "legacy-secret")
	legacy := "[app]\nDEMO_A = plain\nDEMO_SECRET = " + secret + "\n"
	writeFile(t, filepath.Join(dir, "development.ini.enc"), legacy)
	if err := LoadEnv(); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("DEMO_A") != "plain" || os.Getenv("DEMO_SECRET") != "legacy-secret" {
		t.Fatal("legacy file not loaded")
	}
	plain, err := DecryptValues(testKey, []byte(legacy))
	if err != nil || !strings.Contains(string(plain), "DEMO_SECRET=legacy-secret") || !strings.Contains(string(plain), "[app]") {
		t.Fatalf("convert: %v %q", err, plain)
	}
}

func TestNoConfigFilesIsFine(t *testing.T) {
	isolate(t)
	if err := LoadEnv(); err != nil {
		t.Fatalf("no files should not be an error: %v", err)
	}
}

func TestStrictModeNeedsStageSecretAndFile(t *testing.T) {
	dir := isolate(t)
	t.Setenv("STAGE", "development")
	enc, _ := EncryptFile(testKey, "development", []byte("DEMO_A=from-file\n"))

	// No secret given: a .master.key next to the file must not be enough.
	writeFile(t, filepath.Join(dir, masterKeyFile), testKey)
	writeFile(t, filepath.Join(dir, "development.ini.enc"), enc)
	if err := LoadEnv(); err == nil || !strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("strict mode without the secret: want refusal, got %v", err)
	}

	// Secret given but no file.
	t.Setenv("SECRET", testKey)
	os.Remove(filepath.Join(dir, "development.ini.enc"))
	if err := LoadEnv(); err == nil || !strings.Contains(err.Error(), "development.ini.enc") {
		t.Fatalf("strict mode without the file: want refusal, got %v", err)
	}

	// Unknown stage.
	t.Setenv("STAGE", "prod")
	if err := LoadEnv(); err == nil || !strings.Contains(err.Error(), "must be one of") {
		t.Fatalf("unknown stage: want refusal, got %v", err)
	}

	// Stage + secret + file: runs.
	t.Setenv("STAGE", "development")
	writeFile(t, filepath.Join(dir, "development.ini.enc"), enc)
	if err := LoadEnv(); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("DEMO_A") != "from-file" {
		t.Fatal("value from the encrypted file not loaded")
	}
}

func TestWithoutStageEnvVarsAloneStillWork(t *testing.T) {
	isolate(t)
	t.Setenv("DEMO_A", "set-by-docker")
	if err := LoadEnv(); err != nil || os.Getenv("DEMO_A") != "set-by-docker" {
		t.Fatalf("plain env mode broke: %v", err)
	}
}

func TestOlderVariableNamesStillWork(t *testing.T) {
	dir := isolate(t)
	t.Setenv("INFRAHUB_ENV", "staging")
	t.Setenv("INFRAHUB_MASTER_KEY", testKey)
	enc, _ := EncryptFile(testKey, "staging", []byte("DEMO_A=old-names\n"))
	writeFile(t, filepath.Join(dir, "staging.ini.enc"), enc)
	if err := LoadEnv(); err != nil || os.Getenv("DEMO_A") != "old-names" {
		t.Fatalf("INFRAHUB_ENV/INFRAHUB_MASTER_KEY: %v", err)
	}
}

func TestSecretFile(t *testing.T) {
	dir := isolate(t)
	t.Setenv("STAGE", "production")
	writeFile(t, filepath.Join(dir, "key"), testKey+"\n")
	t.Setenv("SECRET_FILE", filepath.Join(dir, "key"))
	enc, _ := EncryptFile(testKey, "production", []byte("DEMO_A=via-secret-file\n"))
	writeFile(t, filepath.Join(dir, "production.ini.enc"), enc)
	if err := LoadEnv(); err != nil || os.Getenv("DEMO_A") != "via-secret-file" {
		t.Fatalf("SECRET_FILE: %v", err)
	}
}

// The public image carries encrypted <stage>.ini.enc files; an install that
// configures itself with plain environment variables (no STAGE, no SECRET)
// must start without them.
func TestEncryptedFileIgnoredWithoutStageOrSecret(t *testing.T) {
	dir := isolate(t)
	t.Setenv("APP_ENV", "production")
	t.Setenv("DEMO_A", "from-compose-env")
	enc, _ := EncryptFile(testKey, "production", []byte("DEMO_A=from-file\nDEMO_B=from-file\n"))
	writeFile(t, filepath.Join(dir, "production.ini.enc"), enc)
	if err := LoadEnv(); err != nil {
		t.Fatalf("plain-env install must ignore an encrypted file it has no secret for: %v", err)
	}
	if os.Getenv("DEMO_A") != "from-compose-env" || os.Getenv("DEMO_B") != "" {
		t.Fatal("encrypted file should not have been read")
	}
	// With the secret (still no STAGE) it is used.
	t.Setenv("SECRET", testKey)
	if err := LoadEnv(); err != nil || os.Getenv("DEMO_B") != "from-file" {
		t.Fatalf("with SECRET the file should load: %v", err)
	}
}
