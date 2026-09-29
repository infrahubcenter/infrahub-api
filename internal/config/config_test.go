package config

import (
	"testing"
	"time"
)

func TestLoad_RequiresDatabaseURL(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv("JWT_SECRET", "secret")
	t.Setenv("SSH_CREDENTIAL_ENCRYPTION_KEY", "dGVzdC1lbmNyeXB0aW9uLWtleS0zMi1ieXRlcyEh")

	if _, err := Load(); err == nil {
		t.Fatal("expected error when DATABASE_URL is unset")
	}
}

func TestLoad_RequiresJWTSecret(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://localhost/test")
	t.Setenv("JWT_SECRET", "")
	t.Setenv("SSH_CREDENTIAL_ENCRYPTION_KEY", "dGVzdC1lbmNyeXB0aW9uLWtleS0zMi1ieXRlcyEh")

	if _, err := Load(); err == nil {
		t.Fatal("expected error when JWT_SECRET is unset")
	}
}

func TestLoad_RequiresEncryptionKey(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://localhost/test")
	t.Setenv("JWT_SECRET", "secret")
	t.Setenv("SSH_CREDENTIAL_ENCRYPTION_KEY", "")

	if _, err := Load(); err == nil {
		t.Fatal("expected error when SSH_CREDENTIAL_ENCRYPTION_KEY is unset")
	}
}

func TestLoad_Defaults(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://localhost/test")
	t.Setenv("JWT_SECRET", "secret")
	t.Setenv("SSH_CREDENTIAL_ENCRYPTION_KEY", "dGVzdC1lbmNyeXB0aW9uLWtleS0zMi1ieXRlcyEh")
	t.Setenv("APP_ENV", "")
	t.Setenv("APP_PORT", "")
	t.Setenv("DB_MAX_CONNS", "")
	t.Setenv("DB_MIN_CONNS", "")
	t.Setenv("SSH_CONNECT_TIMEOUT", "")
	t.Setenv("SSH_COMMAND_TIMEOUT", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.AppEnv != "development" {
		t.Errorf("AppEnv = %q, want development", cfg.AppEnv)
	}
	if cfg.AppPort != "8080" {
		t.Errorf("AppPort = %q, want 8080", cfg.AppPort)
	}
	if cfg.DBMaxConns != 10 {
		t.Errorf("DBMaxConns = %d, want 10", cfg.DBMaxConns)
	}
	if cfg.DBMinConns != 2 {
		t.Errorf("DBMinConns = %d, want 2", cfg.DBMinConns)
	}
	if cfg.SSHConnectTimeout != 10*time.Second {
		t.Errorf("SSHConnectTimeout = %v, want 10s", cfg.SSHConnectTimeout)
	}
	if cfg.SSHCommandTimeout != 30*time.Second {
		t.Errorf("SSHCommandTimeout = %v, want 30s", cfg.SSHCommandTimeout)
	}
	if cfg.VMMonitorInterval != 60*time.Second {
		t.Errorf("VMMonitorInterval = %v, want 60s", cfg.VMMonitorInterval)
	}
	if cfg.VMMonitorWorkers != 5 {
		t.Errorf("VMMonitorWorkers = %d, want 5", cfg.VMMonitorWorkers)
	}
	if cfg.VMMonitorStaleAfter != 5*time.Minute {
		t.Errorf("VMMonitorStaleAfter = %v, want 5m", cfg.VMMonitorStaleAfter)
	}
	if cfg.VMMonitorRetentionDays != 30 {
		t.Errorf("VMMonitorRetentionDays = %d, want 30", cfg.VMMonitorRetentionDays)
	}
	if cfg.VMCPUWarningPercent != 80 || cfg.VMCPUCriticalPercent != 90 {
		t.Errorf("VMCPUWarningPercent/CriticalPercent = %v/%v, want 80/90", cfg.VMCPUWarningPercent, cfg.VMCPUCriticalPercent)
	}
	if cfg.VMMemoryWarningPercent != 80 || cfg.VMMemoryCriticalPercent != 90 {
		t.Errorf("VMMemoryWarningPercent/CriticalPercent = %v/%v, want 80/90", cfg.VMMemoryWarningPercent, cfg.VMMemoryCriticalPercent)
	}
	if cfg.VMDiskWarningPercent != 80 || cfg.VMDiskCriticalPercent != 90 {
		t.Errorf("VMDiskWarningPercent/CriticalPercent = %v/%v, want 80/90", cfg.VMDiskWarningPercent, cfg.VMDiskCriticalPercent)
	}
	if cfg.PackageScanInterval != 6*time.Hour {
		t.Errorf("PackageScanInterval = %v, want 6h", cfg.PackageScanInterval)
	}
	if cfg.PackageScanWorkers != 2 {
		t.Errorf("PackageScanWorkers = %d, want 2", cfg.PackageScanWorkers)
	}
	if cfg.PackageScanCommandTimeout != 90*time.Second {
		t.Errorf("PackageScanCommandTimeout = %v, want 90s", cfg.PackageScanCommandTimeout)
	}
}
