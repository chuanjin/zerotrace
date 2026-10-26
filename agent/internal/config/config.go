package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	AccountID          string      `json:"account_id"` // Anonymous 16-digit ID
	ListenAddr         string      `json:"listen_addr"`
	UpstreamAnthropic  string      `json:"upstream_anthropic"`
	UpstreamOpenAI     string      `json:"upstream_openai"`
	DataDir            string      `json:"data_dir"`
	HMACSecret         string      `json:"hmac_secret"`          // Local secret for deterministic PII pseudonymization
	E2EEKey            string      `json:"e2ee_key"`             // Client-side encryption key for prompt payloads
	GDPRMaskingEnabled bool        `json:"gdpr_masking_enabled"` // Deterministic EU PII scrubbing
	Guardrails         Guardrails  `json:"guardrails"`
	Storage            StorageConf `json:"storage"`
}

type Guardrails struct {
	MaxSessionCostUSD      float64 `json:"max_session_cost_usd"`
	MaxDailyCostUSD        float64 `json:"max_daily_cost_usd"`
	MaxIdenticalRetries    int     `json:"max_identical_retries"`
	CacheChurnAlertPercent float64 `json:"cache_churn_alert_percent"`
}

type StorageConf struct {
	Mode      string `json:"mode"` // "local" or "s3"
	Endpoint  string `json:"endpoint,omitempty"`
	Bucket    string `json:"bucket,omitempty"`
	Region    string `json:"region,omitempty"`
	AccessKey string `json:"access_key,omitempty"`
	SecretKey string `json:"secret_key,omitempty"`
}

func DefaultBaseDir() string {
	if env := os.Getenv("ZEROTRACE_HOME"); env != "" {
		return env
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".zerotrace"
	}
	return filepath.Join(home, ".zerotrace")
}

func ConfigPath() string {
	return filepath.Join(DefaultBaseDir(), "config.json")
}

func GenerateAccountID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	var digits []byte
	for _, v := range b {
		digits = append(digits, fmt.Sprintf("%02d", int(v)%100)...)
	}
	s := string(digits[:16])
	return fmt.Sprintf("%s %s %s %s", s[0:4], s[4:8], s[8:12], s[12:16])
}

func GenerateRandomHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func DefaultConfig() *Config {
	base := DefaultBaseDir()
	return &Config{
		AccountID:          GenerateAccountID(),
		ListenAddr:         "127.0.0.1:9000",
		UpstreamAnthropic:  "https://api.anthropic.com",
		UpstreamOpenAI:     "https://api.openai.com",
		DataDir:            filepath.Join(base, "data"),
		HMACSecret:         GenerateRandomHex(32),
		E2EEKey:            GenerateRandomHex(32),
		GDPRMaskingEnabled: true,
		Guardrails: Guardrails{
			MaxSessionCostUSD:      5.00,
			MaxDailyCostUSD:        25.00,
			MaxIdenticalRetries:    3,
			CacheChurnAlertPercent: 50.0,
		},
		Storage: StorageConf{
			Mode:   "local",
			Bucket: "zerotrace-vault",
			Region: "eu-north-1",
		},
	}
}

func LoadOrCreate() (*Config, error) {
	path := ConfigPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			cfg := DefaultConfig()
			if err := Save(cfg); err != nil {
				return nil, err
			}
			return cfg, nil
		}
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func Save(cfg *Config) error {
	base := DefaultBaseDir()
	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(base, "config.json"), data, 0600)
}
