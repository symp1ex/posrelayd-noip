package config

import (
	"encoding/json"
	"log"
	"os"
)

const configPath = "data/config.json"

var Cfg Config

type Config struct {
	Service ServiceConfig `json:"service"`
	Logs    LogsConfig    `json:"logs"`
}

type ServiceConfig struct {
	Port   int    `json:"port"`
	APIKey string `json:"api_key"`
}

type LogsConfig struct {
	LogLevel  string `json:"log_level"`
	StoreDays int    `json:"store_days"`
}

func init() {
	cfg, err := load()
	if err != nil {
		log.Println("[config]", err)
	}
	Cfg = cfg
}

func load() (Config, error) {
	cfg := defaultConfig()

	data, err := os.ReadFile(configPath)
	if err != nil {
		_ = save(cfg)
		return cfg, err
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		_ = save(cfg)
		return cfg, err
	}

	return cfg, nil
}

func save(cfg Config) error {
	data, err := json.MarshalIndent(cfg, "", "\t")
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, data, 0644)
}

func defaultConfig() Config {
	return Config{
		Service: ServiceConfig{
			Port:   22233,
			APIKey: "b5679e9e-b5b5-4eaf-bb99-83dba95f9f53",
		},
		Logs: LogsConfig{
			LogLevel:  "info",
			StoreDays: 7,
		},
	}
}
