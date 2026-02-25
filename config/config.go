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
	Db      DbConfig      `json:"database"`
	Logs    LogsConfig    `json:"logs"`
}

type ServiceConfig struct {
	Port   int    `json:"port"`
	APIKey string `json:"api_key"`
}

type DbConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Db_name  string `json:"db_name"`
	User     string `json:"user"`
	Password string `json:"password"`
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
		Db: DbConfig{
			Host:     "192.168.0.30",
			Port:     40222,
			Db_name:  "pr_noip",
			User:     "user",
			Password: "password",
		},
		Logs: LogsConfig{
			LogLevel:  "info",
			StoreDays: 7,
		},
	}
}
