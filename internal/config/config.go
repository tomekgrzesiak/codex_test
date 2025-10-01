package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Config represents application configuration derived from file and environment.
type Config struct {
	Server ServerConfig `mapstructure:"server"`
}

// ServerConfig describes HTTP server specific settings.
type ServerConfig struct {
	Address string `mapstructure:"address"`
}

// Load returns configuration merged from defaults, config files, and environment.
func Load() (Config, error) {
	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("./config")

	v.SetEnvPrefix("DEMO")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	v.SetDefault("server.address", ":8080")

	if err := v.ReadInConfig(); err != nil {
		if _, notFound := err.(viper.ConfigFileNotFoundError); !notFound {
			return Config{}, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return Config{}, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return cfg, nil
}
