package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Config represents application configuration derived from file and environment.
type Config struct {
	Server      ServerConfig      `mapstructure:"server"`
	GoogleOAuth GoogleOAuthConfig `mapstructure:"google_oauth"`
	Database    DatabaseConfig    `mapstructure:"database"`
}

// ServerConfig describes HTTP server specific settings.
type ServerConfig struct {
	Address string `mapstructure:"address"`
}

// GoogleOAuthConfig describes Google OAuth 2.0 integration settings.
type GoogleOAuthConfig struct {
	Enabled      bool                   `mapstructure:"enabled"`
	ClientID     string                 `mapstructure:"client_id"`
	ClientSecret string                 `mapstructure:"client_secret"`
	RedirectURL  string                 `mapstructure:"redirect_url"`
	Scopes       []string               `mapstructure:"scopes"`
	StateCookie  OAuthStateCookieConfig `mapstructure:"state_cookie"`
}

// OAuthStateCookieConfig defines how the OAuth state cookie is created.
type OAuthStateCookieConfig struct {
	Name   string `mapstructure:"name"`
	Domain string `mapstructure:"domain"`
	Path   string `mapstructure:"path"`
	MaxAge int    `mapstructure:"max_age"`
	Secure bool   `mapstructure:"secure"`
}

// DatabaseConfig describes connectivity to the backing PostgreSQL instance.
type DatabaseConfig struct {
	DSN string `mapstructure:"dsn"`
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
	v.SetDefault("google_oauth.enabled", false)
	v.SetDefault("google_oauth.redirect_url", "http://localhost:8080/auth/google/callback")
	v.SetDefault("google_oauth.scopes", []string{"openid", "profile", "email"})
	v.SetDefault("google_oauth.state_cookie.name", "oauth_state")
	v.SetDefault("google_oauth.state_cookie.path", "/")
	v.SetDefault("google_oauth.state_cookie.max_age", 600)
	v.SetDefault("google_oauth.state_cookie.secure", false)
	v.SetDefault("database.dsn", "postgres://postgres:postgres@localhost:5432/petstore?sslmode=disable")

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
