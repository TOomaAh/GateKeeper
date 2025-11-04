package config

import (
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

type Configuration struct {
	Notifications NotificationConfig `yaml:"notifications"`
	Unifi         []UnifiConfig      `yaml:"unifi"`
	AbuseIP       AbuseIPConfig      `yaml:"abuseip"`
	RateLimit     RateLimitConfig    `yaml:"ratelimit,omitempty"`
	Database      DatabaseConfig     `yaml:"database,omitempty"`
	Payload       PayloadConfig      `yaml:"payload,omitempty"`
	Dashboard     DashboardConfig    `yaml:"dashboard,omitempty"`
	ExcludedIPs   []string           `yaml:"excluded_ips,omitempty"`
}

type NotificationConfig struct {
	TelegramNotification []TelegramNotificationConfig `yaml:"telegram"`
}

type TelegramNotificationConfig struct {
	ChatId   string `yaml:"chat_id"`
	Token    string `yaml:"token"`
	Template string `yaml:"template,omitempty"`
}

type UnifiConfig struct {
	URL      string `yaml:"url"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type AbuseIPConfig struct {
	APIKey string `yaml:"api_key"`
}

type RateLimitConfig struct {
	RequestsPerMinute int  `yaml:"requests_per_minute"`
	Enabled           bool `yaml:"enabled"`
}

type DatabaseConfig struct {
	Path string `yaml:"path"`
}

type PayloadConfig struct {
	Enabled   bool   `yaml:"enabled"`
	MaxSize   int    `yaml:"max_size"`
	Directory string `yaml:"directory"`
}

type DashboardConfig struct {
	Enabled bool   `yaml:"enabled"`
	Port    string `yaml:"port"`
}

func LoadConfiguration(path string) (*Configuration, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open config file: %w", err)
	}
	defer f.Close()

	var conf Configuration

	bytes, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("cannot read config file: %w", err)
	}

	if err := yaml.Unmarshal(bytes, &conf); err != nil {
		return nil, fmt.Errorf("cannot parse config file: %w", err)
	}

	if conf.RateLimit.RequestsPerMinute == 0 {
		conf.RateLimit.RequestsPerMinute = 5
		conf.RateLimit.Enabled = true
	}

	if conf.Payload.MaxSize == 0 {
		conf.Payload.MaxSize = 1024 * 1024 // 1MB default
	}

	if conf.Payload.Directory == "" {
		conf.Payload.Directory = "./payloads"
	}

	if conf.Dashboard.Port == "" {
		conf.Dashboard.Port = ":8080"
	}

	defaultTemplate := `{{.Emoji}} *Accès direct par IP détecté*

🌐 *IP:* {{.IP}}
🌍 *Pays:* {{.Country}}
📊 *Score AbuseIPDB:* {{.Score}}/100 ({{.Severity}})
🛡️ *Bloqué:* {{.Blocked}}
📂 *Path:* {{.Path}}`

	for i := range conf.Notifications.TelegramNotification {
		if conf.Notifications.TelegramNotification[i].Template == "" {
			conf.Notifications.TelegramNotification[i].Template = defaultTemplate
		}
	}

	return &conf, nil
}
