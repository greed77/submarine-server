// Package config reads server settings from environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"code.reedpeople.com/tehgreedo/submarine-server/internal/mail"
)

// Signup modes.
const (
	SignupOpen      = "open"      // anyone may sign up
	SignupAllowlist = "allowlist" // only emails added with `allow add`
	SignupClosed    = "closed"    // accounts come only from `user create`
)

type Config struct {
	ListenAddr string // LISTEN_ADDR
	DBPath     string // DB_PATH
	BasePath   string // BASE_PATH, e.g. "/submarine"; empty serves at the root
	Signup     string // SIGNUP

	// TrustProxyHeader names the header carrying the real client IP
	// (e.g. CF-Connecting-IP). Leave empty unless the port is reachable
	// only through that proxy, since clients can forge it otherwise.
	TrustProxyHeader string

	MaxBodyBytes int64 // MAX_BODY_MB
	MaxBlobChars int   // MAX_RECORD_MB, stored as hex characters

	ServerName string // SERVER_NAME, used in email subjects
	SMTP       mail.SMTPConfig
}

func (c Config) SMTPEnabled() bool { return c.SMTP.Host != "" }

func FromEnv() (Config, error) {
	c := Config{
		ListenAddr:       env("LISTEN_ADDR", ":8080"),
		DBPath:           env("DB_PATH", "data/submarine.db"),
		BasePath:         strings.TrimRight(env("BASE_PATH", ""), "/"),
		Signup:           strings.ToLower(env("SIGNUP", SignupAllowlist)),
		TrustProxyHeader: env("TRUST_PROXY_HEADER", ""),
		ServerName:       env("SERVER_NAME", "Submarine Sync"),
		SMTP: mail.SMTPConfig{
			Host:     env("SMTP_HOST", ""),
			Port:     env("SMTP_PORT", "587"),
			Username: env("SMTP_USERNAME", ""),
			Password: env("SMTP_PASSWORD", ""),
			From:     env("SMTP_FROM", ""),
			Security: strings.ToLower(env("SMTP_SECURITY", "starttls")),
		},
	}
	bodyMB, err := envInt("MAX_BODY_MB", 20)
	if err != nil {
		return c, err
	}
	recordMB, err := envInt("MAX_RECORD_MB", 4)
	if err != nil {
		return c, err
	}
	c.MaxBodyBytes = int64(bodyMB) << 20
	c.MaxBlobChars = recordMB << 21 // hex: two characters per byte

	switch c.Signup {
	case SignupOpen, SignupAllowlist, SignupClosed:
	default:
		return c, fmt.Errorf("SIGNUP must be open, allowlist or closed (got %q)", c.Signup)
	}
	if c.BasePath != "" && !strings.HasPrefix(c.BasePath, "/") {
		return c, fmt.Errorf("BASE_PATH must start with / (got %q)", c.BasePath)
	}
	if c.SMTPEnabled() {
		switch c.SMTP.Security {
		case "starttls", "tls", "none":
		default:
			return c, fmt.Errorf("SMTP_SECURITY must be starttls, tls or none (got %q)", c.SMTP.Security)
		}
		if c.SMTP.From == "" {
			return c, fmt.Errorf("SMTP_FROM is required when SMTP_HOST is set")
		}
	}
	return c, nil
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) (int, error) {
	v := env(key, "")
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer (got %q)", key, v)
	}
	return n, nil
}
