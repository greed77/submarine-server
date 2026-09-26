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

	// Admin web UI, on its own listener. Disabled when AdminAddr is empty.
	AdminAddr        string // ADMIN_ADDR
	AdminPassword    string // ADMIN_PASSWORD: HTTP basic auth
	AccessTeamDomain string // CF_ACCESS_TEAM_DOMAIN, normalized to <team>.cloudflareaccess.com
	AccessAUD        string // CF_ACCESS_AUD: the Access application's audience tag
	AdminNoAuth      bool   // ADMIN_INSECURE_NO_AUTH: allow the UI with neither of the above
}

func (c Config) AccessEnabled() bool { return c.AccessTeamDomain != "" }

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
		AdminAddr:        env("ADMIN_ADDR", ""),
		AdminPassword:    env("ADMIN_PASSWORD", ""),
		AccessTeamDomain: normalizeTeamDomain(env("CF_ACCESS_TEAM_DOMAIN", "")),
		AccessAUD:        env("CF_ACCESS_AUD", ""),
		AdminNoAuth:      env("ADMIN_INSECURE_NO_AUTH", "") == "true",
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
	if (c.AccessTeamDomain == "") != (c.AccessAUD == "") {
		return c, fmt.Errorf("CF_ACCESS_TEAM_DOMAIN and CF_ACCESS_AUD must be set together")
	}
	if c.AdminAddr != "" && !c.AccessEnabled() && c.AdminPassword == "" && !c.AdminNoAuth {
		return c, fmt.Errorf("ADMIN_ADDR is set but the admin UI has no authentication: set " +
			"CF_ACCESS_TEAM_DOMAIN + CF_ACCESS_AUD (recommended) and/or ADMIN_PASSWORD, " +
			"or ADMIN_INSECURE_NO_AUTH=true if the port is unreachable to anyone else")
	}
	return c, nil
}

// normalizeTeamDomain accepts "myteam", "myteam.cloudflareaccess.com" or a
// full https:// URL.
func normalizeTeamDomain(s string) string {
	s = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(s), "https://"), "/")
	if s != "" && !strings.Contains(s, ".") {
		s += ".cloudflareaccess.com"
	}
	return s
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
