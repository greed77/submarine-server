// Package mail delivers auth emails over SMTP, or writes them to the log when
// SMTP isn't configured so a self-hoster can still complete every flow.
package mail

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"strings"
	"time"
)

type Mailer interface {
	Send(to, subject, body string) error
}

// LogMailer prints messages (tokens included) to the server log.
type LogMailer struct{ Log *slog.Logger }

func (m LogMailer) Send(to, subject, body string) error {
	m.Log.Info("email not sent (SMTP not configured)", "to", to, "subject", subject, "body", body)
	return nil
}

type SMTPConfig struct {
	Host     string
	Port     string
	Username string
	Password string
	From     string
	// Security is "starttls" (default), "tls" (implicit TLS, usually port
	// 465) or "none".
	Security string
}

type SMTPMailer struct{ Cfg SMTPConfig }

func (m SMTPMailer) Send(to, subject, body string) error {
	c := m.Cfg
	addr := net.JoinHostPort(c.Host, c.Port)
	tlsCfg := &tls.Config{ServerName: c.Host}

	var client *smtp.Client
	var err error
	if c.Security == "tls" {
		conn, derr := tls.DialWithDialer(&net.Dialer{Timeout: 15 * time.Second}, "tcp", addr, tlsCfg)
		if derr != nil {
			return derr
		}
		client, err = smtp.NewClient(conn, c.Host)
	} else {
		conn, derr := net.DialTimeout("tcp", addr, 15*time.Second)
		if derr != nil {
			return derr
		}
		client, err = smtp.NewClient(conn, c.Host)
	}
	if err != nil {
		return err
	}
	defer client.Close()

	if c.Security == "" || c.Security == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return fmt.Errorf("smtp server %s does not offer STARTTLS", addr)
		}
		if err := client.StartTLS(tlsCfg); err != nil {
			return err
		}
	}
	if c.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", c.Username, c.Password, c.Host)); err != nil {
			return err
		}
	}
	if err := client.Mail(c.From); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	msg := strings.Join([]string{
		"From: " + c.From,
		"To: " + to,
		"Subject: " + subject,
		"Date: " + time.Now().UTC().Format(time.RFC1123Z),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"",
		strings.ReplaceAll(body, "\n", "\r\n"),
	}, "\r\n")
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}
