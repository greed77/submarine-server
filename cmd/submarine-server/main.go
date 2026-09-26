// Command submarine-server is a self-hostable sync server for the Submarine
// SSH client. Run with no arguments (or "serve") to start the server; the
// other subcommands administer the same database.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"code.reedpeople.com/tehgreedo/submarine-server/internal/api"
	"code.reedpeople.com/tehgreedo/submarine-server/internal/config"
	"code.reedpeople.com/tehgreedo/submarine-server/internal/mail"
	"code.reedpeople.com/tehgreedo/submarine-server/internal/store"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `usage: submarine-server <command> [args]

Server:
  serve                         run the sync server (default)
  healthcheck                   exit 0 if the local server answers /health
  version                       print the version
  backup <file>                 write a consistent copy of the database (safe while serving)

Users:
  user list                     list users with storage usage
  user create <email>           create a user and print a password-setup code
  user reset-token <email>      print a password reset code
  user login-token <email>      print a one-time sign-in code
  user signout <email>          revoke every session of a user
  user disable <email>          block a user and sign out all their devices
  user enable <email>           unblock a user
  user delete <email>           delete a user and ALL their data (asks first)

Sign-up allowlist (used when SIGNUP=allowlist):
  allow list | add <email> | remove <email>

Configuration comes from environment variables; see README.md.
`

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve()
	case "healthcheck":
		err = healthcheck()
	case "version", "--version", "-v":
		fmt.Println(version)
	case "user":
		err = withStore(func(st *store.Store) error { return userCmd(st, args) })
	case "allow":
		err = withStore(func(st *store.Store) error { return allowCmd(st, args) })
	case "backup":
		err = withStore(func(st *store.Store) error { return backupCmd(st, args) })
	case "help", "--help", "-h":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func serve() error {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()

	var mailer mail.Mailer = mail.LogMailer{Log: log}
	if cfg.SMTPEnabled() {
		mailer = mail.SMTPMailer{Cfg: cfg.SMTP}
	}
	srv := api.New(cfg, st, mailer, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go srv.RunJanitor(ctx)

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}
	log.Info("starting submarine-server", "version", version, "addr", cfg.ListenAddr, "db", cfg.DBPath,
		"base_path", cfg.BasePath, "signup", cfg.Signup, "smtp", cfg.SMTPEnabled(),
		"trust_proxy_header", cfg.TrustProxyHeader)
	if !cfg.SMTPEnabled() {
		log.Warn("SMTP_HOST not set: auth emails (with their codes) are written to this log instead")
	}

	errc := make(chan error, 1)
	go func() { errc <- httpSrv.ListenAndServe() }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return httpSrv.Shutdown(shutdownCtx)
}

// healthcheck lets a FROM-scratch container (no curl) run a HEALTHCHECK.
func healthcheck() error {
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	host, port, err := net.SplitHostPort(cfg.ListenAddr)
	if err != nil {
		return err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + net.JoinHostPort(host, port) + cfg.BasePath + "/health")
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health returned %s", resp.Status)
	}
	return nil
}

func withStore(fn func(*store.Store) error) error {
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	if _, err := os.Stat(cfg.DBPath); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("no database at %s (set DB_PATH, or start the server once to create it)", cfg.DBPath)
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()
	return fn(st)
}

func emailArg(args []string) (string, error) {
	if len(args) != 1 {
		return "", errors.New("expected exactly one email argument")
	}
	email := api.NormalizeEmail(args[0])
	if email == "" {
		return "", fmt.Errorf("invalid email %q", args[0])
	}
	return email, nil
}

func confirm(prompt string) bool {
	fmt.Print(prompt + " [y/N] ")
	var answer string
	fmt.Scanln(&answer)
	return strings.EqualFold(strings.TrimSpace(answer), "y")
}
