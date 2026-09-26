package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"code.reedpeople.com/tehgreedo/submarine-server/internal/secret"
	"code.reedpeople.com/tehgreedo/submarine-server/internal/store"
)

// Codes printed by the CLI are handed to the user out of band, so they live
// longer than the emailed equivalents.
const (
	cliResetTTL = 24 * time.Hour
	cliLoginTTL = time.Hour
)

func userCmd(st *store.Store, args []string) error {
	ctx := context.Background()
	if len(args) == 0 {
		return errors.New("usage: user list|create|reset-token|login-token|signout|disable|enable|delete")
	}
	sub, args := args[0], args[1:]
	if sub == "list" {
		return listUsers(ctx, st)
	}
	email, err := emailArg(args)
	if err != nil {
		return err
	}

	if sub == "create" {
		if _, err := st.CreateUser(ctx, email); errors.Is(err, store.ErrConflict) {
			return fmt.Errorf("%s already exists (use `user reset-token` to let them set a new password)", email)
		} else if err != nil {
			return err
		}
		fmt.Printf("Created %s.\n\n", email)
		return printCode(ctx, st, email, store.PurposeReset, cliResetTTL,
			`In the app: Cloud Sync -> Sign in -> "Forgot password" -> "Already have a reset token? Continue",`+
				"\npaste this code and choose a password:")
	}

	u, err := st.UserByEmail(ctx, email)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("no user %s", email)
	}
	if err != nil {
		return err
	}
	switch sub {
	case "reset-token":
		return printCode(ctx, st, email, store.PurposeReset, cliResetTTL,
			`In the app: "Forgot password" -> "Already have a reset token? Continue", then paste:`)
	case "login-token":
		return printCode(ctx, st, email, store.PurposeLogin, cliLoginTTL,
			"Paste this one-time sign-in code into the app's email sign-in:")
	case "signout":
		n, err := st.RevokeUserTokens(ctx, u.ID)
		if err == nil {
			fmt.Printf("Revoked %d session(s) for %s.\n", n, email)
		}
		return err
	case "disable", "enable":
		if err := st.SetDisabled(ctx, u.ID, sub == "disable"); err != nil {
			return err
		}
		fmt.Printf("%s is now %sd.\n", email, sub)
		return nil
	case "delete":
		if !confirm(fmt.Sprintf("Delete %s with all their synced data and every share they own?", email)) {
			fmt.Println("Aborted.")
			return nil
		}
		if err := st.DeleteUser(ctx, u.ID); err != nil {
			return err
		}
		fmt.Printf("Deleted %s.\n", email)
		return nil
	}
	return fmt.Errorf("unknown user command %q", sub)
}

func printCode(ctx context.Context, st *store.Store, email, purpose string, ttl time.Duration, instructions string) error {
	tok := secret.NewToken(16)
	if err := st.CreateEmailToken(ctx, secret.Hash(tok), email, purpose, ttl); err != nil {
		return err
	}
	fmt.Printf("%s\n\n    %s\n\nValid for %.0f hour(s), single use.\n", instructions, tok, ttl.Hours())
	return nil
}

func listUsers(ctx context.Context, st *store.Store) error {
	users, err := st.UserStats(ctx)
	if err != nil {
		return err
	}
	if len(users) == 0 {
		fmt.Println("No users yet. Create one with: submarine-server user create <email>")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "EMAIL\tSTATUS\tLAST SEEN\tDEVICES\tPROFILES\tRECORDS\tTOMBSTONES\tPERSONAL\tSHARES OWNED\tSHARED\tTOTAL")
	var total int64
	for _, u := range users {
		status := "active"
		switch {
		case u.Disabled:
			status = "disabled"
		case !u.HasPassword:
			status = "no password"
		}
		lastSeen := "never"
		if !u.LastSeen.IsZero() {
			lastSeen = u.LastSeen.Local().Format("2006-01-02 15:04")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%d\t%d\t%s\t%d\t%s\t%s\n",
			u.Email, status, lastSeen, u.Devices, u.Profiles, u.Records, u.Tombstones,
			humanBytes(u.PersonalBytes), u.OwnedShares, humanBytes(u.SharedBytes), humanBytes(u.TotalBytes()))
		total += u.TotalBytes()
	}
	tw.Flush()
	fmt.Printf("\n%d user(s), %s stored in total.\n", len(users), humanBytes(total))
	return nil
}

func allowCmd(st *store.Store, args []string) error {
	ctx := context.Background()
	if len(args) == 0 {
		return errors.New("usage: allow list|add <email>|remove <email>")
	}
	sub, args := args[0], args[1:]
	if sub == "list" {
		emails, err := st.Allowlist(ctx)
		if err != nil {
			return err
		}
		if len(emails) == 0 {
			fmt.Println("The sign-up allowlist is empty.")
		}
		for _, e := range emails {
			fmt.Println(e)
		}
		return nil
	}
	email, err := emailArg(args)
	if err != nil {
		return err
	}
	switch sub {
	case "add":
		if err := st.AllowlistAdd(ctx, email); err != nil {
			return err
		}
		fmt.Printf("%s may now sign up (when SIGNUP=allowlist).\n", email)
	case "remove":
		removed, err := st.AllowlistRemove(ctx, email)
		if err != nil {
			return err
		}
		if !removed {
			return fmt.Errorf("%s was not on the allowlist", email)
		}
		fmt.Printf("Removed %s from the allowlist.\n", email)
	default:
		return fmt.Errorf("unknown allow command %q", sub)
	}
	return nil
}

func backupCmd(st *store.Store, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: backup <file>")
	}
	if _, err := os.Stat(args[0]); err == nil {
		return fmt.Errorf("%s already exists", args[0])
	}
	if err := st.Backup(context.Background(), args[0]); err != nil {
		return err
	}
	fmt.Printf("Backed up to %s.\n", args[0])
	return nil
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
