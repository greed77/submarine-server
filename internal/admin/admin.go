// Package admin serves the operator web UI: users, storage, shares and the
// sign-up allowlist. It runs on its own listener so it is never reachable
// through the public API port, and renders plain server-side HTML (no
// JavaScript) from templates embedded in the binary.
package admin

import (
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"code.reedpeople.com/tehgreedo/submarine-server/internal/api"
	"code.reedpeople.com/tehgreedo/submarine-server/internal/config"
	"code.reedpeople.com/tehgreedo/submarine-server/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

type Server struct {
	cfg          config.Config
	store        *store.Store
	log          *slog.Logger
	version      string
	access       *accessVerifier // nil unless Cloudflare Access is configured
	passwordGate *failGate
	pages        map[string]*template.Template
	now          func() time.Time
}

func New(cfg config.Config, st *store.Store, log *slog.Logger, version string) *Server {
	a := &Server{
		cfg:          cfg,
		store:        st,
		log:          log,
		version:      version,
		passwordGate: newFailGate(),
		now:          time.Now,
	}
	if cfg.AccessEnabled() {
		a.access = newAccessVerifier(cfg.AccessTeamDomain, cfg.AccessAUD)
	}
	a.pages = map[string]*template.Template{}
	for _, name := range []string{"users", "user", "code", "shares", "share", "signup", "error"} {
		a.pages[name] = template.Must(template.New("").Funcs(a.funcs()).
			ParseFS(templateFS, "templates/layout.html", "templates/"+name+".html"))
	}
	return a
}

func (a *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))

	mux.HandleFunc("GET /{$}", a.users)
	mux.HandleFunc("POST /users", a.createUser)
	mux.HandleFunc("GET /users/{id}", a.user)
	mux.HandleFunc("POST /users/{id}/{action}", a.userAction)
	mux.HandleFunc("GET /shares", a.shares)
	mux.HandleFunc("GET /shares/{id}", a.share)
	mux.HandleFunc("POST /shares/{id}/delete", a.deleteShare)
	mux.HandleFunc("GET /signup", a.signup)
	mux.HandleFunc("POST /signup/allow", a.allow)
	mux.HandleFunc("POST /signup/remove", a.unallow)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		a.fail(w, r, http.StatusNotFound, "There's no page here.")
	})

	// Cookie-based Access sessions and cached basic-auth credentials are
	// both ambient, so every POST must come from this origin.
	csrf := http.NewCrossOriginProtection()
	return a.authenticate(noStore(csrf.Handler(mux)))
}

func noStore(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'")
		h.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

type page struct {
	Title   string
	Nav     string
	Actor   string
	Flash   string
	Error   string
	Version string
	Data    any
}

func (a *Server) render(w http.ResponseWriter, r *http.Request, status int, name, title, nav string, data any) {
	p := page{
		Title:   title,
		Nav:     nav,
		Actor:   actor(r),
		Flash:   flashes[r.URL.Query().Get("done")],
		Error:   errorsByKey[r.URL.Query().Get("err")],
		Version: a.version,
		Data:    data,
	}
	var buf strings.Builder
	if err := a.pages[name].ExecuteTemplate(&buf, "layout", p); err != nil {
		a.log.Error("admin: render", "page", name, "err", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprint(w, buf.String())
}

func (a *Server) fail(w http.ResponseWriter, r *http.Request, status int, msg string) {
	a.render(w, r, status, "error", http.StatusText(status), "", msg)
}

func (a *Server) internalError(w http.ResponseWriter, r *http.Request, err error) {
	a.log.Error("admin: internal error", "path", r.URL.Path, "err", err)
	a.fail(w, r, http.StatusInternalServerError, "Something went wrong; the server log has details.")
}

// Post/redirect/get messages are chosen from fixed tables, so nothing in the
// query string is ever reflected into the page.
var flashes = map[string]string{
	"signedout": "Signed out every device. They'll need to sign in again.",
	"disabled":  "User disabled and signed out everywhere.",
	"enabled":   "User enabled.",
	"deleted":   "User and all their data deleted.",
	"sharedel":  "Share deleted.",
	"allowed":   "Added to the sign-up allowlist.",
	"removed":   "Removed from the sign-up allowlist.",
}

var errorsByKey = map[string]string{
	"confirm":  "The confirmation didn't match, so nothing was deleted.",
	"email":    "That doesn't look like a valid email address.",
	"exists":   "A user with that email already exists.",
	"notfound": "That entry no longer exists.",
}

func (a *Server) redirect(w http.ResponseWriter, r *http.Request, path, query string) {
	http.Redirect(w, r, path+"?"+query, http.StatusSeeOther)
}

func (a *Server) audit(r *http.Request, action string, args ...any) {
	a.log.Info("admin action", append([]any{"actor", actor(r), "action", action}, args...)...)
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

type usersData struct {
	Users      []store.UserStats
	Active     int
	Disabled   int
	TotalBytes int64
	MaxBytes   int64
	Records    int64
	Tombstones int64
	Shares     int
	DBSize     int64
	Signup     string
}

func (a *Server) users(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	users, err := a.store.UserStats(ctx)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	shares, err := a.store.ShareStats(ctx)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	dbSize, err := a.store.DBSize(ctx)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	d := usersData{Users: users, Shares: len(shares), DBSize: dbSize, Signup: a.cfg.Signup}
	for _, u := range users {
		if u.Disabled {
			d.Disabled++
		} else {
			d.Active++
		}
		d.TotalBytes += u.TotalBytes()
		d.MaxBytes = max(d.MaxBytes, u.TotalBytes())
		d.Records += u.Records
		d.Tombstones += u.Tombstones
	}
	for _, sh := range shares {
		d.Records += sh.Records
		d.Tombstones += sh.Tombstones
	}
	a.render(w, r, http.StatusOK, "users", "Users", "users", d)
}

type userData struct {
	User     *store.UserStats
	Profiles []store.ProfileStats
	Shares   []store.ShareInfo
	Sessions []store.Session
}

func (a *Server) user(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u, ok := a.lookupUser(w, r)
	if !ok {
		return
	}
	d := userData{User: u}
	var err error
	if d.Profiles, err = a.store.ProfileStats(ctx, u.ID); err == nil {
		if d.Shares, err = a.store.SharesFor(ctx, u.ID); err == nil {
			d.Sessions, err = a.store.Sessions(ctx, u.ID)
		}
	}
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	a.render(w, r, http.StatusOK, "user", u.Email, "users", d)
}

func (a *Server) lookupUser(w http.ResponseWriter, r *http.Request) (*store.UserStats, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		a.fail(w, r, http.StatusNotFound, "No such user.")
		return nil, false
	}
	u, err := a.store.UserStat(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		a.fail(w, r, http.StatusNotFound, "No such user. They may have been deleted.")
		return nil, false
	}
	if err != nil {
		a.internalError(w, r, err)
		return nil, false
	}
	return u, true
}

type codeData struct {
	UserID       int64
	Email        string
	Heading      string
	Instructions string
	Code         string
	Hours        int
}

const (
	resetInstructions = `In the app, open Cloud Sync → Sign in → "Forgot password" → "Already have a reset token? Continue", then paste this code and choose a password.`
	loginInstructions = `In the app, open Cloud Sync → "Sign in by email" → "Already have a sign-in token? Continue", then paste this code.`
)

func (a *Server) createUser(w http.ResponseWriter, r *http.Request) {
	email := api.NormalizeEmail(r.FormValue("email"))
	if email == "" {
		a.redirect(w, r, "/", "err=email")
		return
	}
	id, err := a.store.CreateUser(r.Context(), email)
	if errors.Is(err, store.ErrConflict) {
		a.redirect(w, r, "/", "err=exists")
		return
	}
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	a.audit(r, "create user", "email", email)
	a.showCode(w, r, id, email, store.PurposeReset, store.AdminResetTTL, "Account created", resetInstructions)
}

func (a *Server) showCode(w http.ResponseWriter, r *http.Request, userID int64, email, purpose string, ttl time.Duration, heading, instructions string) {
	code, err := a.store.NewEmailCode(r.Context(), email, purpose, ttl)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	a.render(w, r, http.StatusOK, "code", heading, "users", codeData{
		UserID: userID, Email: email, Heading: heading, Instructions: instructions,
		Code: code, Hours: int(ttl.Hours()),
	})
}

func (a *Server) userAction(w http.ResponseWriter, r *http.Request) {
	u, ok := a.lookupUser(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	back := fmt.Sprintf("/users/%d", u.ID)
	switch action := r.PathValue("action"); action {
	case "reset-code":
		a.audit(r, "issue reset code", "email", u.Email)
		a.showCode(w, r, u.ID, u.Email, store.PurposeReset, store.AdminResetTTL, "Password reset code", resetInstructions)
	case "login-code":
		a.audit(r, "issue sign-in code", "email", u.Email)
		a.showCode(w, r, u.ID, u.Email, store.PurposeLogin, store.AdminLoginTTL, "Sign-in code", loginInstructions)
	case "signout":
		if _, err := a.store.RevokeUserTokens(ctx, u.ID); err != nil {
			a.internalError(w, r, err)
			return
		}
		a.audit(r, "sign out everywhere", "email", u.Email)
		a.redirect(w, r, back, "done=signedout")
	case "disable", "enable":
		if err := a.store.SetDisabled(ctx, u.ID, action == "disable"); err != nil {
			a.internalError(w, r, err)
			return
		}
		a.audit(r, action+" user", "email", u.Email)
		a.redirect(w, r, back, "done="+action+"d")
	case "delete":
		if !strings.EqualFold(strings.TrimSpace(r.FormValue("confirm")), u.Email) {
			a.redirect(w, r, back, "err=confirm")
			return
		}
		if err := a.store.DeleteUser(ctx, u.ID); err != nil {
			a.internalError(w, r, err)
			return
		}
		a.audit(r, "delete user", "email", u.Email, "bytes", u.TotalBytes())
		a.redirect(w, r, "/", "done=deleted")
	default:
		a.fail(w, r, http.StatusNotFound, "Unknown action.")
	}
}

// ---------------------------------------------------------------------------
// Shares
// ---------------------------------------------------------------------------

type sharesData struct {
	Shares   []store.ShareStats
	MaxBytes int64
}

func (a *Server) shares(w http.ResponseWriter, r *http.Request) {
	shares, err := a.store.ShareStats(r.Context())
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	d := sharesData{Shares: shares}
	for _, sh := range shares {
		d.MaxBytes = max(d.MaxBytes, sh.Bytes)
	}
	a.render(w, r, http.StatusOK, "shares", "Shares", "shares", d)
}

type shareData struct {
	Share   *store.ShareStats
	Members []store.MemberInfo
}

func (a *Server) share(w http.ResponseWriter, r *http.Request) {
	sh, ok := a.lookupShare(w, r)
	if !ok {
		return
	}
	members, err := a.store.Members(r.Context(), sh.ShareID)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	a.render(w, r, http.StatusOK, "share", sh.Name, "shares", shareData{Share: sh, Members: members})
}

func (a *Server) deleteShare(w http.ResponseWriter, r *http.Request) {
	sh, ok := a.lookupShare(w, r)
	if !ok {
		return
	}
	if strings.TrimSpace(r.FormValue("confirm")) != sh.Name {
		a.redirect(w, r, "/shares/"+sh.ShareID, "err=confirm")
		return
	}
	if err := a.store.DeleteShare(r.Context(), sh.ShareID); err != nil {
		a.internalError(w, r, err)
		return
	}
	a.audit(r, "delete share", "share_id", sh.ShareID, "name", sh.Name, "owner", sh.OwnerEmail)
	a.redirect(w, r, "/shares", "done=sharedel")
}

func (a *Server) lookupShare(w http.ResponseWriter, r *http.Request) (*store.ShareStats, bool) {
	sh, err := a.store.ShareStat(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		a.fail(w, r, http.StatusNotFound, "No such share. It may have been deleted.")
		return nil, false
	}
	if err != nil {
		a.internalError(w, r, err)
		return nil, false
	}
	return sh, true
}

// ---------------------------------------------------------------------------
// Sign-up
// ---------------------------------------------------------------------------

type signupData struct {
	Mode      string
	Allowlist []string
}

func (a *Server) signup(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.Allowlist(r.Context())
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	a.render(w, r, http.StatusOK, "signup", "Sign-up", "signup", signupData{Mode: a.cfg.Signup, Allowlist: list})
}

func (a *Server) allow(w http.ResponseWriter, r *http.Request) {
	email := api.NormalizeEmail(r.FormValue("email"))
	if email == "" {
		a.redirect(w, r, "/signup", "err=email")
		return
	}
	if err := a.store.AllowlistAdd(r.Context(), email); err != nil {
		a.internalError(w, r, err)
		return
	}
	a.audit(r, "allowlist add", "email", email)
	a.redirect(w, r, "/signup", "done=allowed")
}

func (a *Server) unallow(w http.ResponseWriter, r *http.Request) {
	email := api.NormalizeEmail(r.FormValue("email"))
	removed, err := a.store.AllowlistRemove(r.Context(), email)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	if !removed {
		a.redirect(w, r, "/signup", "err=notfound")
		return
	}
	a.audit(r, "allowlist remove", "email", email)
	a.redirect(w, r, "/signup", "done=removed")
}

// ---------------------------------------------------------------------------
// Template helpers
// ---------------------------------------------------------------------------

func (a *Server) funcs() template.FuncMap {
	return template.FuncMap{
		"bytes": humanBytes,
		"num":   thousands,
		// count renders "1 record" / "1,204 records".
		"count": func(n int64, unit string) string {
			if n == 1 {
				return "1 " + unit
			}
			return thousands(n) + " " + unit + "s"
		},
		"ago": func(t time.Time) string { return ago(a.now(), t) },
		"when": func(t time.Time) string {
			if t.IsZero() {
				return ""
			}
			return t.UTC().Format("2006-01-02 15:04 UTC")
		},
		// pct is a bar width in whole percent; any non-zero value gets at
		// least 1% so it stays visible.
		"pct": func(n, top int64) int64 {
			if n <= 0 || top <= 0 {
				return 0
			}
			return min(100, max(1, n*100/top))
		},
	}
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

func thousands(n int64) string {
	s := strconv.FormatInt(n, 10)
	if n < 0 {
		return "-" + thousands(-n)
	}
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func ago(now, t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return plural(int(d.Minutes()), "minute") + " ago"
	case d < 48*time.Hour:
		return plural(int(d.Hours()), "hour") + " ago"
	case d < 60*24*time.Hour:
		return plural(int(d.Hours()/24), "day") + " ago"
	default:
		return t.UTC().Format("2006-01-02")
	}
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}
