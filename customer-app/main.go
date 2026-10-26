// Customer Manager: a CoreLink sample application.
//
// An ordinary application that lists customers from PostgreSQL, with no
// database password in its configuration, image or environment. It asks the
// CoreLink connector running beside it for a sealed envelope, opens it under
// its own identity's grant, and connects with the dynamic credential inside.
// When the credential rotates it reconnects on the new one by itself.
//
// Environment variables:
//
//	PLATFORM_URL  your CoreLink URL, for the identity's connect (required)
//	NHI_ID        this application's identity (required unless a deployment file names it)
//	SECRET_NAME   the dynamic credential's secret name (required unless a deployment file names it)
//	WATCH_INTERVAL how often to check the credential (default 5s)
//	TRANSIT_URL   the connector's envelope cache (default http://127.0.0.1:9092)
//	DB_SSLMODE    override the credential's sslmode (default: the one CoreLink
//	              issued, else "prefer")
//
// Or, instead of NHI_ID and SECRET_NAME, a deployment file at
// /etc/corelink/secrets.yaml (override with CORELINK_DEPLOYMENT_FILE) naming the
// identity to attest as and the secrets to ask for. It grants nothing; the grant
// on the identity is what CoreLink checks.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Tech-Blend-Consulting/corelink-apps/transit"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// credBundle is the JSON structure stored in the DB credential secret.
type credBundle struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Host     string `json:"host"`
	Port     string `json:"port"`
	Database string `json:"database"`
	// ConnectionString carries the sslmode the connection was configured with.
	ConnectionString string `json:"connection_string"`
}

// dbPool wraps *sql.DB with the credential used to open it.
type dbPool struct {
	db       *sql.DB
	username string
}

// App holds all runtime state.
type App struct {
	mu             sync.RWMutex
	pool           *dbPool
	currentCred    credBundle
	lastCredChange time.Time
	connError      string
	configs        []transit.Config
	configsErr     string
	transitURL     string
	secretName     string
	configSource   string

	// What the live status panel shows, kept by the watcher's callbacks.
	tc       *transit.Client
	identity partStatus // this application's identity
	secret   partStatus // the credential secret
}

// partStatus is one card of the live status panel.
type partStatus struct {
	ID     string    `json:"id,omitempty"`
	Name   string    `json:"name,omitempty"`
	State  string    `json:"state"`  // the badge: ok, warn, bad
	Label  string    `json:"label"`  // what the badge says
	Detail string    `json:"detail"` // a sentence of explanation
	Reason string    `json:"reason,omitempty"`
	Since  time.Time `json:"since"`
}

// set changes a part's status, keeping since when nothing changed. The
// caller holds a.mu.
func (p *partStatus) set(state, label, detail, reason string) {
	if p.State != state || p.Label != label || p.Reason != reason {
		p.Since = time.Now()
	}
	p.State, p.Label, p.Detail, p.Reason = state, label, detail, reason
}

// withheldText says, for a person, why CoreLink withholds the secret.
func withheldText(reason string) (label, detail string) {
	switch reason {
	case transit.ReasonSecretDisabled:
		return "Disabled", "The secret is disabled in CoreLink. Nothing delivers it until it is enabled."
	case transit.ReasonConnectionLocked:
		return "Connection locked", "Its database connection is locked in CoreLink. Nothing delivers it until the connection is unlocked."
	case transit.ReasonIdentityRefused:
		return "Identity suspended", "CoreLink refuses this application's identity: it is suspended, or no longer verifies."
	case transit.ReasonConnectorRefused:
		return "Connector refused", "CoreLink refuses the connector's identity: it is suspended, or no longer verifies."
	}
	return "Withheld", "CoreLink is withholding the secret."
}

func main() {
	transitURL := envOr("TRANSIT_URL", "http://127.0.0.1:9092")
	platformURL := os.Getenv("PLATFORM_URL")
	nhiID := os.Getenv("NHI_ID")
	secretName := os.Getenv("SECRET_NAME")
	configSource := "environment"

	// The deployment file, if the deployment carries one.
	//
	// It names the identity to attest as and the secrets to ask for, and nothing
	// else: it grants nothing, and CoreLink checks the grant on the NHI whatever
	// this file says. Neither value is sensitive -- the NHI id is a pointer, and
	// presenting someone else's fails the claim match at Connect.
	//
	// A missing file is not an error, because an application may be configured
	// either way. A file that exists and does not parse is, because running on a
	// configuration nobody wrote is the wrong recovery.
	dep, depErr := transit.LoadDeploymentIfPresent("")
	if depErr != nil {
		log.Fatalf("Deployment file: %v", depErr)
	}
	if dep != nil {
		// A pod whose file names one ServiceAccount while the pod spec says
		// another will fail at CoreLink with a claim mismatch, later and less
		// obviously. This is a misconfiguration check, not a security control:
		// CoreLink verifies the token properly and decides.
		if err := dep.VerifyServiceAccount(); err != nil {
			log.Fatalf("%v", err)
		}
		nhiID = dep.NHIID
		secretName = dep.Secrets[0]
		configSource = dep.Path
		log.Printf("Deployment file %s: identity %s, secrets %v",
			dep.Path, dep.NHIID, dep.Secrets)
	}

	if nhiID == "" {
		log.Fatal("no identity: set NHI_ID, or deploy a secrets.yaml naming nhiId")
	}
	if secretName == "" {
		log.Fatal("no secret: set SECRET_NAME, or deploy a secrets.yaml listing it")
	}
	if platformURL == "" {
		log.Fatal("PLATFORM_URL environment variable is required")
	}

	opts := transit.Options{
		TransitURL:  transitURL,
		PlatformURL: platformURL,
		NHIID:       nhiID,
	}

	tc := transit.New(opts)
	defer tc.Close()

	app := &App{
		transitURL:   transitURL,
		secretName:   secretName,
		configSource: configSource,
		tc:           tc,
	}
	app.identity.ID = nhiID
	app.identity.set("warn", "Connecting", "Connecting to CoreLink as this identity.", "")
	app.secret.Name = secretName
	app.secret.set("warn", "Waiting", "Not delivered yet.", "")

	http.HandleFunc("/", app.handleIndex)
	http.HandleFunc("/api/status", app.handleStatus)
	http.HandleFunc("/customers/add", app.handleAdd)
	http.HandleFunc("/customers/update", app.handleUpdate)
	http.HandleFunc("/customers/delete", app.handleDelete)

	// The page comes up first, so what follows can be watched on it: a first
	// connect that waits for approval, or an identity that is refused.
	go app.run(tc, dep)

	// Loopback unless told otherwise. This page names the database user the app
	// is currently connected as, which is the point of the demo and also a thing
	// worth not publishing to the network. The container cannot be reached
	// through a published port while bound to loopback, so the compose file sets
	// this and confines its own publish to the host's loopback instead.
	bindAddr := os.Getenv("SAMPLE_BIND_ADDR")
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}
	addr := bindAddr + ":5051"
	log.Printf("Customer app listening on http://%s", addr)
	log.Printf("Transit API: %s  Secret: %s", transitURL, secretName)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal(err)
	}
}

// run connects to CoreLink and watches the credential. A refused or failed
// connect is retried and shown on the page, not fatal, so a suspended identity
// or a first connect waiting for approval can be watched as it happens.
func (a *App) run(tc *transit.Client, dep *transit.Deployment) {
	for wait := time.Second; ; wait = min(wait*2, 30*time.Second) {
		err := tc.Bootstrap()
		if err == nil {
			break
		}
		a.mu.Lock()
		if errors.Is(err, transit.ErrIdentityRefused) {
			label, detail := withheldText(transit.ReasonIdentityRefused)
			a.identity.set("bad", label, detail, transit.ReasonIdentityRefused)
		} else {
			a.identity.set("warn", "Connecting", "Could not connect to CoreLink yet: "+err.Error(), "")
		}
		a.mu.Unlock()
		log.Printf("Transit bootstrap failed (%v); retrying in %s", err, wait)
		time.Sleep(wait)
	}
	a.connected()

	// Resolve the whole list at startup.
	//
	// A name the identity has no grant for, a secret that does not exist, or an
	// id that does not match the attested identity is reported now rather than
	// at three in the morning when a code path runs for the first time. Resolve
	// checks both halves: that the grants cover the name, and that a connector
	// actually holds an envelope for it. Shown on the page and logged; the
	// watcher keeps trying, so a secret that becomes available is picked up.
	wanted := []string{a.secretName}
	if dep != nil {
		wanted = dep.Secrets
	}
	if err := tc.Resolve(wanted...); err != nil {
		log.Printf("Startup check failed (configured by %s): %v", a.configSource, err)
	} else {
		log.Printf("Startup check passed: %v", wanted)
	}

	interval := 5 * time.Second
	if v, err := time.ParseDuration(os.Getenv("WATCH_INTERVAL")); err == nil && v > 0 {
		interval = v
	}
	w := transit.NewWatcher(tc, interval)

	// Watch the DB credential secret; reconnect on change.
	w.WatchSecret(a.secretName, func(raw string) {
		a.reloadFromValue(raw)
		a.connected()
		a.mu.Lock()
		a.secret.set("ok", "Delivered", "Opened from the connector's envelope with the key CoreLink handed this identity.", "")
		a.mu.Unlock()
	})
	// Withheld in CoreLink (disabled, connection locked, identity suspended): stop
	// using what this process already holds. Nothing delivers it again until
	// that is undone, when WatchSecret fires again.
	w.OnUnavailable(func(name string, err error) {
		a.withdraw(err)
	})
	// Every failed fetch, for the status panel.
	w.OnError(func(name string, err error) {
		reason := transit.WithheldReason(err)
		a.mu.Lock()
		defer a.mu.Unlock()
		switch {
		case reason == transit.ReasonIdentityRefused:
			label, detail := withheldText(reason)
			a.identity.set("bad", label, detail, reason)
			a.secret.set("bad", label, detail, reason)
		case reason != "":
			label, detail := withheldText(reason)
			a.secret.set("bad", label, detail, reason)
		default:
			a.secret.set("warn", "Unavailable", "Could not fetch it: "+err.Error(), "")
		}
	})

	// No config watch. The connector's /v1/configs endpoint answers 410 Gone:
	// config delivery went the same way as plaintext secret delivery, because it
	// was the same thing in a different shape -- the connector handing over a
	// readable value. Watching it here produced a permanent error in the page
	// rather than a feature, so it is removed rather than left failing.
	a.mu.Lock()
	a.configsErr = "config delivery was removed from the connector; secrets arrive as sealed envelopes"
	a.mu.Unlock()

	w.Start()
}

// connected records that CoreLink accepts this identity, and learns its name.
func (a *App) connected() {
	a.mu.RLock()
	named := a.identity.Name != ""
	a.mu.RUnlock()
	var who transit.Identity
	if !named {
		if id, err := a.tc.WhoAmI(); err == nil {
			who = id
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if who.Name != "" {
		a.identity.Name = who.Name
	}
	a.identity.set("ok", "Connected", "CoreLink accepts this identity.", "")
}

// connectorStatus is what the connector says about itself on /v1/status.
type connectorStatus struct {
	Connector struct {
		NHIID string `json:"nhi_id"`
		Name  string `json:"name"`
	} `json:"connector"`
	Session       string    `json:"session"`
	Since         time.Time `json:"since"`
	Platform      string    `json:"platform"`
	EnvelopesHeld int       `json:"envelopes_held"`
}

// connectorPart asks the connector for its status, live.
func (a *App) connectorPart() map[string]any {
	out := map[string]any{"url": a.transitURL}
	client := http.Client{Timeout: time.Second}
	resp, err := client.Get(strings.TrimSuffix(a.transitURL, "/") + "/v1/status")
	if err != nil {
		out["state"], out["label"], out["detail"] = "bad", "Unreachable", "The connector does not answer."
		return out
	}
	defer resp.Body.Close()
	var st connectorStatus
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&st) != nil {
		out["state"], out["label"], out["detail"] = "warn", "Unknown", "This connector does not report its status (an older version)."
		return out
	}
	out["id"], out["name"], out["since"], out["envelopes_held"], out["platform"] =
		st.Connector.NHIID, st.Connector.Name, st.Since, st.EnvelopesHeld, st.Platform
	switch st.Session {
	case "connected":
		out["state"], out["label"], out["detail"] = "ok", "Connected", "Holding sealed envelopes it cannot open."
	case "refused":
		label, detail := withheldText(transit.ReasonConnectorRefused)
		out["state"], out["label"], out["detail"] = "bad", label, detail+" It serves nothing."
	default:
		out["state"], out["label"], out["detail"] = "warn", "Connecting", "Connecting to CoreLink."
	}
	return out
}

// databasePart says whether the pool is open and answering.
func (a *App) databasePart() map[string]any {
	a.mu.RLock()
	pool, cred, connErr := a.pool, a.currentCred, a.connError
	a.mu.RUnlock()
	out := map[string]any{}
	if pool == nil {
		out["state"], out["label"] = "bad", "Disconnected"
		out["detail"] = "No connection is open."
		if connErr != "" {
			out["detail"] = connErr
		}
		return out
	}
	out["user"], out["target"] = cred.Username, fmt.Sprintf("%s:%s/%s", cred.Host, cred.Port, cred.Database)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := pool.db.PingContext(ctx); err != nil {
		out["state"], out["label"], out["detail"] = "bad", "Failing", "The database does not accept the connection: "+err.Error()
		return out
	}
	out["state"], out["label"], out["detail"] = "ok", "Connected", "Connected as the dynamic user."
	return out
}

// handleStatus serves the live status panel's data. Nothing in it is secret:
// identity ids are pointers, and the dynamic user's name is shown on the page.
func (a *App) handleStatus(w http.ResponseWriter, _ *http.Request) {
	a.mu.RLock()
	identity, secret := a.identity, a.secret
	a.mu.RUnlock()
	body := map[string]any{
		"identity":  identity,
		"connector": a.connectorPart(),
		"secret":    secret,
		"database":  a.databasePart(),
		"at":        time.Now().UTC(),
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(body)
}

// reloadFromValue parses raw (JSON credential), reconnects to the DB if the
// credential has changed.
func (a *App) reloadFromValue(raw string) {
	var cred credBundle
	if err := json.Unmarshal([]byte(raw), &cred); err != nil {
		a.mu.Lock()
		a.connError = fmt.Sprintf("Failed to parse credential JSON: %v", err)
		a.mu.Unlock()
		return
	}
	if cred.Username == "" || cred.Password == "" {
		a.mu.Lock()
		a.connError = "credential missing username or password"
		a.mu.Unlock()
		return
	}

	a.mu.Lock()
	same := a.currentCred.Username == cred.Username && a.currentCred.Password == cred.Password
	hasPool := a.pool != nil
	a.mu.Unlock()

	if same && hasPool {
		a.mu.Lock()
		a.connError = ""
		a.mu.Unlock()
		return
	}

	db, err := openDB(cred)
	if err != nil {
		a.mu.Lock()
		a.connError = fmt.Sprintf("DB connect as %s failed: %v", cred.Username, err)
		a.mu.Unlock()
		return
	}

	a.mu.Lock()
	if a.pool != nil {
		a.pool.db.Close()
	}
	a.pool = &dbPool{db: db, username: cred.Username}
	a.currentCred = cred
	a.lastCredChange = time.Now()
	a.connError = ""
	a.mu.Unlock()

	log.Printf("Connected to %s as %s (via transit)", cred.Database, cred.Username)
}

func openDB(cred credBundle) (*sql.DB, error) {
	port := cred.Port
	if port == "" {
		port = "5432"
	}
	// Built from the separate fields, each quoted, so a password with any
	// character in it is passed exactly; only the sslmode is taken from the
	// connection string CoreLink issued.
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		dsnQuote(cred.Host), dsnQuote(port), dsnQuote(cred.Username), dsnQuote(cred.Password),
		dsnQuote(cred.Database), dsnQuote(sslMode(cred)))
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// sslMode is DB_SSLMODE when set, else the sslmode in the credential's
// connection string, else "prefer": TLS when the server offers it, which a
// managed database such as Azure Database for PostgreSQL requires.
func sslMode(cred credBundle) string {
	if v := os.Getenv("DB_SSLMODE"); v != "" {
		return v
	}
	if u, err := url.Parse(cred.ConnectionString); err == nil {
		if v := u.Query().Get("sslmode"); v != "" {
			return v
		}
	}
	return "prefer"
}

// dsnQuote quotes a value for a libpq key=value connection string.
func dsnQuote(v string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(v) + "'"
}

// withdraw drops the database pool and the credential it was opened with.
func (a *App) withdraw(err error) {
	a.mu.Lock()
	if a.pool != nil {
		a.pool.db.Close()
		a.pool = nil
	}
	a.currentCred = credBundle{}
	_, why := withheldText(transit.WithheldReason(err))
	a.connError = "The credential was withdrawn. " + why +
		" Connections opened with it are closed; it comes back when that is undone."
	a.mu.Unlock()
	log.Printf("Credential withdrawn: %v", err)
}

// --- Domain ---

type customer struct {
	ID        int
	Name      string
	Email     string
	Plan      string
	Country   string
	CreatedAt string
}

func (a *App) listCustomers() ([]customer, error) {
	a.mu.RLock()
	pool := a.pool
	a.mu.RUnlock()
	if pool == nil {
		return nil, fmt.Errorf("not connected")
	}
	rows, err := pool.db.Query(
		`SELECT id, full_name, email, tier, country, to_char(created_at, 'Mon DD, YYYY') FROM customers ORDER BY id`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []customer
	for rows.Next() {
		var c customer
		if err := rows.Scan(&c.ID, &c.Name, &c.Email, &c.Plan, &c.Country, &c.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, c)
	}
	return list, rows.Err()
}

func (a *App) addCustomer(name, email, plan, country string) error {
	a.mu.RLock()
	pool := a.pool
	a.mu.RUnlock()
	if pool == nil {
		return fmt.Errorf("not connected")
	}
	if plan == "" {
		plan = "free"
	}
	if country == "" {
		country = "US"
	}
	_, err := pool.db.Exec(
		`INSERT INTO customers (full_name, email, tier, country, created_at) VALUES ($1, $2, $3, $4, now())`,
		name, email, plan, country,
	)
	return err
}

func (a *App) updateCustomer(id int, name, email, plan string) error {
	a.mu.RLock()
	pool := a.pool
	a.mu.RUnlock()
	if pool == nil {
		return fmt.Errorf("not connected")
	}
	_, err := pool.db.Exec(
		`UPDATE customers SET full_name=$1, email=$2, tier=$3 WHERE id=$4`,
		name, email, plan, id,
	)
	return err
}

func (a *App) deleteCustomer(id int) error {
	a.mu.RLock()
	pool := a.pool
	a.mu.RUnlock()
	if pool == nil {
		return fmt.Errorf("not connected")
	}
	_, err := pool.db.Exec(`DELETE FROM customers WHERE id = $1`, id)
	return err
}

// --- HTTP handlers ---

func (a *App) handleAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	email := strings.TrimSpace(r.FormValue("email"))
	plan := r.FormValue("plan")
	country := strings.ToUpper(strings.TrimSpace(r.FormValue("country")))
	if name == "" || email == "" {
		http.Redirect(w, r, "/?error=Name+and+email+are+required", http.StatusSeeOther)
		return
	}
	if err := a.addCustomer(name, email, plan, country); err != nil {
		http.Redirect(w, r, "/?error="+template.URLQueryEscaper(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil || id <= 0 {
		http.Redirect(w, r, "/?error=Invalid+customer+ID", http.StatusSeeOther)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	email := strings.TrimSpace(r.FormValue("email"))
	plan := r.FormValue("plan")
	if name == "" || email == "" {
		http.Redirect(w, r, "/?error=Name+and+email+are+required", http.StatusSeeOther)
		return
	}
	if err := a.updateCustomer(id, name, email, plan); err != nil {
		http.Redirect(w, r, "/?error="+template.URLQueryEscaper(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) handleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil || id <= 0 {
		http.Redirect(w, r, "/?error=Invalid+customer+ID", http.StatusSeeOther)
		return
	}
	if err := a.deleteCustomer(id); err != nil {
		http.Redirect(w, r, "/?error="+template.URLQueryEscaper(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

type pageData struct {
	Customers      []customer
	ConnectedAs    string
	ConnectedTo    string
	ConnError      string
	LastCredChange string
	TransitURL     string
	SecretName     string
	ErrorMsg       string
	// What the connector is holding for this secret, fetched straight from its
	// envelope cache. The point of showing it is that this is all the connector
	// has: ciphertext under a key it was never given.
	SealedID      string
	SealedVersion int
	SealedCipher  string
	SealedErr     string
	// Where the identity and the secret names came from: a deployment file, or
	// the environment.
	ConfigSource string
}

// peekEnvelope asks the connector for the sealed envelope, exactly as any
// caller on the box could.
//
// It is unauthenticated on purpose -- what it serves cannot be opened without a
// grant CoreLink checks -- so this needs no credential and proves the point: the
// page can show you the ciphertext precisely because possession of it is worth
// nothing.
func (a *App) peekEnvelope() (id string, version int, cipher string, errMsg string) {
	url := strings.TrimSuffix(a.transitURL, "/") + "/v1/envelopes/" + a.secretName
	resp, err := http.Get(url)
	if err != nil {
		return "", 0, "", err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusConflict {
		var e struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.NewDecoder(resp.Body).Decode(&e) == nil && e.Error.Message != "" {
			return "", 0, "", "The connector withholds it: " + e.Error.Message + "."
		}
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, "", fmt.Sprintf("the connector answered HTTP %d", resp.StatusCode)
	}
	var body struct {
		SecretID string `json:"secret_id"`
		Version  int    `json:"version"`
		Envelope string `json:"envelope"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", 0, "", err.Error()
	}
	return body.SecretID, body.Version, body.Envelope, ""
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	pool := a.pool
	cred := a.currentCred
	connErr := a.connError
	lastChange := a.lastCredChange
	a.mu.RUnlock()

	errMsg := r.URL.Query().Get("error")

	var customers []customer
	if pool != nil {
		var listErr error
		customers, listErr = a.listCustomers()
		if listErr != nil && connErr == "" {
			connErr = listErr.Error()
		}
	}

	var lastChangeStr string
	if !lastChange.IsZero() {
		lastChangeStr = lastChange.Format("Jan 2, 2006 3:04:05 PM")
	}

	data := pageData{
		Customers:      customers,
		ConnectedAs:    cred.Username,
		ConnectedTo:    fmt.Sprintf("%s:%s/%s", cred.Host, cred.Port, cred.Database),
		ConnError:      connErr,
		LastCredChange: lastChangeStr,
		TransitURL:     a.transitURL,
		SecretName:     a.secretName,
		ErrorMsg:       errMsg,
		ConfigSource:   a.configSource,
	}

	data.SealedID, data.SealedVersion, data.SealedCipher, data.SealedErr = a.peekEnvelope()

	t := template.Must(template.New("page").Parse(pageHTML))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, data); err != nil {
		log.Printf("template error: %v", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return strings.TrimRight(v, "/")
	}
	return fallback
}

const pageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Customer Manager - Dynamic DB Credentials</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root {
  --bg: #0f1117;
  --surface: #1a1d27;
  --surface-hi: #22252f;
  --border: rgba(255,255,255,0.07);
  --text: #e2e8f0;
  --text-2: #94a3b8;
  --text-3: #64748b;
  --primary: #0ea5e9;
  --primary-bg: rgba(14,165,233,0.1);
  --success: #22c55e;
  --success-bg: rgba(34,197,94,0.1);
  --danger: #ef4444;
  --danger-bg: rgba(239,68,68,0.1);
  --warning: #f59e0b;
  --warning-bg: rgba(245,158,11,0.1);
  --radius: 10px;
  --mono: 'JetBrains Mono','SF Mono','Fira Code',monospace;
}
body{font-family:-apple-system,BlinkMacSystemFont,'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;min-height:100vh}
.container{max-width:1400px;margin:0 auto;padding:2rem 2rem}
.header{display:flex;align-items:center;justify-content:space-between;margin-bottom:2rem;padding-bottom:1.5rem;border-bottom:1px solid var(--border)}
.header h1{font-size:1.4rem;font-weight:600;letter-spacing:-0.02em}
.header h1 span{color:var(--primary)}
.badge{display:inline-flex;align-items:center;gap:0.35rem;padding:0.25rem 0.65rem;border-radius:9999px;font-size:0.75rem;font-weight:500}
.badge--go{background:rgba(0,173,216,0.1);color:#00ADD8;font-family:var(--mono)}
.badge--ok{background:var(--success-bg);color:var(--success)}
.badge--err{background:var(--danger-bg);color:var(--danger)}
.dot{width:7px;height:7px;border-radius:50%;background:currentColor}
.badge--ok .dot{animation:pulse 2s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}
.cred-bar{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:0.85rem 1.25rem;margin-bottom:1.5rem;display:flex;align-items:center;flex-wrap:wrap;gap:0.75rem 1.5rem}
.cred-bar__label{font-size:0.75rem;color:var(--text-3);text-transform:uppercase;letter-spacing:0.04em}
.cred-bar__val{font-family:var(--mono);font-size:0.82rem;color:var(--text-2)}
.cred-bar__user{font-family:var(--mono);font-size:0.82rem;color:var(--primary);font-weight:600}
.cred-bar__item{display:flex;flex-direction:column;gap:0.15rem}
.status-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:1rem;margin-bottom:1.5rem}
@media(max-width:1100px){.status-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:600px){.status-grid{grid-template-columns:1fr}}
.status-card{background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--border);border-radius:var(--radius);padding:0.85rem 1rem;display:flex;flex-direction:column;gap:0.3rem;min-width:0}
.status-card--ok{border-left-color:var(--success)}
.status-card--warn{border-left-color:var(--warning)}
.status-card--bad{border-left-color:var(--danger)}
.status-card__hdr{display:flex;align-items:center;justify-content:space-between;gap:0.5rem}
.status-card__title{font-size:0.72rem;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-3)}
.status-card__main{font-size:0.88rem;color:var(--text);overflow-wrap:anywhere}
.status-card__sub{font-size:0.75rem;color:var(--text-3);overflow-wrap:anywhere}
.status-card__detail{font-size:0.8rem;color:var(--text-2)}
.status-card__since{font-size:0.72rem;color:var(--text-3)}
.badge--warn{background:var(--warning-bg);color:var(--warning)}
.mono{font-family:var(--mono)}
.alert{padding:0.75rem 1rem;border-radius:var(--radius);margin-bottom:1.25rem;font-size:0.875rem}
.alert--err{background:var(--danger-bg);border:1px solid rgba(239,68,68,0.25);color:var(--danger)}
.alert--warn{background:var(--warning-bg);border:1px solid rgba(245,158,11,0.2);color:var(--warning)}
.layout{display:grid;grid-template-columns:1fr 320px;gap:1.5rem;align-items:start}
@media(max-width:900px){.layout{grid-template-columns:1fr}}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden}
.card__hdr{display:flex;align-items:center;justify-content:space-between;padding:0.9rem 1.25rem;border-bottom:1px solid var(--border)}
.card__title{font-size:0.95rem;font-weight:600}
.card__count{font-family:var(--mono);font-size:0.75rem;padding:0.15rem 0.5rem;border-radius:9999px;background:var(--surface-hi);color:var(--text-3)}
table{width:100%;border-collapse:collapse;table-layout:fixed}
th{padding:0.6rem 1rem;text-align:left;font-size:0.72rem;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-3);border-bottom:1px solid var(--border)}
td{padding:0.65rem 1rem;border-bottom:1px solid var(--border);font-size:0.875rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tr:last-child td{border-bottom:none}
tr:hover td{background:var(--surface-hi)}
col.col-id{width:52px}
col.col-name{width:18%}
col.col-email{width:26%}
col.col-plan{width:100px}
col.col-created{width:130px}
col.col-actions{width:150px}
.plan{display:inline-block;padding:0.15rem 0.5rem;border-radius:9999px;font-size:0.72rem;font-weight:600;text-transform:uppercase;letter-spacing:0.03em}
.plan--free{background:var(--surface-hi);color:var(--text-3)}
.plan--pro{background:var(--primary-bg);color:var(--primary)}
.plan--enterprise{background:var(--success-bg);color:var(--success)}
/* hidden must win over the display rules below, or toggling it does nothing. */
[hidden]{display:none!important}
.btn{display:inline-flex;align-items:center;gap:0.35rem;padding:0.3rem 0.7rem;border-radius:6px;font-size:0.78rem;font-weight:500;border:none;cursor:pointer;text-decoration:none;transition:opacity 0.15s;white-space:nowrap}
.btn--danger{background:var(--danger-bg);color:var(--danger);border:1px solid rgba(239,68,68,0.2)}
.btn--danger:hover{opacity:0.8}
.btn--primary{background:var(--primary);color:#fff}
.btn--primary:hover{opacity:0.85}
.btn--ghost{background:var(--surface-hi);color:var(--text-2);border:1px solid var(--border)}
.btn--ghost:hover{color:var(--text)}
.row-actions{display:flex;align-items:center;gap:0.4rem}
.sidebar{display:flex;flex-direction:column;gap:1.25rem}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden}
.panel__hdr{padding:0.85rem 1.15rem;border-bottom:1px solid var(--border);font-size:0.9rem;font-weight:600}
.form-body{padding:1.15rem;display:flex;flex-direction:column;gap:0.8rem}
.field{display:flex;flex-direction:column;gap:0.3rem}
.field label{font-size:0.72rem;font-weight:500;color:var(--text-3);text-transform:uppercase;letter-spacing:0.04em}
.input,.select{background:var(--surface-hi);border:1px solid var(--border);border-radius:6px;color:var(--text);padding:0.45rem 0.7rem;font-size:0.875rem;width:100%;outline:none;transition:border-color 0.15s}
.input:focus,.select:focus{border-color:var(--primary)}
.select option{background:var(--surface)}
.empty{padding:3rem 1.25rem;text-align:center;color:var(--text-3);font-size:0.9rem}
.footer{margin-top:2rem;padding-top:1rem;border-top:1px solid var(--border);font-size:0.78rem;color:var(--text-3);display:flex;justify-content:space-between;flex-wrap:wrap;gap:0.5rem}
.mono{font-family:var(--mono)}
/* Edit modal */
dialog{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);padding:0;width:420px;max-width:95vw;box-shadow:0 25px 60px rgba(0,0,0,0.6)}
dialog::backdrop{background:rgba(0,0,0,0.55)}
.dialog__hdr{display:flex;align-items:center;justify-content:space-between;padding:1rem 1.25rem;border-bottom:1px solid var(--border)}
.dialog__title{font-size:0.95rem;font-weight:600}
.dialog__close{background:none;border:none;color:var(--text-3);cursor:pointer;font-size:1.2rem;line-height:1;padding:0.1rem 0.3rem;border-radius:4px}
.dialog__close:hover{color:var(--text);background:var(--surface-hi)}
.dialog__footer{display:flex;justify-content:flex-end;gap:0.6rem;padding:1rem 1.25rem;border-top:1px solid var(--border)}
</style>
</head>
<body>
<div class="container">

  <div class="header">
    <h1><span>Customer</span> Manager</h1>
    <div style="display:flex;align-items:center;gap:0.75rem">
      <span class="badge badge--go">Go</span>
      <span class="badge {{if .ConnectedAs}}badge--ok{{else}}badge--err{{end}}" id="hdr-badge"><span class="dot"></span> <span id="hdr-label">{{if .ConnectedAs}}Connected{{else}}Disconnected{{end}}</span></span>
    </div>
  </div>

  <!-- Live status: refreshed every 2 seconds from /api/status -->
  <div class="status-grid" id="status" aria-live="polite">
    <div class="status-card" id="st-identity">
      <div class="status-card__hdr"><span class="status-card__title">This app's identity</span><span class="badge st-badge">...</span></div>
      <div class="status-card__main st-main mono"></div>
      <div class="status-card__sub st-sub mono"></div>
      <div class="status-card__detail st-detail"></div>
      <div class="status-card__since st-since"></div>
    </div>
    <div class="status-card" id="st-connector">
      <div class="status-card__hdr"><span class="status-card__title">Connector</span><span class="badge st-badge">...</span></div>
      <div class="status-card__main st-main mono"></div>
      <div class="status-card__sub st-sub mono"></div>
      <div class="status-card__detail st-detail"></div>
      <div class="status-card__since st-since"></div>
    </div>
    <div class="status-card" id="st-secret">
      <div class="status-card__hdr"><span class="status-card__title">Credential secret</span><span class="badge st-badge">...</span></div>
      <div class="status-card__main st-main mono">{{.SecretName}}</div>
      <div class="status-card__sub st-sub mono">configured by {{.ConfigSource}}{{if .LastCredChange}} &middot; last rotation {{.LastCredChange}}{{end}}</div>
      <div class="status-card__detail st-detail"></div>
      <div class="status-card__since st-since"></div>
    </div>
    <div class="status-card" id="st-database">
      <div class="status-card__hdr"><span class="status-card__title">Database</span><span class="badge st-badge">...</span></div>
      <div class="status-card__main st-main mono"></div>
      <div class="status-card__sub st-sub mono"></div>
      <div class="status-card__detail st-detail"></div>
      <div class="status-card__since st-since"></div>
    </div>
  </div>

  {{if .ConnError}}
  <div class="alert alert--warn">{{.ConnError}}</div>
  {{end}}

  {{if .ErrorMsg}}
  <div class="alert alert--err">{{.ErrorMsg}}</div>
  {{end}}

  <div class="layout">

    <!-- Customer table -->
    <div class="card">
      <div class="card__hdr">
        <span class="card__title">Customers</span>
        <span class="card__count">{{len .Customers}} records</span>
      </div>
      {{if .Customers}}
      <table>
        <colgroup>
          <col class="col-id">
          <col class="col-name">
          <col class="col-email">
          <col class="col-plan">
          <col class="col-plan">
          <col class="col-created">
          <col class="col-actions">
        </colgroup>
        <thead>
          <tr>
            <th>ID</th>
            <th>Name</th>
            <th>Email</th>
            <th>Plan</th>
            <th>Country</th>
            <th>Created</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {{range .Customers}}
          <tr>
            <td class="mono" style="color:var(--text-3)">{{.ID}}</td>
            <td style="font-weight:500">{{.Name}}</td>
            <td class="mono" style="font-size:0.8rem;color:var(--text-2)">{{.Email}}</td>
            <td><span class="plan plan--{{.Plan}}">{{.Plan}}</span></td>
            <td>{{.Country}}</td>
            <td style="color:var(--text-3);font-size:0.8rem">{{.CreatedAt}}</td>
            <td>
              <div class="row-actions">
                <button type="button" class="btn btn--ghost"
                  onclick="openEdit({{.ID}}, '{{.Name}}', '{{.Email}}', '{{.Plan}}')">Edit</button>
                <form method="POST" action="/customers/delete" style="display:inline" data-confirm-form>
                  <input type="hidden" name="id" value="{{.ID}}">
                  <button type="button" class="btn btn--danger" data-confirm-ask>Delete</button>
                  <span data-confirm-panel hidden>
                    <button type="submit" class="btn btn--danger">Confirm</button>
                    <button type="button" class="btn btn--ghost" data-confirm-cancel>Cancel</button>
                  </span>
                </form>
              </div>
            </td>
          </tr>
          {{end}}
        </tbody>
      </table>
      {{else}}
      <div class="empty">
        {{if .ConnError}}No database connection: the status above says why{{else}}No customers yet — add one{{end}}
      </div>
      {{end}}
    </div>

    <!-- Sidebar -->
    <div class="sidebar">

      <!-- Add customer form -->
      <div class="panel">
        <div class="panel__hdr">Add Customer</div>
        <form method="POST" action="/customers/add">
          <div class="form-body">
            <div class="field">
              <label for="name">Name</label>
              <input type="text" id="name" name="name" class="input" placeholder="Jane Smith" required>
            </div>
            <div class="field">
              <label for="email">Email</label>
              <input type="email" id="email" name="email" class="input" placeholder="jane@example.com" required>
            </div>
            <div class="field">
              <label for="country">Country</label>
              <input type="text" id="country" name="country" class="input" placeholder="US" maxlength="2">
            </div>
            <div class="field">
              <label for="plan">Plan</label>
              <select id="plan" name="plan" class="select">
                <option value="free">Free</option>
                <option value="pro">Pro</option>
                <option value="enterprise">Enterprise</option>
              </select>
            </div>
            <button type="submit" class="btn btn--primary" style="width:100%;justify-content:center;padding:0.55rem">
              Add Customer
            </button>
          </div>
        </form>
      </div>

      <!-- What the connector holds -->
      <div class="panel">
        <div class="panel__hdr">What the connector holds</div>
        {{if .SealedErr}}
        <div style="padding:0.75rem 1.15rem;font-size:0.8rem;color:var(--text-3)">{{.SealedErr}}</div>
        {{else}}
        <div style="padding:0.75rem 1.15rem;font-size:0.78rem;color:var(--text-2);line-height:1.5">
          The connector is granted <code style="font-family:var(--mono);color:var(--primary)">secrets:cache</code>
          and nothing else. This is everything it has for
          <code style="font-family:var(--mono);color:var(--primary)">{{.SecretName}}</code> &mdash;
          ciphertext under a key it was never given.
        </div>
        <div style="padding:0 1.15rem 0.5rem;font-size:0.72rem;color:var(--text-3);font-family:var(--mono)">
          secret {{.SealedID}} &middot; version {{.SealedVersion}}
        </div>
        <pre style="font-size:0.68rem;color:var(--text-2);margin:0 1.15rem 1.15rem;white-space:pre-wrap;word-break:break-all;background:var(--surface-hi);border:1px solid var(--border);border-radius:6px;padding:0.5rem 0.65rem;max-height:9rem;overflow-y:auto">{{.SealedCipher}}</pre>
        <div style="padding:0 1.15rem 1.15rem;font-size:0.78rem;color:var(--text-2);line-height:1.5">
          This application is granted <code style="font-family:var(--mono);color:var(--primary)">secrets:unwrap</code>
          and nothing else. It took that envelope, asked CoreLink for the key, and opened it here &mdash;
          connected as <code style="font-family:var(--mono);color:var(--primary)">{{.ConnectedAs}}</code>.
          Neither identity holds <code style="font-family:var(--mono)">secrets:read</code>.
        </div>
        {{end}}
      </div>

    </div>

  </div>

  <script>
    // Inline confirmation rather than confirm(): a browser dialog blocks the
    // page and the project's frontend standards forbid it.
    document.addEventListener('click', function (e) {
      var ask = e.target.closest('[data-confirm-ask]');
      if (ask) {
        var form = ask.closest('[data-confirm-form]');
        ask.hidden = true;
        form.querySelector('[data-confirm-panel]').hidden = false;
        return;
      }
      var cancel = e.target.closest('[data-confirm-cancel]');
      if (cancel) {
        var f = cancel.closest('[data-confirm-form]');
        f.querySelector('[data-confirm-panel]').hidden = true;
        f.querySelector('[data-confirm-ask]').hidden = false;
      }
    });
  </script>

  <div class="footer">
    <span>Credentials watched via transit SDK — reconnects automatically on rotation</span>
    <span>Page refreshes every 15s</span>
  </div>

</div>

<!-- Edit customer dialog -->
<dialog id="edit-dialog">
  <div class="dialog__hdr">
    <span class="dialog__title">Edit Customer</span>
    <button class="dialog__close" onclick="document.getElementById('edit-dialog').close()">x</button>
  </div>
  <form method="POST" action="/customers/update">
    <input type="hidden" id="edit-id" name="id">
    <div class="form-body">
      <div class="field">
        <label for="edit-name">Name</label>
        <input type="text" id="edit-name" name="name" class="input" required>
      </div>
      <div class="field">
        <label for="edit-email">Email</label>
        <input type="email" id="edit-email" name="email" class="input" required>
      </div>
      <div class="field">
        <label for="edit-plan">Plan</label>
        <select id="edit-plan" name="plan" class="select">
          <option value="free">Free</option>
          <option value="pro">Pro</option>
          <option value="enterprise">Enterprise</option>
        </select>
      </div>
    </div>
    <div class="dialog__footer">
      <button type="button" class="btn btn--ghost" onclick="document.getElementById('edit-dialog').close()">Cancel</button>
      <button type="submit" class="btn btn--primary">Save Changes</button>
    </div>
  </form>
</dialog>

<script>
function openEdit(id, name, email, plan) {
  document.getElementById('edit-id').value = id;
  document.getElementById('edit-name').value = name;
  document.getElementById('edit-email').value = email;
  var sel = document.getElementById('edit-plan');
  for (var i = 0; i < sel.options.length; i++) {
    sel.options[i].selected = sel.options[i].value === plan;
  }
  document.getElementById('edit-dialog').showModal();
}

// Live status: poll /api/status every 2 seconds and update the four cards.
var lastDB = null;
function setCard(id, part, main, sub) {
  var card = document.getElementById(id);
  if (!card || !part) return;
  card.className = 'status-card status-card--' + (part.state || 'warn');
  var badge = card.querySelector('.st-badge');
  badge.className = 'badge st-badge badge--' + ({ok: 'ok', warn: 'warn', bad: 'err'}[part.state] || 'warn');
  badge.textContent = part.label || '';
  if (main !== null) card.querySelector('.st-main').textContent = main;
  if (sub !== null) card.querySelector('.st-sub').textContent = sub;
  card.querySelector('.st-detail').textContent = part.detail || '';
  var since = part.since ? new Date(part.since) : null;
  card.querySelector('.st-since').textContent =
    since && since.getFullYear() > 1 ? 'since ' + since.toLocaleTimeString() : '';
}
function refreshStatus() {
  fetch('/api/status', {cache: 'no-store'}).then(function(r) { return r.json(); }).then(function(s) {
    var id = s.identity || {};
    setCard('st-identity', id, id.name || id.id || '', id.name ? id.id : '');
    var c = s.connector || {};
    setCard('st-connector', c, c.name ? c.name : (c.id || c.url || ''),
      [c.name ? c.id : '', c.url, c.envelopes_held != null ? c.envelopes_held + ' envelope(s) held' : ''].filter(Boolean).join(' \u00b7 '));
    setCard('st-secret', s.secret, null, null);
    var d = s.database || {};
    setCard('st-database', d, d.user || 'no connection', d.target || '');
    var hb = document.getElementById('hdr-badge');
    if (hb) {
      hb.className = 'badge ' + (d.state === 'ok' ? 'badge--ok' : 'badge--err');
      document.getElementById('hdr-label').textContent = d.state === 'ok' ? 'Connected' : 'Disconnected';
    }
    // When the connection opens or closes, show the customer list as it now is.
    if (lastDB !== null && lastDB !== d.state && !document.activeElement.closest('form, dialog')) {
      location.reload();
    }
    lastDB = d.state;
  }).catch(function() {
    setCard('st-identity', {state: 'bad', label: 'App unreachable', detail: 'The sample app does not answer.'}, null, null);
  });
}
refreshStatus();
setInterval(refreshStatus, 2000);

// Auto-reload every 15s, but pause while any form field or dialog has focus.
var reloadTimer = null;
var RELOAD_MS = 15000;

function scheduleReload() {
  clearTimeout(reloadTimer);
  reloadTimer = setTimeout(function(){ location.reload(); }, RELOAD_MS);
}

function pauseReload() {
  clearTimeout(reloadTimer);
  reloadTimer = null;
}

document.addEventListener('focusin', function(e) {
  if (e.target.matches('input, select, textarea, button') || e.target.closest('dialog')) {
    pauseReload();
  }
});

document.addEventListener('focusout', function(e) {
  setTimeout(function() {
    var active = document.activeElement;
    if (!active || (!active.matches('input, select, textarea, button') && !active.closest('dialog'))) {
      scheduleReload();
    }
  }, 0);
});

scheduleReload();
</script>
</body>
</html>`
