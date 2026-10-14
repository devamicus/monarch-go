// Package monarch is the install-side library. It trusts only a snapshot that
// verifies against the pinned master keys and this install's key.
package monarch

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/devamicus/monarch-go/token"
)

const (
	ModeServing    = "serving"
	ModeRestricted = "restricted"
)

// ErrNotServing is returned when the install has no allow-snapshot in force.
var ErrNotServing = errors.New("monarch: not serving")

// Option configures one deployment. Every process of that deployment must
// share StateDir so they present one install identity.
//
// Mode off, file, and live follow MONARCH_MODE when Mode is empty. An unsealed
// process with no mode set skips license checks. Sealed refuses off and file.
// LicenseFile is the JSON from POST /v1/offline-tokens. An empty field reads
// MONARCH_LICENSE_FILE. Open imports that file when the path is set.
// Info receives notices. A nil Info prints text lines to stderr.
type Option struct {
	StateDir    string
	ServerURL   string
	LicenseKey  string
	Environment string
	Masters     token.Masters
	Sealed      bool
	Mode        string
	File        string
	LicenseFile string
	Info        func(msg string, args ...any)
	HTTP        *http.Client
	Now         func() time.Time
	Skew        time.Duration
}

// Client holds the install key, the cached snapshot, and the current decision.
type Client struct {
	opt      Option
	pub      ed25519.PublicKey
	priv     ed25519.PrivateKey
	mu       sync.Mutex
	cache    stored
	high     int64
	reason   string
	mode     string
	modeName string
	local    localFile
}

type stored struct {
	Token      string `json:"token"`
	Delegation string `json:"delegation"`
	VerifiedAt int64  `json:"verified_at"`
	InstanceID string `json:"instance_id"`
}

// Open loads or creates the install key and evaluates any cached snapshot.
// It does not contact the network. Mode off and mode file do not create a state directory.
func Open(opt Option) (*Client, error) {
	mode, err := resolveMode(opt)
	if err != nil {
		return nil, err
	}
	opt = applyDefaults(opt)
	if mode == ModeOff {
		c := &Client{opt: opt, modeName: mode, mode: ModeServing}
		c.info("license check disabled for development")
		return c, nil
	}
	if mode == ModeFile {
		path := opt.File
		if path == "" {
			path = localFileName
		}
		doc, err := loadLocal(path)
		if err != nil {
			return nil, err
		}
		c := &Client{opt: opt, modeName: mode, mode: ModeServing, local: doc}
		c.info("using " + path + " for development")
		return c, nil
	}
	if opt.StateDir == "" {
		return nil, errors.New("monarch: state directory is required")
	}
	if err := os.MkdirAll(opt.StateDir, 0o700); err != nil {
		return nil, err
	}
	pub, priv, err := loadOrCreateKey(filepath.Join(opt.StateDir, "key.pem"))
	if err != nil {
		return nil, err
	}
	c := &Client{opt: opt, pub: pub, priv: priv, mode: ModeRestricted, reason: "no snapshot", modeName: mode}
	if raw, err := os.ReadFile(filepath.Join(opt.StateDir, "cache.json")); err == nil {
		_ = json.Unmarshal(raw, &c.cache)
	}
	if raw, err := os.ReadFile(filepath.Join(opt.StateDir, "highwater")); err == nil {
		c.high, _ = strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	}
	before := c.cache.Token
	if path := licenseFilePath(opt); path != "" {
		if err := c.importLicenseFile(path); err != nil {
			if errors.Is(err, token.ErrWindow) {
				c.explainLicense("air-gap license expired")
			}
			return nil, err
		}
	}
	c.evaluate(opt.Now())
	if c.cache.Token != before {
		c.info("imported", "instance", c.cache.InstanceID)
	} else if c.mode == ModeServing {
		c.info("connected", "instance", c.cache.InstanceID, "server", c.opt.ServerURL)
	} else if headline, ok := c.licenseHeadline(); ok {
		c.explainLicense(headline)
	}
	return c, nil
}

// PublicKey is the install key this deployment presents.
func (c *Client) PublicKey() ed25519.PublicKey { return c.pub }

// Mode is serving or restricted.
func (c *Client) Mode() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mode
}

// Reason explains a restricted decision.
func (c *Client) Reason() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reason
}

// Allows reports a feature from the current allow-snapshot.
// Mode off allows every feature. Mode file reads the local document.
func (c *Client) Allows(feature string) bool {
	switch c.modeName {
	case ModeOff:
		return true
	case ModeFile:
		return c.local.Features[feature]
	default:
		claims, ok := c.serving()
		return ok && claims.Entitlements.Features[feature]
	}
}

// Limit reports a numeric entitlement. The second result is false when the
// snapshot does not grant premium use.
func (c *Client) Limit(name string) (int64, bool) {
	switch c.modeName {
	case ModeOff:
		return c.limitOff()
	case ModeFile:
		n, present := c.local.Limits[name]
		return n, present
	default:
		claims, ok := c.serving()
		if !ok {
			return 0, false
		}
		n, present := claims.Entitlements.Limits[name]
		return n, present
	}
}

// Config is the compiled runtime document from the current allow-snapshot.
// It returns ErrNotServing when the install is restricted, including when the
// caller has not checked Mode first.
func (c *Client) Config() (int64, map[string]any, error) {
	switch c.modeName {
	case ModeOff:
		return 0, map[string]any{}, nil
	case ModeFile:
		return c.local.Config.Revision, copyValues(c.local.Config.Values), nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evaluate(c.opt.Now())
	if c.mode != ModeServing {
		return 0, map[string]any{}, c.restricted()
	}
	claims, err := c.verified(c.opt.Now())
	if err != nil {
		return 0, map[string]any{}, err
	}
	values := claims.Config.Values
	if values == nil {
		values = map[string]any{}
	}
	out := make(map[string]any, len(values))
	for k, v := range values {
		out[k] = v
	}
	return claims.Config.Revision, out, nil
}

// Guard activates this install when a license key is set, then calls app only
// while the snapshot is serving. app is not called when the install is restricted.
// The context passed to app is cancelled if a later heartbeat leaves the restricted state.
func (c *Client) Guard(ctx context.Context, app func(context.Context) error) error {
	if c.modeName == ModeOff || c.modeName == ModeFile {
		return app(ctx)
	}
	if err := c.prepare(ctx); err != nil {
		return err
	}
	if err := c.notServing(); err != nil {
		return err
	}
	appCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go c.supervise(appCtx, cancel)
	return app(appCtx)
}

func (c *Client) prepare(ctx context.Context) error {
	c.mu.Lock()
	has := c.cache.Token != ""
	c.mu.Unlock()
	if has || c.opt.LicenseKey == "" {
		return nil
	}
	return c.Activate(ctx)
}

func (c *Client) supervise(ctx context.Context, cancel context.CancelFunc) {
	for {
		if err := c.notServing(); err != nil {
			if headline, ok := c.licenseHeadline(); ok {
				c.explainLicense(headline)
			}
			cancel()
			return
		}
		wait := c.nextWait()
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			c.mu.Lock()
			delivery := ""
			if claims, err := c.verified(c.opt.Now()); err == nil {
				delivery = claims.Delivery
			}
			instanceID := c.cache.InstanceID
			c.mu.Unlock()
			if delivery == token.DeliveryFile || instanceID == "" {
				continue
			}
			_ = c.Heartbeat(ctx)
		}
	}
}

func (c *Client) notServing() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evaluate(c.opt.Now())
	if c.mode == ModeServing {
		return nil
	}
	return c.restricted()
}

func (c *Client) restricted() error {
	if c.reason == "" {
		return ErrNotServing
	}
	return fmt.Errorf("%w: %s", ErrNotServing, c.reason)
}

func (c *Client) serving() (token.Claims, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evaluate(c.opt.Now())
	if c.mode != ModeServing {
		return token.Claims{}, false
	}
	claims, err := c.verified(c.opt.Now())
	if err != nil {
		return token.Claims{}, false
	}
	return claims, true
}

// Activate registers this install with the license key and stores the snapshot.
func (c *Client) Activate(ctx context.Context) error {
	if err := c.requireLive(); err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{
		"license_key": c.opt.LicenseKey,
		"public_key":  base64.RawURLEncoding.EncodeToString(c.pub),
		"environment": c.opt.Environment,
		"sdk_version": "0.1.0",
	})
	var out struct {
		InstanceID string `json:"instance_id"`
		Token      string `json:"token"`
		Delegation string `json:"delegation"`
	}
	if err := c.post(ctx, "/v1/agent/activate", body, nil, &out); err != nil {
		return err
	}
	if err := c.accept(out.InstanceID, out.Token, out.Delegation); err != nil {
		return err
	}
	c.info("activated", "instance", out.InstanceID, "server", c.opt.ServerURL)
	return nil
}

// Heartbeat refreshes the snapshot. A failed request leaves the previous cache in place.
func (c *Client) Heartbeat(ctx context.Context) error {
	if err := c.requireLive(); err != nil {
		return err
	}
	c.mu.Lock()
	instanceID := c.cache.InstanceID
	c.mu.Unlock()
	if instanceID == "" {
		return errors.New("monarch: install is not activated")
	}
	body := []byte(`{}`)
	now := c.opt.Now().UTC()
	sig := ed25519.Sign(c.priv, token.RequestSigningInput(instanceID, now, body))
	header := map[string]string{
		"Monarch-Instance":  instanceID,
		"Monarch-Timestamp": strconv.FormatInt(now.Unix(), 10),
		"Monarch-Signature": base64.RawURLEncoding.EncodeToString(sig),
	}
	var out struct {
		InstanceID string `json:"instance_id"`
		Token      string `json:"token"`
		Delegation string `json:"delegation"`
	}
	if err := c.post(ctx, "/v1/agent/heartbeat", body, header, &out); err != nil {
		c.mu.Lock()
		c.evaluate(c.opt.Now())
		c.mu.Unlock()
		return err
	}
	return c.accept(out.InstanceID, out.Token, out.Delegation)
}

// Import stores an air-gap license file after it verifies for this install.
// Open does this when LicenseFile or MONARCH_LICENSE_FILE is set.
func (c *Client) Import(snapshotToken, delegation string) error {
	if err := c.requireLive(); err != nil {
		return err
	}
	c.mu.Lock()
	id := c.cache.InstanceID
	c.mu.Unlock()
	return c.accept(id, snapshotToken, delegation)
}

// Run activates if needed and heartbeats until ctx is cancelled.
func (c *Client) Run(ctx context.Context) error {
	if err := c.requireLive(); err != nil {
		return err
	}
	c.mu.Lock()
	has := c.cache.Token != ""
	c.mu.Unlock()
	if !has && c.opt.LicenseKey != "" {
		if err := c.Activate(ctx); err != nil {
			return err
		}
	}
	for {
		wait := c.nextWait()
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
			c.mu.Lock()
			file := false
			if claims, err := c.verified(c.opt.Now()); err == nil && claims.Delivery == token.DeliveryFile {
				file = true
			}
			c.mu.Unlock()
			if file {
				continue
			}
			if c.cacheInstance() == "" {
				continue
			}
			_ = c.Heartbeat(ctx)
		}
	}
}

func (c *Client) cacheInstance() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cache.InstanceID
}

func (c *Client) nextWait() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evaluate(c.opt.Now())
	if c.mode != ModeServing {
		return time.Minute
	}
	claims, err := c.verified(c.opt.Now())
	if err != nil || claims.NextCheckin <= 0 {
		return 10 * time.Minute
	}
	return time.Duration(claims.NextCheckin) * time.Second
}

func (c *Client) accept(instanceID, snapshotToken, delegation string) error {
	now := c.opt.Now()
	claims, err := token.Verify(snapshotToken, delegation, c.opt.Masters, now, c.pub)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache.Token != "" && claims.Version <= c.version(now) {
		c.evaluate(now)
		return nil
	}
	if instanceID == "" {
		instanceID = claims.Subject
	}
	c.cache = stored{Token: snapshotToken, Delegation: delegation, VerifiedAt: now.Unix(), InstanceID: instanceID}
	if now.Unix() > c.high {
		c.high = now.Unix()
	}
	if claims.IssuedAt > c.high {
		c.high = claims.IssuedAt
	}
	if err := c.persist(); err != nil {
		return err
	}
	c.evaluate(now)
	return nil
}

func (c *Client) version(now time.Time) int64 {
	claims, err := c.verified(now)
	if err != nil {
		return 0
	}
	return claims.Version
}

func (c *Client) evaluate(now time.Time) {
	if now.Add(c.opt.Skew).Unix() < c.high {
		c.mode = ModeRestricted
		c.reason = "clock"
		return
	}
	claims, err := c.verified(now)
	if err != nil {
		c.mode = ModeRestricted
		c.reason = err.Error()
		return
	}
	if claims.Enforcement != token.EnforcementAllow {
		c.mode = ModeRestricted
		c.reason = claims.Reason
		return
	}
	if now.Unix() >= claims.LicenseExpiresAt {
		c.mode = ModeRestricted
		c.reason = "license expired"
		return
	}
	if claims.Delivery == token.DeliveryHeartbeat {
		deadline := time.Unix(c.cache.VerifiedAt, 0).Add(time.Duration(claims.GraceSeconds) * time.Second)
		if !now.Before(deadline) {
			c.mode = ModeRestricted
			c.reason = "grace elapsed"
			return
		}
	}
	c.mode = ModeServing
	c.reason = ""
	if now.Unix() > c.high {
		c.high = now.Unix()
		_ = c.persistHigh()
	}
}

func (c *Client) verified(now time.Time) (token.Claims, error) {
	if c.cache.Token == "" || c.cache.Delegation == "" {
		return token.Claims{}, errors.New("monarch: no snapshot")
	}
	return token.Verify(c.cache.Token, c.cache.Delegation, c.opt.Masters, now, c.pub)
}

func (c *Client) persist() error {
	raw, err := json.Marshal(c.cache)
	if err != nil {
		return err
	}
	if err := writeFile(filepath.Join(c.opt.StateDir, "cache.json"), raw); err != nil {
		return err
	}
	return c.persistHigh()
}

func (c *Client) persistHigh() error {
	return writeFile(filepath.Join(c.opt.StateDir, "highwater"), []byte(strconv.FormatInt(c.high, 10)))
}

func (c *Client) post(ctx context.Context, path string, body []byte, header map[string]string, dst any) error {
	if c.opt.ServerURL == "" {
		return errors.New("monarch: server url is required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.opt.ServerURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	res, err := c.opt.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return err
	}
	if res.StatusCode >= 300 {
		return fmt.Errorf("monarch: %s: %s", res.Status, bytes.TrimSpace(raw))
	}
	return json.Unmarshal(raw, dst)
}

func loadOrCreateKey(path string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if raw, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, nil, errors.New("monarch: key is not PEM")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		priv, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			return nil, nil, errors.New("monarch: key is not Ed25519")
		}
		pub, ok := priv.Public().(ed25519.PublicKey)
		if !ok {
			return nil, nil, errors.New("monarch: public key")
		}
		return pub, priv, nil
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	if err := writeFile(path, encoded); err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

func writeFile(path string, raw []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
