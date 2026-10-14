package monarch

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/devamicus/monarch-go/token"
)

const (
	// ModeOff skips license checks. Guard runs the application, Allows is true,
	// and Config returns an empty document.
	ModeOff = "off"
	// ModeFile serves monarch.local.json and does not call the API.
	ModeFile = "file"
	// ModeLive verifies snapshots with the pinned master keys.
	ModeLive = "live"

	localFileName = "monarch.local.json"
)

func licenseFilePath(opt Option) string {
	if path := strings.TrimSpace(opt.LicenseFile); path != "" {
		return path
	}
	return strings.TrimSpace(os.Getenv("MONARCH_LICENSE_FILE"))
}

func (c *Client) importLicenseFile(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("monarch: %s: %w", path, err)
	}
	var doc struct {
		Token      string `json:"token"`
		Delegation string `json:"delegation"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("monarch: %s: %w", path, err)
	}
	if doc.Token == "" || doc.Delegation == "" {
		return fmt.Errorf("monarch: %s: token and delegation are required", path)
	}
	return c.Import(doc.Token, doc.Delegation)
}

type localFile struct {
	Features map[string]bool  `json:"features"`
	Limits   map[string]int64 `json:"limits"`
	Config   struct {
		Revision int64          `json:"revision"`
		Schema   string         `json:"schema"`
		Values   map[string]any `json:"values"`
	} `json:"config"`
}

func resolveMode(opt Option) (string, error) {
	mode := strings.TrimSpace(opt.Mode)
	if mode == "" {
		mode = strings.TrimSpace(os.Getenv("MONARCH_MODE"))
	}
	if mode == "" {
		if opt.Sealed {
			mode = ModeLive
		} else {
			mode = ModeOff
		}
	}
	switch mode {
	case ModeOff, ModeFile, ModeLive:
	default:
		return "", fmt.Errorf("monarch: unknown mode %q", mode)
	}
	if opt.Sealed && mode != ModeLive {
		return "", fmt.Errorf("monarch: this build rejects MONARCH_MODE=%s", mode)
	}
	if mode == ModeLive && len(opt.Masters) == 0 {
		return "", errors.New("monarch: no master keys; run monarch seal")
	}
	return mode, nil
}

func applyDefaults(opt Option) Option {
	if opt.Environment == "" {
		opt.Environment = "prod"
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Skew == 0 {
		opt.Skew = 5 * time.Minute
	}
	if opt.HTTP == nil {
		opt.HTTP = &http.Client{Timeout: 15 * time.Second}
	}
	return opt
}

func loadLocal(path string) (localFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return localFile{}, fmt.Errorf("monarch: %s: %w", path, err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var doc localFile
	if err := dec.Decode(&doc); err != nil {
		return localFile{}, fmt.Errorf("monarch: %s: %w", path, err)
	}
	return doc, nil
}

func (c *Client) licenseHeadline() (string, bool) {
	if c.modeName != ModeLive || c.mode == ModeServing {
		return "", false
	}
	if c.cache.Token == "" {
		if strings.TrimSpace(c.opt.LicenseKey) != "" || licenseFilePath(c.opt) != "" {
			return "", false
		}
		return "no license configured", true
	}
	if cachedDelivery(c.cache.Token) != token.DeliveryFile {
		return "", false
	}
	if c.reason == "license expired" || strings.Contains(c.reason, token.ErrWindow.Error()) {
		return "air-gap license expired", true
	}
	return "", false
}

func (c *Client) explainLicense(headline string) {
	pub := base64.RawURLEncoding.EncodeToString(c.pub)
	c.info(fmt.Sprintf(`%s

Online. An admin creates a license and an activation key. Start this process with:

  MONARCH_SERVER_URL=https://monarch.example.com
  MONARCH_LICENSE_KEY=mon_live_...

Offline. An admin issues a file for this public key:

  public key: %s

Save that response and start this process with:

  MONARCH_LICENSE_FILE=/var/lib/app/monarch/license.json
`, headline, pub))
}

func cachedDelivery(compact string) string {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var doc struct {
		Delivery string `json:"delivery"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return ""
	}
	return doc.Delivery
}

func (c *Client) info(msg string, args ...any) {
	fn := c.opt.Info
	if fn == nil {
		fn = defaultInfo
	}
	fn(msg, args...)
}

func defaultInfo(msg string, args ...any) {
	var b strings.Builder
	b.WriteString("monarch: ")
	b.WriteString(msg)
	for i := 0; i < len(args); i += 2 {
		if i+1 >= len(args) {
			fmt.Fprintf(&b, " %v", args[i])
			break
		}
		fmt.Fprintf(&b, " %v=%v", args[i], args[i+1])
	}
	b.WriteByte('\n')
	_, _ = io.WriteString(os.Stderr, b.String())
}

func (c *Client) requireLive() error {
	switch c.modeName {
	case ModeLive:
		return nil
	case ModeFile:
		return errors.New("monarch: using a local license file")
	default:
		return errors.New("monarch: license check disabled for development")
	}
}

func (c *Client) limitOff() (int64, bool) {
	return math.MaxInt64, true
}

func copyValues(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
