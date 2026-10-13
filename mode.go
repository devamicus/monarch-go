package monarch

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strings"
	"time"
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
