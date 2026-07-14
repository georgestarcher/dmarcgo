package dmarcgo

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// TestDShieldLiveDNSPerspectiveCompatibility is an explicitly enabled,
// one-request research check. It is not a supported adapter or a CI
// dependency. The current public endpoint does not provide usable TXT evidence
// for the authentication owner names required by CollectDNSPerspectives.
func TestDShieldLiveDNSPerspectiveCompatibility(t *testing.T) {
	if os.Getenv("DMARCGO_DSHIELD_LIVE") != "1" {
		t.Skip("set DMARCGO_DSHIELD_LIVE=1 to run the bounded compatibility check")
	}
	userAgent := strings.TrimSpace(os.Getenv("DMARCGO_DSHIELD_USER_AGENT"))
	if userAgent == "" {
		t.Fatal("DMARCGO_DSHIELD_USER_AGENT must identify the caller and include contact information")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://isc.sans.edu/api/dnslookup/example.com/TXT?json", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errDShieldRedirect
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Errorf("close DShield compatibility response: %v", closeErr)
		}
	}()
	if resp.StatusCode == http.StatusTooManyRequests {
		t.Skipf("DShield rate limited the one-request compatibility check; retry-after=%q", resp.Header.Get("Retry-After"))
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DShield compatibility status=%d", resp.StatusCode)
	}
	if contentType := resp.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(contentType), "application/json") {
		t.Fatalf("DShield compatibility content type=%q", contentType)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024+1))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > 1024*1024 {
		t.Fatal("DShield compatibility response exceeded 1 MiB")
	}
	var payload any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("DShield compatibility JSON: %v", err)
	}
	switch value := payload.(type) {
	case []any:
		t.Logf("DShield TXT compatibility returned %d perspective rows; an empty array is the observed 2026-07-14 behavior", len(value))
	case map[string]any:
		t.Logf("DShield TXT compatibility returned an object with %d fields; inspect before designing an adapter", len(value))
	default:
		t.Fatalf("DShield compatibility JSON shape=%T", payload)
	}
}

var errDShieldRedirect = errors.New("DShield compatibility check does not follow redirects")
