package monitor_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Formulary-Labs/scan/monitor"
)

func TestRun_dryRun(t *testing.T) {
	cfg := monitor.ScanConfig{
		Program:   "test",
		Framework: "iso27001",
	}
	report := monitor.Run(cfg, true, nil)
	if report.Program != "test" {
		t.Errorf("program = %q, want test", report.Program)
	}
	if report.Warning == "" {
		t.Error("expected warning in dry-run mode")
	}
	if len(report.Findings) > 0 {
		t.Error("expected no findings in dry-run mode")
	}
}

func TestScore_keywordMatch(t *testing.T) {
	cfg := monitor.ScanConfig{
		Program:   "test",
		Framework: "iso27001",
		Keywords:  []string{"ISMS", "information security"},
	}
	// Run against a mock server that returns a simple RSS feed.
	rss := `<?xml version="1.0"?>
<rss version="2.0">
<channel>
<item>
<title>New ISMS guidance published</title>
<description>NIST releases updated information security guidance for risk management.</description>
<link>https://example.com/isms</link>
<pubDate>Mon, 14 Sep 2026 10:00:00 +0000</pubDate>
</item>
<item>
<title>Unrelated news</title>
<description>This has nothing to do with compliance.</description>
<link>https://example.com/unrelated</link>
<pubDate>Mon, 14 Sep 2026 10:00:00 +0000</pubDate>
</item>
</channel>
</rss>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/rss+xml")
		w.Write([]byte(rss)) //nolint:errcheck
	}))
	defer srv.Close()

	cfg.Sources = []monitor.CustomSource{
		{Name: "Test RSS", URL: srv.URL + "/feed.rss", Category: monitor.CustomCategory},
	}
	cfg.Categories = []monitor.SourceCategory{monitor.CustomCategory}

	report := monitor.Run(cfg, false, srv.Client())

	if len(report.Findings) == 0 {
		t.Error("expected at least 1 finding matching ISMS keywords")
	}
	for _, f := range report.Findings {
		if !strings.Contains(strings.ToLower(f.Title), "isms") &&
			!strings.Contains(strings.ToLower(f.Summary), "information security") {
			t.Errorf("unexpected finding not matching keywords: %q", f.Title)
		}
	}
}

func TestParseCISAKEV(t *testing.T) {
	cisaJSON := `{
		"vulnerabilities": [
			{
				"cveID": "CVE-2026-1234",
				"vulnerabilityName": "Test Vulnerability",
				"shortDescription": "A critical vulnerability in ISO test components.",
				"dateAdded": "2026-09-14"
			}
		]
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(cisaJSON)) //nolint:errcheck
	}))
	defer srv.Close()

	cfg := monitor.ScanConfig{
		Program:    "test",
		Framework:  "iso27001",
		Keywords:   []string{"ISO"},
		Categories: []monitor.SourceCategory{monitor.CISACategory},
		Sources: []monitor.CustomSource{
			{Name: "CISA KEV", URL: srv.URL + "/kev.json", Category: monitor.CISACategory},
		},
	}

	report := monitor.Run(cfg, false, srv.Client())
	if len(report.Findings) == 0 {
		t.Error("expected CISA KEV finding matching 'ISO'")
	}
}

func TestFrameworkKeywords(t *testing.T) {
	if _, ok := monitor.FrameworkKeywords["iso27001"]; !ok {
		t.Error("expected iso27001 in FrameworkKeywords")
	}
	if _, ok := monitor.FrameworkKeywords["iso42001"]; !ok {
		t.Error("expected iso42001 in FrameworkKeywords")
	}
	if _, ok := monitor.FrameworkKeywords["iec62443"]; !ok {
		t.Error("expected iec62443 in FrameworkKeywords")
	}
}
