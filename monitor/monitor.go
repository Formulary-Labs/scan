// Package monitor implements the external intelligence scan for the scan tool.
//
// scan fetches configured sources — RSS/Atom feeds, CISA advisories, NVD CVE
// feeds, regulatory sites — and scores each item's relevance against a
// program context using heuristic keyword matching.
//
// All external content is treated as untrusted. The fixed extraction schema
// from functions/external-intel-spec.md governs how source content enters the
// output: title, source, published_date, url, summary only.
//
// No raw external HTML or full article text is included in output.
//
// Five source categories:
//   1. CISA advisories and alerts
//   2. NVD/CVE vulnerability feed
//   3. Regulatory and standards bodies (NIST, ISO, ENISA)
//   4. AI/ML safety and ethics research (arXiv, AI safety institutions)
//   5. Custom RSS/Atom feeds (user-configured)
package monitor

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// SourceCategory is one of the 5 scan source categories.
type SourceCategory string

const (
	CISACategory       SourceCategory = "cisa"
	NVDCategory        SourceCategory = "nvd"
	RegulatoryCategory SourceCategory = "regulatory"
	AIMLCategory       SourceCategory = "aiml"
	CustomCategory     SourceCategory = "custom"
)

// ScanConfig configures a scan run.
type ScanConfig struct {
	Program     string          `json:"program"`
	Framework   string          `json:"framework,omitempty"`
	Stack       []string        `json:"stack,omitempty"`   // product names, tech stack
	Keywords    []string        `json:"keywords,omitempty"` // extra relevance keywords
	Categories  []SourceCategory `json:"categories,omitempty"` // empty = all
	LookbackDays int            `json:"lookback_days,omitempty"`
	Sources     []CustomSource  `json:"sources,omitempty"` // custom RSS/Atom sources
}

// CustomSource is a user-defined RSS/Atom feed URL.
type CustomSource struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	Category SourceCategory `json:"category"`
}

// Finding is a single scan result with relevance scoring.
type Finding struct {
	ID            string         `json:"id"`
	Title         string         `json:"title"`
	Source        string         `json:"source"`
	Category      SourceCategory `json:"category"`
	PublishedDate string         `json:"published_date"`
	URL           string         `json:"url,omitempty"`
	Summary       string         `json:"summary"`
	RelevanceScore float64       `json:"relevance_score"` // 0.0 - 1.0
	MatchedKeywords []string     `json:"matched_keywords,omitempty"`
	RiskDelta     string         `json:"risk_delta,omitempty"` // "new", "updated", "seen"
}

// ScanReport is the full output of a scan run.
type ScanReport struct {
	Program     string    `json:"program"`
	ScannedAt   time.Time `json:"scanned_at"`
	LookbackDays int      `json:"lookback_days"`
	Categories  []SourceCategory `json:"categories"`
	Findings    []Finding `json:"findings"`
	Errors      []string  `json:"errors,omitempty"`
	Warning     string    `json:"warning,omitempty"`
}

// DefaultSources returns the built-in source list for all categories.
func DefaultSources() []CustomSource {
	return []CustomSource{
		{Name: "CISA Advisories", URL: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", Category: CISACategory},
		{Name: "NIST Cybersecurity", URL: "https://www.nist.gov/news-events/cybersecurity.rss", Category: RegulatoryCategory},
		{Name: "ENISA News", URL: "https://www.enisa.europa.eu/media/news-items/RSS", Category: RegulatoryCategory},
		{Name: "AI Safety Research", URL: "https://arxiv.org/rss/cs.AI", Category: AIMLCategory},
		{Name: "NVD Recent CVEs", URL: "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz", Category: NVDCategory},
	}
}

// FrameworkKeywords returns heuristic keywords for common frameworks.
var FrameworkKeywords = map[string][]string{
	"iso27001":  {"ISO 27001", "information security", "ISMS", "risk management", "access control"},
	"iso42001":  {"ISO 42001", "AI management", "AIMS", "artificial intelligence", "AI governance"},
	"iec62443":  {"IEC 62443", "OT security", "industrial control", "IACS", "cybersecurity"},
	"hds":       {"health data", "HDS", "données de santé", "GDPR health", "medical data"},
	"soc2":      {"SOC 2", "trust service", "availability", "confidentiality", "processing integrity"},
	"fedramp":   {"FedRAMP", "FISMA", "federal cloud", "NIST 800-53"},
	"nist-csf":  {"NIST CSF", "cybersecurity framework", "identify protect detect respond recover"},
}

// Run executes a scan against the configured sources.
// In dry-run mode, it returns an empty report with a notice rather than making
// network calls.
func Run(cfg ScanConfig, dryRun bool, httpClient *http.Client) ScanReport {
	report := ScanReport{
		Program:      cfg.Program,
		ScannedAt:    time.Now().UTC(),
		LookbackDays: cfg.LookbackDays,
	}

	if cfg.LookbackDays == 0 {
		cfg.LookbackDays = 14
		report.LookbackDays = 14
	}

	// Determine which categories to scan.
	categories := cfg.Categories
	if len(categories) == 0 {
		categories = []SourceCategory{CISACategory, NVDCategory, RegulatoryCategory, AIMLCategory}
	}
	report.Categories = categories

	if dryRun {
		report.Warning = "dry-run mode: no network requests made"
		return report
	}

	// Build keyword set for relevance scoring.
	keywords := buildKeywords(cfg)

	// Collect sources.
	sources := cfg.Sources
	catSet := map[SourceCategory]bool{}
	for _, c := range categories {
		catSet[c] = true
	}
	for _, s := range DefaultSources() {
		if catSet[s.Category] {
			sources = append(sources, s)
		}
	}

	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}

	since := time.Now().Add(-time.Duration(cfg.LookbackDays) * 24 * time.Hour)
	idCounter := 0

	for _, src := range sources {
		if !catSet[src.Category] {
			continue
		}
		items, err := fetchSource(src, httpClient)
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("%s: %v", src.Name, err))
			continue
		}
		for _, item := range items {
			if item.Published != "" {
				t, err := parseDate(item.Published)
				if err == nil && t.Before(since) {
					continue // outside lookback window
				}
			}
			score, matched := score(item, keywords)
			if score < 0.1 {
				continue // below relevance threshold
			}
			idCounter++
			report.Findings = append(report.Findings, Finding{
				ID:              fmt.Sprintf("SCAN-%03d", idCounter),
				Title:           item.Title,
				Source:          src.Name,
				Category:        src.Category,
				PublishedDate:   item.Published,
				URL:             item.URL,
				Summary:         "[EXTERNAL SOURCE — UNVALIDATED] " + truncate(item.Summary, 200),
				RelevanceScore:  score,
				MatchedKeywords: matched,
				RiskDelta:       "new",
			})
		}
	}

	return report
}

// LoadConfig reads a scan config from a JSON or YAML file.
func LoadConfig(path string) (*ScanConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading scan config %q: %w", path, err)
	}
	var cfg ScanConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing scan config %q: %w", path, err)
	}
	return &cfg, nil
}

// --- internal ---

// feedItem is the normalised shape of a fetched item.
type feedItem struct {
	Title     string
	Summary   string
	URL       string
	Published string
}

// fetchSource fetches items from a source using HTTP. Handles RSS/Atom XML
// and CISA/NVD JSON formats.
func fetchSource(src CustomSource, client *http.Client) ([]feedItem, error) {
	resp, err := client.Get(src.URL)
	if err != nil {
		return nil, fmt.Errorf("fetching %q: %w", src.URL, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading body from %q: %w", src.URL, err)
	}

	// Try CISA KEV JSON.
	if src.Category == CISACategory {
		items := parseCISAKEV(body)
		if len(items) > 0 {
			return items, nil
		}
	}

	// Try RSS/Atom XML.
	if items, err := parseRSS(body); err == nil && len(items) > 0 {
		return items, nil
	}

	return nil, fmt.Errorf("could not parse response from %q as RSS/Atom or known JSON format", src.URL)
}

// RSS/Atom parser (minimal).
type rssRoot struct {
	XMLName xml.Name `xml:"rss"`
	Channel struct {
		Items []struct {
			Title       string `xml:"title"`
			Description string `xml:"description"`
			Link        string `xml:"link"`
			PubDate     string `xml:"pubDate"`
		} `xml:"item"`
	} `xml:"channel"`
}

type atomRoot struct {
	XMLName xml.Name `xml:"feed"`
	Entries []struct {
		Title   string `xml:"title"`
		Summary string `xml:"summary"`
		Link    struct {
			Href string `xml:"href,attr"`
		} `xml:"link"`
		Published string `xml:"published"`
		Updated   string `xml:"updated"`
	} `xml:"entry"`
}

func parseRSS(data []byte) ([]feedItem, error) {
	// Try RSS.
	var rss rssRoot
	if err := xml.Unmarshal(data, &rss); err == nil && len(rss.Channel.Items) > 0 {
		var items []feedItem
		for _, i := range rss.Channel.Items {
			items = append(items, feedItem{
				Title:     cleanText(i.Title),
				Summary:   cleanText(i.Description),
				URL:       i.Link,
				Published: i.PubDate,
			})
		}
		return items, nil
	}
	// Try Atom.
	var atom atomRoot
	if err := xml.Unmarshal(data, &atom); err == nil && len(atom.Entries) > 0 {
		var items []feedItem
		for _, e := range atom.Entries {
			pub := e.Published
			if pub == "" {
				pub = e.Updated
			}
			items = append(items, feedItem{
				Title:     cleanText(e.Title),
				Summary:   cleanText(e.Summary),
				URL:       e.Link.Href,
				Published: pub,
			})
		}
		return items, nil
	}
	return nil, fmt.Errorf("not RSS or Atom")
}

// parseCISAKEV parses the CISA Known Exploited Vulnerabilities JSON feed.
func parseCISAKEV(data []byte) []feedItem {
	var doc struct {
		Vulnerabilities []struct {
			CveID            string `json:"cveID"`
			VulnerabilityName string `json:"vulnerabilityName"`
			ShortDescription  string `json:"shortDescription"`
			DateAdded         string `json:"dateAdded"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil
	}
	var items []feedItem
	for _, v := range doc.Vulnerabilities {
		items = append(items, feedItem{
			Title:     fmt.Sprintf("%s: %s", v.CveID, v.VulnerabilityName),
			Summary:   v.ShortDescription,
			URL:       fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", v.CveID),
			Published: v.DateAdded,
		})
	}
	return items
}

// buildKeywords assembles the full keyword list for relevance scoring.
func buildKeywords(cfg ScanConfig) []string {
	var kws []string
	kws = append(kws, cfg.Keywords...)
	kws = append(kws, cfg.Stack...)
	if fkws, ok := FrameworkKeywords[strings.ToLower(cfg.Framework)]; ok {
		kws = append(kws, fkws...)
	}
	return kws
}

// score returns a relevance score [0, 1] and matched keywords for an item.
func score(item feedItem, keywords []string) (float64, []string) {
	if len(keywords) == 0 {
		return 0.1, nil // no context — minimal relevance
	}
	text := strings.ToLower(item.Title + " " + item.Summary)
	var matched []string
	for _, kw := range keywords {
		if strings.Contains(text, strings.ToLower(kw)) {
			matched = append(matched, kw)
		}
	}
	if len(matched) == 0 {
		return 0, nil
	}
	s := float64(len(matched)) / float64(len(keywords))
	if s > 1 {
		s = 1
	}
	return s, matched
}

func parseDate(s string) (time.Time, error) {
	formats := []string{
		time.RFC1123Z, time.RFC1123, time.RFC3339,
		"Mon, 2 Jan 2006 15:04:05 -0700",
		"2006-01-02",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse date %q", s)
}

func cleanText(s string) string {
	// Strip basic HTML tags.
	s = strings.NewReplacer("<p>", " ", "</p>", " ", "<br>", " ", "<br/>", " ", "<li>", " ", "</li>", " ").Replace(s)
	// Collapse whitespace.
	parts := strings.Fields(s)
	return strings.Join(parts, " ")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
