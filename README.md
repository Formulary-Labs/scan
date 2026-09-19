# scan

The threat landscape changes on its own schedule. `scan` fetches from five source categories, scores each item against your program's framework and stack, and returns only what's relevant — everything else is noise.

```bash
go get github.com/Formulary-Labs/scan
```

## What it does

`scan` fetches external threat intelligence and regulatory news from five source categories, scores each item for relevance against your program's framework, tech stack, and keywords, and returns a `ScanReport`. Items scoring below 0.1 are discarded. All external content is treated as untrusted — only `title`, `source`, `published_date`, `url`, and `summary` are extracted from source material.

Every summary in the output is prefixed `[EXTERNAL SOURCE — UNVALIDATED]`. That prefix is a data handling boundary, not a style choice. `scan` extracts; it does not verify.

## Usage

```go
import "github.com/Formulary-Labs/scan/monitor"

report, err := monitor.Run(monitor.ScanConfig{
    Program:      "my-program",
    Framework:    "iso42001",
    Stack:        []string{"kubernetes", "postgresql", "nginx"},
    Keywords:     []string{"AI governance", "model risk"},
    Categories:   []monitor.SourceCategory{"cisa", "nvd", "regulatory", "aiml"},
    LookbackDays: 14,
})
```

Omit `Categories` to scan all four default categories. The `aiml` category (`arXiv cs.AI`) is included by default but can be omitted for non-AI programs.

## Source categories

| Category | Source | Feed type |
|---|---|---|
| `cisa` | CISA Known Exploited Vulnerabilities | JSON |
| `nvd` | NVD CVE feed | JSON |
| `regulatory` | NIST Cybersecurity, ENISA News | RSS/Atom |
| `aiml` | arXiv cs.AI | Atom |
| `custom` | User-defined feeds | RSS/Atom |

### Adding custom feeds

```go
monitor.ScanConfig{
    Sources: []monitor.CustomSource{
        {
            Name:     "Internal Security Blog",
            URL:      "https://security.example.com/feed.xml",
            Category: monitor.CustomCategory,
        },
    },
}
```

Custom feeds are scored against the same program keywords as built-in sources.

## Relevance scoring

Each item is scored against the union of keywords derived from `Framework`, `Stack`, and `Keywords`:

```
relevance_score = matched_keywords / total_keywords
```

`matched_keywords` lists which keywords triggered the score. Items below 0.1 are dropped before the report is assembled.

`risk_delta` values: `new` (not seen in prior scan), `updated` (seen before with changes), `seen` (unchanged since last scan).

## Output

```json
{
  "program": "my-program",
  "scanned_at": "2026-09-18T00:00:00Z",
  "lookback_days": 14,
  "categories": ["cisa", "nvd", "regulatory", "aiml"],
  "findings": [
    {
      "id": "SCAN-001",
      "title": "Critical vulnerability in nginx 1.24",
      "source": "NVD",
      "category": "nvd",
      "published_date": "2026-09-15",
      "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-XXXX",
      "summary": "[EXTERNAL SOURCE — UNVALIDATED] Remote code execution via ...",
      "relevance_score": 0.6,
      "matched_keywords": ["nginx"],
      "risk_delta": "new"
    }
  ],
  "errors": []
}
```

`errors` lists any sources that failed to fetch — `scan` continues scanning remaining sources when one fails and reports the error in the output.

## Running on a schedule

`scan` is designed for scheduled runs — weekly or biweekly is typical. The `ScanReport` JSON output feeds two downstream steps:

- **`specimen`** — convert high-relevance findings into new risk entries via `IngestFeedForward`
- **The agent layer** (regimen) — score risk deltas and draft stakeholder notifications for items that crossed a relevance or severity threshold since the last scan

```bash
scan --program iso42001 --framework iso42001 --lookback 14 > scan-report.json
```

## License

Apache License 2.0
