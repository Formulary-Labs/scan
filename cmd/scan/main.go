// scan runs external regulatory/threat intelligence monitoring for a program.
//
// Usage:
//
//	scan --program <slug> [--config scan-config.json] [--format json|md]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Formulary-Labs/scan/monitor"
	"github.com/Formulary-Labs/substrate/exit"
	"github.com/Formulary-Labs/substrate/provenance"
)

const version = "0.1.0"

func main() {
	var (
		programFlag  = flag.String("program", "", "Program slug (required)")
		configFlag   = flag.String("config", "", "Path to scan config JSON")
		frameworkFlag = flag.String("framework", "", "Compliance framework slug (iso27001, iec62443, iso42001, etc.)")
		categoriesFlag = flag.String("categories", "", "Comma-separated source categories: cisa,nvd,regulatory,aiml,custom")
		lookbackFlag = flag.Int("lookback-days", 14, "Lookback window in days")
		thresholdFlag = flag.Float64("threshold", 0.1, "Minimum relevance score [0-1]")
		dryRunFlag   = flag.Bool("dry-run", false, "Print what would be fetched without making network requests")
		fmtFlag      = flag.String("format", "json", "Output format: json (default), md")
		versionFlag  = flag.Bool("version", false, "Print version and exit")
	)
	flag.Usage = usage
	flag.Parse()

	if *versionFlag {
		fmt.Printf("scan version %s\n", version)
		os.Exit(exit.OK)
	}

	if *programFlag == "" {
		fmt.Fprintln(os.Stderr, `{"error": "--program is required", "code": 2}`)
		flag.Usage()
		os.Exit(exit.ToolError)
	}

	var cfg monitor.ScanConfig
	if *configFlag != "" {
		loaded, err := monitor.LoadConfig(*configFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, `{"error": %q, "code": 2}`+"\n", err.Error())
			os.Exit(exit.ToolError)
		}
		cfg = *loaded
	}

	// CLI flags override config file.
	if *programFlag != "" {
		cfg.Program = *programFlag
	}
	if *frameworkFlag != "" {
		cfg.Framework = *frameworkFlag
	}
	if *lookbackFlag > 0 {
		cfg.LookbackDays = *lookbackFlag
	}
	if *categoriesFlag != "" {
		for _, c := range strings.Split(*categoriesFlag, ",") {
			cfg.Categories = append(cfg.Categories, monitor.SourceCategory(strings.TrimSpace(c)))
		}
	}

	report := monitor.Run(cfg, *dryRunFlag, nil)

	// Filter by threshold.
	if *thresholdFlag > 0 {
		var filtered []monitor.Finding
		for _, f := range report.Findings {
			if f.RelevanceScore >= *thresholdFlag {
				filtered = append(filtered, f)
			}
		}
		report.Findings = filtered
	}

	switch *fmtFlag {
	case "md":
		printMD(report)
	default:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(report) //nolint:errcheck
	}

	_ = provenance.Write("logs/provenance.jsonl", provenance.Entry{
		Spec:        "functions/external-intel-spec.md",
		Output:      "stdout",
		OutputType:  "other",
		Program:     cfg.Program,
		Purpose:     fmt.Sprintf("scan: %d findings, %d lookback days, framework %s", len(report.Findings), cfg.LookbackDays, cfg.Framework),
		Reusability: provenance.Instance,
		QualityGate: provenance.Pass,
		Tool:        "scan",
		ToolVersion: version,
	})
}

func printMD(r monitor.ScanReport) {
	sb := &strings.Builder{}
	fmt.Fprintf(sb, "# External Intelligence Scan: %s\n\n", r.Program)
	fmt.Fprintf(sb, "**Scanned:** %s  \n", r.ScannedAt.Format("2006-01-02 15:04 UTC"))
	fmt.Fprintf(sb, "**Lookback:** %d days  \n", r.LookbackDays)
	fmt.Fprintf(sb, "**Findings:** %d\n\n", len(r.Findings))

	if r.Warning != "" {
		fmt.Fprintf(sb, "> %s\n\n", r.Warning)
	}
	if len(r.Errors) > 0 {
		fmt.Fprintf(sb, "## Source Errors\n\n")
		for _, e := range r.Errors {
			fmt.Fprintf(sb, "- %s\n", e)
		}
		fmt.Fprintln(sb)
	}

	if len(r.Findings) == 0 {
		fmt.Fprintf(sb, "No findings above the relevance threshold.\n")
	} else {
		fmt.Fprintf(sb, "| ID | Source | Score | Title |\n|---|---|---|---|\n")
		for _, f := range r.Findings {
			title := f.Title
			if len(title) > 70 {
				title = title[:67] + "..."
			}
			fmt.Fprintf(sb, "| %s | %s | %.2f | %s |\n", f.ID, f.Source, f.RelevanceScore, title)
		}
		fmt.Fprintln(sb)
		for _, f := range r.Findings {
			fmt.Fprintf(sb, "### %s — %s\n\n", f.ID, f.Title)
			fmt.Fprintf(sb, "**Source:** %s (%s)  \n", f.Source, f.Category)
			fmt.Fprintf(sb, "**Published:** %s  \n", f.PublishedDate)
			fmt.Fprintf(sb, "**Relevance:** %.2f (matched: %s)  \n\n", f.RelevanceScore, strings.Join(f.MatchedKeywords, ", "))
			fmt.Fprintf(sb, "%s\n\n", f.Summary)
			if f.URL != "" {
				fmt.Fprintf(sb, "[Source](%s)\n\n", f.URL)
			}
		}
	}
	fmt.Print(sb.String())
}

func usage() {
	fmt.Fprintln(os.Stderr, `scan — external regulatory/threat intelligence monitoring

Usage:
  scan --program <slug> [flags]

Flags:
  --program string      Program slug (required)
  --config string       Path to scan config JSON
  --framework string    Framework: iso27001, iso42001, iec62443, soc2, fedramp, nist-csf
  --categories string   Source categories: cisa,nvd,regulatory,aiml,custom (default: all)
  --lookback-days int   Lookback window in days (default: 14)
  --threshold float     Minimum relevance score 0-1 (default: 0.1)
  --dry-run             Print config without making network requests
  --format string       Output format: json (default), md
  --version             Print version and exit

Examples:
  scan --program iso42001 --framework iso42001 --dry-run
  scan --program iso42001 --framework iso42001 --lookback-days 7 --format md
  scan --program iso42001 --config data/iso42001/scan-config.json`)
}
