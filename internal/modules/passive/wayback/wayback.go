package wayback

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/MohammadAliMehri/ReconSaas/internal/engine"
	"github.com/MohammadAliMehri/ReconSaas/internal/model"
	"github.com/MohammadAliMehri/ReconSaas/internal/scope"
)

// Module discovers historical URLs and endpoints from the Wayback Machine.
type Module struct{}

// New creates a new wayback module instance.
func New() *Module {
	return &Module{}
}

func (m *Module) ID() string          { return "wayback" }
func (m *Module) Phase() model.Mode   { return model.ModePassive }
func (m *Module) Description() string { return "Wayback Machine Historical URL Discovery" }

var sensitiveExtensions = []string{
	".sql", ".bak", ".old", ".zip", ".tar.gz", ".tar", ".gz",
	".conf", ".config", ".cfg", ".ini", ".env", ".properties",
	".xml", ".json", ".yaml", ".yml", ".toml",
	".log", ".txt", ".csv", ".xls", ".xlsx",
	".pem", ".key", ".crt", ".cer", ".p12", ".pfx",
}

var interestingPaths = []string{
	"/admin", "/internal", "/api/", "/graphql", "/swagger", "/docs",
	"/debug", "/console", "/shell", "/manager", "/wp-admin",
	"/phpmyadmin", "/.git", "/.svn", "/.env", "/config",
	"/backup", "/test", "/dev", "/staging", "/login", "/auth",
}

func (m *Module) Run(ctx context.Context, req engine.Request, emit func(model.Finding) error) (*model.ModuleResult, error) {
	domain := scope.CanonicalizeDomain(req.Target)
	var findings []model.Finding

	cdxURL := fmt.Sprintf(
		"https://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=original,statuscode,mimetype,timestamp&collapse=urlkey&limit=5000",
		domain,
	)

	var urlsList []map[string]string
	var sensitiveFiles []string
	var interestingList []string
	uniquePaths := make(map[string]bool)
	statusCodes := make(map[string]int)

	if resp, err := req.Client.Get(ctx, cdxURL, nil); err == nil && resp.StatusCode == 200 {
		var rawRows [][]string
		if err := json.Unmarshal(resp.Body, &rawRows); err == nil && len(rawRows) > 1 {
			// Skip header row
			for _, row := range rawRows[1:] {
				if len(row) == 0 {
					continue
				}
				origURL := row[0]
				statusCode := ""
				if len(row) > 1 {
					statusCode = row[1]
				}
				mime := ""
				if len(row) > 2 {
					mime = row[2]
				}
				ts := ""
				if len(row) > 3 {
					ts = row[3]
				}

				if statusCode != "" {
					statusCodes[statusCode]++
				}

				urlsList = append(urlsList, map[string]string{
					"url":        origURL,
					"status":     statusCode,
					"mimetype":   mime,
					"timestamp":  ts,
				})

				urlLower := strings.ToLower(origURL)
				for _, ext := range sensitiveExtensions {
					if strings.HasSuffix(urlLower, ext) || strings.Contains(urlLower, ext+"?") {
						sensitiveFiles = append(sensitiveFiles, origURL)
						break
					}
				}

				for _, p := range interestingPaths {
					if strings.Contains(urlLower, p) {
						interestingList = append(interestingList, origURL)
						break
					}
				}

				if parsed, err := url.Parse(origURL); err == nil && parsed.Path != "" {
					uniquePaths[parsed.Path] = true
				}
			}
		}
	}

	sort.Strings(sensitiveFiles)
	sort.Strings(interestingList)

	var pathList []string
	for p := range uniquePaths {
		pathList = append(pathList, p)
	}
	sort.Strings(pathList)

	// Save unique paths and URLs in shared data for downstream analysis/JS module
	req.SharedData.Store("wayback_urls", urlsList)
	req.SharedData.Store("wayback_paths", pathList)

	if len(urlsList) > 0 {
		f := model.Finding{
			ID:        fmt.Sprintf("wayback-total-%s", domain),
			Module:    m.ID(),
			Target:    domain,
			Title:     fmt.Sprintf("Wayback: %d Historical URLs Found", len(urlsList)),
			Detail:    fmt.Sprintf("Discovered %d archived URLs and %d unique paths.", len(urlsList), len(pathList)),
			Severity:  model.SeverityInfo,
			Timestamp: time.Now().UTC(),
		}
		findings = append(findings, f)
		_ = emit(f)
	}

	if len(sensitiveFiles) > 0 {
		sample := sensitiveFiles
		if len(sample) > 15 {
			sample = sample[:15]
		}
		f := model.Finding{
			ID:        fmt.Sprintf("wayback-sensitive-%s", domain),
			Module:    m.ID(),
			Target:    domain,
			Title:     fmt.Sprintf("Sensitive File Extensions in Archive (%d)", len(sensitiveFiles)),
			Detail:    fmt.Sprintf("Potential backup or config artifacts: %s", strings.Join(sample, ", ")),
			Severity:  model.SeverityMedium,
			Timestamp: time.Now().UTC(),
		}
		findings = append(findings, f)
		_ = emit(f)
	}

	data := map[string]interface{}{
		"total_urls":        len(urlsList),
		"urls":              urlsList,
		"sensitive_files":   sensitiveFiles,
		"interesting_paths": interestingList,
		"unique_paths":      pathList,
		"status_codes":      statusCodes,
	}

	return &model.ModuleResult{
		Module:    m.ID(),
		Target:    domain,
		Findings:  findings,
		Data:      data,
		Timestamp: time.Now().UTC(),
	}, nil
}

