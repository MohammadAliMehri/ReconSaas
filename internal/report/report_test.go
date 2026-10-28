package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MohammadAliMehri/ReconSaas/internal/model"
)

func TestGenerator_GenerateFiles(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "recon-report-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	gen := NewGenerator(tempDir, "example.com", model.ModePassive)

	findings := []model.Finding{
		{
			ID:        "f-1",
			Module:    "dns",
			Target:    "example.com",
			Title:     "DNS A Records",
			Severity:  model.SeverityInfo,
			Timestamp: time.Now().UTC(),
		},
		{
			ID:        "f-2",
			Module:    "headers",
			Target:    "example.com",
			Title:     "CORS Wildcard with Credentials",
			Severity:  model.SeverityCritical,
			Timestamp: time.Now().UTC(),
		},
	}

	results := []*model.ModuleResult{
		{
			Module:    "certs",
			Target:    "example.com",
			Duration:  100 * time.Millisecond,
			Findings:  findings[:1],
			Data:      map[string]interface{}{"subdomains": []string{"sub1.example.com", "sub2.example.com"}},
			Timestamp: time.Now().UTC(),
		},
	}

	if err := gen.Generate(results, findings); err != nil {
		t.Fatalf("gen.Generate failed: %v", err)
	}

	// Verify report.md
	mdBytes, err := os.ReadFile(filepath.Join(tempDir, "report.md"))
	if err != nil {
		t.Fatalf("failed to read report.md: %v", err)
	}
	if len(mdBytes) == 0 {
		t.Errorf("report.md is empty")
	}

	// Verify report.json
	jsonBytes, err := os.ReadFile(filepath.Join(tempDir, "report.json"))
	if err != nil {
		t.Fatalf("failed to read report.json: %v", err)
	}
	var reportData map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &reportData); err != nil {
		t.Fatalf("failed to parse report.json: %v", err)
	}
	if summary, ok := reportData["summary"].(map[string]interface{}); ok {
		if total, ok := summary["total_findings"].(float64); !ok || total != 2 {
			t.Errorf("expected 2 total findings in json, got %v", summary["total_findings"])
		}
	} else {
		t.Errorf("missing summary in report.json")
	}

	// Verify subdomains.txt
	subBytes, err := os.ReadFile(filepath.Join(tempDir, "passive", "subdomains.txt"))
	if err != nil {
		t.Fatalf("failed to read subdomains.txt: %v", err)
	}
	if string(subBytes) != "sub1.example.com\nsub2.example.com" {
		t.Errorf("unexpected subdomains.txt content: %q", string(subBytes))
	}
}

