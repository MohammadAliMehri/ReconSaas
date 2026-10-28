package fingerprint

import (
	"testing"
)

func TestEngine_LoadsSignatures(t *testing.T) {
	eng, err := NewEngine()
	if err != nil {
		t.Fatalf("failed to create fingerprint engine: %v", err)
	}

	if len(eng.fingerprints) < 200 {
		t.Errorf("expected at least 200 signatures, loaded %d", len(eng.fingerprints))
	}
	if len(eng.categories) < 40 {
		t.Errorf("expected at least 40 categories, loaded %d", len(eng.categories))
	}
}

func TestEngine_MatchingAndVersion(t *testing.T) {
	eng, err := NewEngine()
	if err != nil {
		t.Fatalf("failed to create fingerprint engine: %v", err)
	}

	headers := map[string]string{
		"Server":       "nginx/1.24.0",
		"X-Powered-By": "PHP/8.2.10",
		"CF-RAY":       "abc12345",
	}
	cookies := []string{"PHPSESSID", "__cf_bm"}
	body := `<meta name="generator" content="WordPress 6.5">`
	scripts := []string{"https://example.com/wp-includes/js/jquery.min.js"}

	results := eng.Analyze(headers, cookies, body, "https://example.com", scripts)

	matchMap := make(map[string]MatchResult)
	for _, m := range results {
		matchMap[m.Name] = m
	}

	expected := []string{"Nginx", "PHP", "WordPress", "Cloudflare", "jQuery"}
	for _, exp := range expected {
		if _, ok := matchMap[exp]; !ok {
			t.Errorf("expected match for %s, but not found", exp)
		}
	}

	if nginx, ok := matchMap["Nginx"]; ok && nginx.Version != "1.24.0" {
		t.Errorf("expected Nginx version 1.24.0, got %q", nginx.Version)
	}
	if php, ok := matchMap["PHP"]; ok && php.Version != "8.2.10" {
		t.Errorf("expected PHP version 8.2.10, got %q", php.Version)
	}
	if wp, ok := matchMap["WordPress"]; ok && wp.Version != "6.5" {
		t.Errorf("expected WordPress version 6.5, got %q", wp.Version)
	}
}

func TestEngine_NoFalsePositiveDjango(t *testing.T) {
	eng, err := NewEngine()
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	headers := map[string]string{
		"X-Frame-Options": "DENY",
		"Server":          "nginx",
	}
	cookies := []string{"XSRF-TOKEN"}

	results := eng.Analyze(headers, cookies, "", "https://example.com", nil)
	for _, m := range results {
		if m.Name == "Django" {
			t.Errorf("unexpected false positive for Django")
		}
	}
}

