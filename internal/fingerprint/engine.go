package fingerprint

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
)

//go:embed signatures.json
var defaultSignaturesData []byte

// TechSignature represents patterns defining a technology fingerprint.
type TechSignature struct {
	Headers    map[string]string `json:"headers,omitempty"`
	Cookies    []string          `json:"cookies,omitempty"`
	Meta       map[string]string `json:"meta,omitempty"`
	Scripts    []string          `json:"scripts,omitempty"`
	HTML       []string          `json:"html,omitempty"`
	URL        []string          `json:"url,omitempty"`
	JS         []string          `json:"js,omitempty"`
	Implies    []string          `json:"implies,omitempty"`
	Version    string            `json:"version,omitempty"`
	Categories []int             `json:"categories,omitempty"`
}

// SignatureFile maps technology names to their fingerprint definitions.
type SignatureFile struct {
	Fingerprints map[string]TechSignature `json:"fingerprints"`
	Categories   map[string]string        `json:"categories"`
}

// CompiledTech stores pre-compiled regular expressions for high-performance matching.
type CompiledTech struct {
	Name        string
	Signature   TechSignature
	HeaderRegex map[string]*regexp.Regexp
	CookieRegex []*regexp.Regexp
	MetaRegex   map[string]*regexp.Regexp
	ScriptRegex []*regexp.Regexp
	HTMLRegex   []*regexp.Regexp
	URLRegex    []*regexp.Regexp
	JSRegex     []*regexp.Regexp
	VerRegex    *regexp.Regexp
}

// MatchResult represents a single identified technology and its detection metadata.
type MatchResult struct {
	Name           string   `json:"name"`
	Version        string   `json:"version,omitempty"`
	Confidence     int      `json:"confidence"`
	Categories     []int    `json:"categories,omitempty"`
	CategoryNames  []string `json:"category_names,omitempty"`
	Implies        []string `json:"implies,omitempty"`
	MatchedBy      string   `json:"matched_by"`
	MatchedPattern string   `json:"matched_pattern,omitempty"`
}

// Engine performs signature evaluation on HTTP response artifacts.
type Engine struct {
	mu           sync.RWMutex
	fingerprints map[string]CompiledTech
	categories   map[int]string
}

// NewEngine initializes the engine using embedded signatures.
func NewEngine() (*Engine, error) {
	eng := &Engine{
		fingerprints: make(map[string]CompiledTech),
		categories:   make(map[int]string),
	}
	if err := eng.loadFromBytes(defaultSignaturesData); err != nil {
		return nil, fmt.Errorf("failed to load embedded signatures: %w", err)
	}
	return eng, nil
}

// LoadCustomSignatures loads and compiles signatures from a JSON file path.
func (e *Engine) LoadCustomSignatures(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read signatures file %q: %w", filePath, err)
	}
	return e.loadFromBytes(data)
}

func (e *Engine) loadFromBytes(data []byte) error {
	var sf SignatureFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	for catIDStr, catName := range sf.Categories {
		var id int
		if _, err := fmt.Sscanf(catIDStr, "%d", &id); err == nil {
			e.categories[id] = catName
		}
	}

	for name, sig := range sf.Fingerprints {
		compiled := CompiledTech{
			Name:        name,
			Signature:   sig,
			HeaderRegex: make(map[string]*regexp.Regexp),
			MetaRegex:   make(map[string]*regexp.Regexp),
		}

		for hName, hPattern := range sig.Headers {
			if r, err := regexp.Compile("(?i)" + hPattern); err == nil {
				compiled.HeaderRegex[hName] = r
			}
		}

		for _, cPattern := range sig.Cookies {
			if r, err := regexp.Compile("(?i)" + cPattern); err == nil {
				compiled.CookieRegex = append(compiled.CookieRegex, r)
			}
		}

		for mName, mPattern := range sig.Meta {
			if r, err := regexp.Compile("(?i)" + mPattern); err == nil {
				compiled.MetaRegex[mName] = r
			}
		}

		for _, sPattern := range sig.Scripts {
			if r, err := regexp.Compile("(?i)" + sPattern); err == nil {
				compiled.ScriptRegex = append(compiled.ScriptRegex, r)
			}
		}

		for _, hPattern := range sig.HTML {
			if r, err := regexp.Compile("(?i)" + hPattern); err == nil {
				compiled.HTMLRegex = append(compiled.HTMLRegex, r)
			}
		}

		for _, uPattern := range sig.URL {
			if r, err := regexp.Compile("(?i)" + regexp.QuoteMeta(uPattern)); err == nil {
				compiled.URLRegex = append(compiled.URLRegex, r)
			}
		}

		for _, jPattern := range sig.JS {
			if r, err := regexp.Compile(regexp.QuoteMeta(jPattern)); err == nil {
				compiled.JSRegex = append(compiled.JSRegex, r)
			}
		}

		if sig.Version != "" {
			if r, err := regexp.Compile("(?i)" + sig.Version); err == nil {
				compiled.VerRegex = r
			}
		}

		e.fingerprints[name] = compiled
	}

	return nil
}

// Analyze evaluates response headers, cookies, HTML body, scripts, and URL.
func (e *Engine) Analyze(
	headers map[string]string,
	cookies []string,
	body string,
	reqURL string,
	scriptSources []string,
) []MatchResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	matches := make(map[string]MatchResult)

	// Combine headers into a string for version scanning
	var headerStr strings.Builder
	for k, v := range headers {
		headerStr.WriteString(fmt.Sprintf("%s: %s\n", k, v))
	}
	allHeaders := headerStr.String()

	for techName, ct := range e.fingerprints {
		res := e.checkTech(ct, headers, allHeaders, cookies, body, reqURL, scriptSources)
		if res != nil {
			if existing, ok := matches[techName]; !ok || res.Confidence > existing.Confidence {
				matches[techName] = *res
			}
		}
	}

	// Resolve implied dependencies (e.g., WordPress implies PHP)
	implied := make(map[string]bool)
	for _, m := range matches {
		for _, dep := range m.Implies {
			if _, exists := matches[dep]; !exists && !implied[dep] {
				implied[dep] = true
			}
		}
	}

	for depName := range implied {
		if ct, ok := e.fingerprints[depName]; ok {
			var catNames []string
			for _, cid := range ct.Signature.Categories {
				if cname, exists := e.categories[cid]; exists {
					catNames = append(catNames, cname)
				}
			}
			matches[depName] = MatchResult{
				Name:          depName,
				Confidence:    30, // Inferred confidence
				Categories:    ct.Signature.Categories,
				CategoryNames: catNames,
				MatchedBy:     "implied",
			}
		}
	}

	// Sort results descending by confidence
	results := make([]MatchResult, 0, len(matches))
	for _, m := range matches {
		results = append(results, m)
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Confidence > results[j].Confidence
	})

	return results
}

func (e *Engine) checkTech(
	ct CompiledTech,
	headers map[string]string,
	allHeaders string,
	cookies []string,
	body string,
	reqURL string,
	scriptSources []string,
) *MatchResult {
	var bestConfidence int
	var bestMatchedBy string
	var bestPattern string
	var version string
	matched := false

	// 1. Headers (100% confidence)
	for hName, regex := range ct.HeaderRegex {
		var actual string
		for k, v := range headers {
			if strings.EqualFold(k, hName) {
				actual = v
				break
			}
		}
		if actual != "" && regex.MatchString(actual) {
			matched = true
			if 100 > bestConfidence {
				bestConfidence = 100
				bestMatchedBy = "headers"
				bestPattern = fmt.Sprintf("%s: %s", hName, regex.String())
			}
			if version == "" {
				version = extractVersion(regex, actual)
			}
		}
	}

	// 2. Cookies (90% confidence)
	for _, regex := range ct.CookieRegex {
		for _, c := range cookies {
			if regex.MatchString(c) {
				matched = true
				if 90 > bestConfidence {
					bestConfidence = 90
					bestMatchedBy = "cookies"
					bestPattern = regex.String()
				}
				break
			}
		}
	}

	// 3. Meta tags (95% confidence)
	for mName, regex := range ct.MetaRegex {
		// Pattern: <meta name="generator" content="..."> or reverse
		metaRe := regexp.MustCompile(fmt.Sprintf(`(?i)<meta[^>]+(?:name|property)=["']%s["'][^>]+content=["']([^"']+)`, regexp.QuoteMeta(mName)))
		if sub := metaRe.FindStringSubmatch(body); len(sub) > 1 {
			if regex.MatchString(sub[1]) {
				matched = true
				if 95 > bestConfidence {
					bestConfidence = 95
					bestMatchedBy = "meta"
					bestPattern = fmt.Sprintf("%s: %s", mName, regex.String())
				}
				if version == "" {
					version = extractVersion(regex, sub[1])
				}
			}
		}
	}

	// 4. Scripts (80% confidence)
	for _, regex := range ct.ScriptRegex {
		for _, s := range scriptSources {
			if regex.MatchString(s) {
				matched = true
				if 80 > bestConfidence {
					bestConfidence = 80
					bestMatchedBy = "scripts"
					bestPattern = regex.String()
				}
				if version == "" {
					version = extractVersion(regex, s)
				}
				break
			}
		}
	}

	// 5. HTML Body (70% confidence)
	for _, regex := range ct.HTMLRegex {
		if regex.MatchString(body) {
			matched = true
			if 70 > bestConfidence {
				bestConfidence = 70
				bestMatchedBy = "html"
				bestPattern = regex.String()
			}
			if version == "" {
				version = extractVersion(regex, body)
			}
			break
		}
	}

	// 6. URL (75% confidence)
	for _, regex := range ct.URLRegex {
		if regex.MatchString(reqURL) {
			matched = true
			if 75 > bestConfidence {
				bestConfidence = 75
				bestMatchedBy = "url"
				bestPattern = regex.String()
			}
			break
		}
	}

	// 7. JS globals in body (60% confidence)
	for _, regex := range ct.JSRegex {
		if regex.MatchString(body) {
			matched = true
			if 60 > bestConfidence {
				bestConfidence = 60
				bestMatchedBy = "js"
				bestPattern = regex.String()
			}
			break
		}
	}

	if !matched {
		return nil
	}

	// Check dedicated version regex if not extracted yet
	if version == "" && ct.VerRegex != nil {
		version = extractVersion(ct.VerRegex, allHeaders)
		if version == "" && len(body) > 0 {
			sample := body
			if len(sample) > 5000 {
				sample = sample[:5000]
			}
			version = extractVersion(ct.VerRegex, sample)
		}
	}

	var catNames []string
	for _, cid := range ct.Signature.Categories {
		if cname, exists := e.categories[cid]; exists {
			catNames = append(catNames, cname)
		}
	}

	return &MatchResult{
		Name:           ct.Name,
		Version:        version,
		Confidence:     bestConfidence,
		Categories:     ct.Signature.Categories,
		CategoryNames:  catNames,
		Implies:        ct.Signature.Implies,
		MatchedBy:      bestMatchedBy,
		MatchedPattern: bestPattern,
	}
}

var versionDigitsRegex = regexp.MustCompile(`^[\d.]+$`)

func extractVersion(re *regexp.Regexp, text string) string {
	matches := re.FindStringSubmatch(text)
	if len(matches) > 1 {
		candidate := strings.TrimSpace(matches[1])
		if versionDigitsRegex.MatchString(candidate) {
			return candidate
		}
	}
	return ""
}

