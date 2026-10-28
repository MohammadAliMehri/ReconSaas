package model

import "time"

// Mode represents the execution mode of the recon framework.
type Mode string

const (
	ModePassive Mode = "passive"
	ModeActive  Mode = "active"
	ModeHybrid  Mode = "hybrid"
)

// Severity indicates the risk or importance level of a finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Evidence holds raw, immutable supporting data for a finding.
type Evidence struct {
	Type        string      `json:"type"`                  // e.g. "header", "url", "body_snippet", "record", "socket_banner"
	Source      string      `json:"source"`                // origin of evidence, e.g. "https://example.com/robots.txt"
	Description string      `json:"description,omitempty"` // contextual notes
	Data        interface{} `json:"data"`                  // structured or scalar evidence payload
}

// Finding represents an individual observation or vulnerability lead discovered by a module.
type Finding struct {
	ID         string     `json:"id"`
	Module     string     `json:"module"`
	Target     string     `json:"target"`
	Title      string     `json:"title"`
	Detail     string     `json:"detail,omitempty"`
	Severity   Severity   `json:"severity"`
	Confidence float64    `json:"confidence"` // 0.0 to 1.0 (or percentage 0 to 100)
	Evidence   []Evidence `json:"evidence,omitempty"`
	Timestamp  time.Time  `json:"timestamp"`
}

// Asset represents a discovered target entity (domain, subdomain, port, URL, endpoint).
type Asset struct {
	Type       string                 `json:"type"` // e.g. "subdomain", "port", "url", "endpoint"
	Identifier string                 `json:"identifier"`
	Source     string                 `json:"source"`
	Score      float64                `json:"score,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// ModuleResult contains the collected data and findings returned by a module execution.
type ModuleResult struct {
	Module    string                 `json:"module"`
	Target    string                 `json:"target"`
	Duration  time.Duration          `json:"duration_ns"`
	Findings  []Finding              `json:"findings"`
	Data      map[string]interface{} `json:"data"`
	Errors    []string               `json:"errors,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

