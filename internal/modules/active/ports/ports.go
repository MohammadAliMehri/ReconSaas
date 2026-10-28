package ports

import (
	"context"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MohammadAliMehri/ReconSaas/internal/engine"
	"github.com/MohammadAliMehri/ReconSaas/internal/model"
	"github.com/MohammadAliMehri/ReconSaas/internal/scope"
)

// Module performs TCP connect port scanning and banner grabbing on authorized targets.
type Module struct {
	topPorts map[int]string
}

// New creates a new ports module instance.
func New() *Module {
	return &Module{
		topPorts: map[int]string{
			21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
			80: "http", 110: "pop3", 111: "rpc", 135: "msrpc", 139: "netbios",
			143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
			1433: "mssql", 1521: "oracle", 2049: "nfs", 3306: "mysql",
			3389: "rdp", 5432: "postgres", 5900: "vnc", 6379: "redis",
			8080: "http-alt", 8443: "https-alt", 8888: "http-alt2",
			9090: "web-console", 9200: "elasticsearch", 11211: "memcached",
			27017: "mongodb", 50000: "sap", 50070: "hadoop",
			4200: "angular-dev", 3000: "node-dev", 5000: "flask-dev",
			8000: "django-dev", 8001: "http-dev", 4443: "https-dev",
			15672: "rabbitmq-mgmt", 2379: "etcd", 2375: "docker",
			10250: "kubelet", 6443: "kubernetes-api",
		},
	}
}

func (m *Module) ID() string          { return "ports" }
func (m *Module) Phase() model.Mode   { return model.ModeActive }
func (m *Module) Description() string { return "TCP Port & Service Banner Scanner" }

type portResult struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	Banner  string `json:"banner,omitempty"`
}

func (m *Module) Run(ctx context.Context, req engine.Request, emit func(model.Finding) error) (*model.ModuleResult, error) {
	domain := scope.CanonicalizeDomain(req.Target)
	var findings []model.Finding

	var portsToScan []int
	for p := range m.topPorts {
		portsToScan = append(portsToScan, p)
	}
	sort.Ints(portsToScan)

	// Concurrency-limited port scanning
	sem := make(chan struct{}, 20)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var openPorts []portResult

	for _, p := range portsToScan {
		if ctx.Err() != nil {
			break
		}

		port := p
		serviceName := m.topPorts[port]
		targetAddr := fmt.Sprintf("%s:%d", domain, port)

		wg.Add(1)
		sem <- struct{}{}

		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			connCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
			defer cancel()

			conn, err := req.Client.DialTCP(connCtx, targetAddr)
			if err != nil {
				return
			}
			defer conn.Close()

			// Port is open
			banner := grabBanner(conn, 1000*time.Millisecond)
			res := portResult{
				Port:    port,
				Service: serviceName,
				Banner:  banner,
			}

			mu.Lock()
			openPorts = append(openPorts, res)
			mu.Unlock()

			sev := model.SeverityInfo
			if isHighRiskPort(port) {
				sev = model.SeverityMedium
			}

			f := model.Finding{
				ID:        fmt.Sprintf("port-%d-%s", port, domain),
				Module:    m.ID(),
				Target:    domain,
				Title:     fmt.Sprintf("Open Port %d (%s)", port, serviceName),
				Detail:    fmt.Sprintf("Port %d is open. Service: %s. Banner: %s", port, serviceName, banner),
				Severity:  sev,
				Timestamp: time.Now().UTC(),
				Evidence: []model.Evidence{
					{Type: "socket_banner", Source: targetAddr, Data: banner},
				},
			}
			_ = emit(f)
		}()
	}

	wg.Wait()

	sort.Slice(openPorts, func(i, j int) bool {
		return openPorts[i].Port < openPorts[j].Port
	})

	// Store open ports in shared data
	req.SharedData.Store("open_ports", openPorts)

	data := map[string]interface{}{
		"open_ports":  openPorts,
		"total_open":  len(openPorts),
		"scanned_top": len(portsToScan),
	}

	return &model.ModuleResult{
		Module:    m.ID(),
		Target:    domain,
		Findings:  findings,
		Data:      data,
		Timestamp: time.Now().UTC(),
	}, nil
}

func grabBanner(conn net.Conn, timeout time.Duration) string {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		return ""
	}
	banner := strings.TrimSpace(string(buf[:n]))
	banner = strings.ReplaceAll(banner, "\r", " ")
	banner = strings.ReplaceAll(banner, "\n", " ")
	if len(banner) > 120 {
		banner = banner[:120] + "..."
	}
	return banner
}

func isHighRiskPort(port int) bool {
	highRisk := map[int]bool{
		21: true, 23: true, 445: true, 1433: true, 1521: true,
		2049: true, 2375: true, 2379: true, 3306: true, 3389: true,
		5432: true, 5900: true, 6379: true, 9200: true, 10250: true,
		11211: true, 27017: true,
	}
	return highRisk[port]
}

