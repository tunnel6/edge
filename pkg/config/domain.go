package config

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// DomainProvider 定义获取 Edge 级别域名配置的接口
// 各组件依赖此接口获取 AssignedDomain 和 CustomDomain，不持有副本
type DomainProvider interface {
	GetAssignedDomain() string
	GetCustomDomain() string
}

// DNS status constants
const (
	DNSStatusUnknown  uint8 = 0
	DNSStatusResolved uint8 = 1
	DNSStatusFailed   uint8 = 2
)

// Cert status constants
const (
	CertStatusUnknown uint8 = 0
	CertStatusReady   uint8 = 1
	CertStatusMissing uint8 = 2
)

// CNAME status constants (mirrors server.CnameStatus*)
const (
	CnameStatusUnknown  uint8 = 0
	CnameStatusMatched  uint8 = 2
	CnameStatusMismatch uint8 = 3
	CnameStatusNotFound uint8 = 4
)

// DomainStatus holds cached DNS/cert status for a domain, checked once at startup.
type DomainStatus struct {
	DNSStatus  uint8  // DNSStatus*
	CertStatus uint8  // CertStatus*
	Error      string // last error message, if any
}

// DomainConfig 是 DomainProvider 的可变实现
// 提供线程安全的 getter/setter，并支持持久化
type DomainConfig struct {
	mu             sync.RWMutex
	assignedDomain string
	customDomain   string
	dataDir        string

	// Cached DNS/cert status, checked once at startup
	assignedStatus DomainStatus
	customStatus   DomainStatus
	cnameStatus    uint8 // CnameStatus*
}

// NewDomainConfig 创建 DomainConfig 实例
func NewDomainConfig(dataDir string) *DomainConfig {
	return &DomainConfig{
		dataDir: dataDir,
	}
}

// GetAssignedDomain 返回当前的 AssignedDomain
func (d *DomainConfig) GetAssignedDomain() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.assignedDomain
}

// GetCustomDomain 返回当前的 CustomDomain
func (d *DomainConfig) GetCustomDomain() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.customDomain
}

// SetAssignedDomain updates AssignedDomain and persists it.
// It keeps the historical bool-only API; callers that need persistence errors
// should use SetAssignedDomainWithError.
func (d *DomainConfig) SetAssignedDomain(domain string) bool {
	changed, _ := d.SetAssignedDomainWithError(domain)
	return changed
}

// SetAssignedDomainWithError updates AssignedDomain and persists it.
// It persists even when the in-memory value is unchanged, so a manually removed
// assigned-domain file can be restored on the next bootstrap.
func (d *DomainConfig) SetAssignedDomainWithError(domain string) (bool, error) {
	domain = normalizeDomain(domain)

	d.mu.Lock()
	changed := d.assignedDomain != domain
	if changed {
		d.assignedDomain = domain
	}
	dataDir := d.dataDir
	d.mu.Unlock()

	// 持久化（不在锁内执行 IO）
	if dataDir != "" && domain != "" {
		if err := SaveAssignedDomain(dataDir, domain); err != nil {
			return changed, err
		}
	}
	return changed, nil
}

// SetCustomDomain 更新 CustomDomain
// 返回是否有变化
func (d *DomainConfig) SetCustomDomain(domain string) bool {
	domain = normalizeDomain(domain)

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.customDomain == domain {
		return false
	}
	d.customDomain = domain
	return true
}

// LoadFromLocal 从本地文件加载 AssignedDomain
func (d *DomainConfig) LoadFromLocal() error {
	if d.dataDir == "" {
		return nil
	}
	domain, err := LoadAssignedDomain(d.dataDir)
	if err != nil {
		return err
	}
	d.SetAssignedDomain(domain)
	return nil
}

// GetAssignedDomainStatus 返回缓存的 assigned domain DNS/cert 状态
func (d *DomainConfig) GetAssignedDomainStatus() DomainStatus {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.assignedStatus
}

// GetCustomDomainStatus 返回缓存的 custom domain DNS/cert 状态
func (d *DomainConfig) GetCustomDomainStatus() DomainStatus {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.customStatus
}

// GetCnameStatus 返回缓存的 CNAME 状态
func (d *DomainConfig) GetCnameStatus() uint8 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.cnameStatus
}

// CertChecker is a callback that checks whether a valid certificate exists for a domain.
// Returns true if a usable cert is available.
type CertChecker func(domain string) bool

// CheckAndStoreDNSStatus performs one-time DNS resolution and cert checks for both
// assigned and custom domains, storing the results in memory.
func (d *DomainConfig) CheckAndStoreDNSStatus(certChecker CertChecker) {
	d.mu.RLock()
	assigned := d.assignedDomain
	custom := d.customDomain
	d.mu.RUnlock()

	var assignedStatus, customStatus DomainStatus
	var cnameStatus uint8

	// Check assigned domain
	if assigned != "" {
		assignedStatus = checkDomainDNS(assigned)
		if certChecker != nil && certChecker("*."+assigned) {
			assignedStatus.CertStatus = CertStatusReady
		} else {
			assignedStatus.CertStatus = CertStatusMissing
		}
	}

	// Check custom domain
	if custom != "" {
		customStatus = checkDomainDNS(custom)
		if certChecker != nil && certChecker("*."+custom) {
			customStatus.CertStatus = CertStatusReady
		} else {
			customStatus.CertStatus = CertStatusMissing
		}

		// Check CNAME: custom -> assigned
		if assigned != "" {
			cnameStatus = checkCNAME(custom, assigned)
		}
	}

	d.mu.Lock()
	d.assignedStatus = assignedStatus
	d.customStatus = customStatus
	d.cnameStatus = cnameStatus
	d.mu.Unlock()
}

// checkDomainDNS resolves a domain to verify DNS is working.
func checkDomainDNS(domain string) DomainStatus {
	probe := fmt.Sprintf("_yat-probe.%s", domain)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try CNAME first (wildcard check)
	if cname, err := net.DefaultResolver.LookupCNAME(ctx, probe); err == nil && cname != "" {
		return DomainStatus{DNSStatus: DNSStatusResolved}
	}

	// Fallback: try A/AAAA on the bare domain
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	if addrs, err := net.DefaultResolver.LookupHost(ctx2, domain); err == nil && len(addrs) > 0 {
		return DomainStatus{DNSStatus: DNSStatusResolved}
	}

	return DomainStatus{DNSStatus: DNSStatusFailed, Error: fmt.Sprintf("dns lookup failed for %s", domain)}
}

// checkCNAME checks if *.customDomain has a CNAME pointing to assignedDomain.
func checkCNAME(customDomain, assignedDomain string) uint8 {
	probe := "_yat-probe." + customDomain
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cname, err := net.DefaultResolver.LookupCNAME(ctx, probe)
	if err != nil || cname == "" {
		return CnameStatusNotFound
	}

	cname = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(cname)), ".")

	// Accept assignedDomain itself or any host under its base
	assignedBase := assignedDomain
	if idx := strings.IndexByte(assignedDomain, '.'); idx > 0 && idx+1 < len(assignedDomain) {
		assignedBase = assignedDomain[idx+1:]
	}

	if cname == assignedDomain || cname == assignedBase || strings.HasSuffix(cname, "."+assignedBase) {
		return CnameStatusMatched
	}
	return CnameStatusMismatch
}

// normalizeDomain 标准化域名：去除空白、转小写、去除末尾点号
func normalizeDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.ToLower(domain)
	domain = strings.TrimSuffix(domain, ".")
	return domain
}
