package certmgr

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	logger "icool.io/yat/edge/pkg/log"
)

// YatScopeOID is the X.509 extension OID for certificate scope claims.
// When present, the extension value is an ASN.1 SEQUENCE OF UTF8String,
// each entry being a scope token such as "network:<networkID>".
// Absence of this extension means full (unrestricted) access.
var YatScopeOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}

// EncodeScopeExtension marshals a list of scope tokens into an X.509
// extension value suitable for ExtraExtensions.
func EncodeScopeExtension(scopes []string) (pkix.Extension, error) {
	val, err := asn1.Marshal(scopes)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("marshal scope extension: %w", err)
	}
	return pkix.Extension{
		Id:    YatScopeOID,
		Value: val,
	}, nil
}

// ParseScopeExtension extracts scope tokens from a raw X.509 extension
// value (the DER bytes). Returns nil when the extension is absent or
// cannot be decoded.
func ParseScopeExtension(raw []byte) []string {
	var scopes []string
	if _, err := asn1.Unmarshal(raw, &scopes); err != nil {
		return nil
	}
	return scopes
}

// FindScopeExtension searches a certificate's extensions for the yat-scope
// OID and returns the decoded scope tokens. Returns nil when not found.
func FindScopeExtension(cert *x509.Certificate) []string {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(YatScopeOID) {
			return ParseScopeExtension(ext.Value)
		}
	}
	return nil
}

// EdgeAuthorization is signed by this Edge's CA and scoped to one Edge.
// Client-supplied CSR subject and extensions never determine privileges.
type EdgeAuthorization struct {
	EdgeID string
	Role   string
}

const RoleOwner = "owner"
const RoleDevice = "device"

var YatAuthorizationOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 2}

func ReadEdgeAuthorization(cert *x509.Certificate, edgeID string) (EdgeAuthorization, error) {
	if cert != nil {
		for _, ext := range cert.Extensions {
			if !ext.Id.Equal(YatAuthorizationOID) {
				continue
			}
			var auth EdgeAuthorization
			rest, err := asn1.Unmarshal(ext.Value, &auth)
			if err == nil && len(rest) == 0 && auth.EdgeID == edgeID && (auth.Role == RoleOwner || auth.Role == RoleDevice) {
				return auth, nil
			}
			return EdgeAuthorization{}, fmt.Errorf("invalid certificate Edge authorization")
		}
	}
	return EdgeAuthorization{}, fmt.Errorf("certificate has no Edge authorization; pair again")
}

type EdgeCA struct {
	subCAKey  crypto.PrivateKey
	subCACert *x509.Certificate
	rootCert  *x509.Certificate
}

// Create
func NewEdgeCA(subCAKeyPEM, subCACertPEM, rootCertPEM []byte) (*EdgeCA, error) {
	// Parse
	keyBlock, _ := pem.Decode(subCAKeyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode sub-CA key PEM")
	}

	subCAKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse sub-CA key: %w", err)
	}

	// Parse
	subCACert, err := parseCertPEM(subCACertPEM)
	if err != nil {
		return nil, fmt.Errorf("parse sub-CA cert: %w", err)
	}

	// Verify
	if !subCACert.IsCA {
		return nil, fmt.Errorf("sub-CA certificate is not a CA cert")
	}

	// Parse
	rootCert, err := parseCertPEM(rootCertPEM)
	if err != nil {
		return nil, fmt.Errorf("parse root cert: %w", err)
	}

	logger.Info("EdgeCA initialized",
		"sub_ca_cn", subCACert.Subject.CommonName,
		"sub_ca_expires", subCACert.NotAfter)

	return &EdgeCA{
		subCAKey:  subCAKey,
		subCACert: subCACert,
		rootCert:  rootCert,
	}, nil
}

func (ca *EdgeCA) SignClientCSR(csrPEM []byte, deviceID string, validity time.Duration, scopes []string, authorization EdgeAuthorization) (*ClientCertResult, error) {
	// Parse
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CSR PEM")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}

	// Verify
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid CSR signature: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   buildClientCertCN(deviceID),
			Organization: []string{"Yat"},
			Country:      []string{"CN"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
	}

	// Embed scope claims as a custom X.509 extension.
	// Empty scopes = full access (no extension written).
	if len(scopes) > 0 {
		scopeExt, err := EncodeScopeExtension(scopes)
		if err != nil {
			return nil, fmt.Errorf("encode scope extension: %w", err)
		}
		template.ExtraExtensions = append(template.ExtraExtensions, scopeExt)
	}

	if authorization.EdgeID == "" || (authorization.Role != RoleOwner && authorization.Role != RoleDevice) {
		return nil, fmt.Errorf("invalid Edge certificate authorization")
	}
	roleDER, err := asn1.Marshal(authorization)
	if err != nil {
		return nil, err
	}
	template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{Id: YatAuthorizationOID, Value: roleDER})

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.subCACert, csr.PublicKey, ca.subCAKey)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Build
	subCACertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.subCACert.Raw,
	})

	rootCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.rootCert.Raw,
	})

	chainPEM := append(append(certPEM, subCACertPEM...), rootCertPEM...)

	logger.Info("client certificate signed locally",
		"device_id", deviceID,
		"serial", serialNumber.String(),
		"expires", template.NotAfter,
		"scopes", scopes)

	return &ClientCertResult{
		CertPEM:      certPEM,
		SerialNumber: serialNumber.String(),
		ExpiresAt:    template.NotAfter,
		ChainPEM:     chainPEM,
	}, nil
}

// Get
func (ca *EdgeCA) GetSubCACert() *x509.Certificate {
	return ca.subCACert
}

// Get
func (ca *EdgeCA) GetRootCert() *x509.Certificate {
	return ca.rootCert
}

// Check
func (ca *EdgeCA) IsExpiringSoon(threshold time.Duration) bool {
	return time.Until(ca.subCACert.NotAfter) < threshold
}

type ClientCertResult struct {
	CertPEM      []byte
	SerialNumber string
	ExpiresAt    time.Time
	ChainPEM     []byte
}

// ServerCertRequest Edge TLS 证书签发请求
type ServerCertRequest struct {
	EdgeID        string // Edge ID
	PublicAddress string // 公网地址 (IP 或域名)
	CustomDomain  string // 自定义域名（可选）
	Validity      time.Duration
}

// ServerCertResult Edge TLS 证书签发结果
type ServerCertResult struct {
	CertPEM      []byte
	KeyPEM       []byte
	ChainPEM     []byte // 完整证书链: Cert + Sub-CA + Root
	SerialNumber string
	ExpiresAt    time.Time
}

// SignServerCert 签发 Edge TLS 服务器证书
func (ca *EdgeCA) SignServerCert(req *ServerCertRequest) (*ServerCertResult, error) {
	// 1. 生成新的密钥对
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate private key: %w", err)
	}

	// 2. 生成序列号
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}

	// 3. 构建 SAN (Subject Alternative Names)
	var dnsNames []string
	var ipAddresses []net.IP

	// 添加 Edge ID 相关域名
	dnsNames = append(dnsNames,
		fmt.Sprintf("%s.edge.myproxy.dev", req.EdgeID),
		fmt.Sprintf("%s.edge.yat.io", req.EdgeID),
		fmt.Sprintf("%s.myproxy.dev", req.EdgeID),
		fmt.Sprintf("%s.e.tunnel6.com", req.EdgeID),
		"localhost",
	)

	// 添加自定义域名
	if req.CustomDomain != "" {
		dnsNames = append(dnsNames, req.CustomDomain)
	}

	// 解析公网地址
	if req.PublicAddress != "" {
		host := req.PublicAddress
		// 尝试分离 host:port
		if h, _, err := net.SplitHostPort(req.PublicAddress); err == nil {
			host = h
		}
		if ip := net.ParseIP(host); ip != nil {
			ipAddresses = append(ipAddresses, ip)
		} else {
			dnsNames = append(dnsNames, host)
		}
	}

	// 添加本地 IP
	ipAddresses = append(ipAddresses, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))

	// 4. 构建证书模板
	validity := req.Validity
	if validity == 0 {
		validity = 90 * 24 * time.Hour // 默认 90 天
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("edge_%s", req.EdgeID),
			Organization: []string{"Yat"},
			Country:      []string{"CN"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
	}

	// 5. 使用 Sub-CA 签发证书
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.subCACert, &privateKey.PublicKey, ca.subCAKey)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	// 6. 编码证书
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// 7. 编码私钥
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	// 8. 构建完整证书链
	subCACertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.subCACert.Raw,
	})
	rootCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.rootCert.Raw,
	})
	chainPEM := append(append(certPEM, subCACertPEM...), rootCertPEM...)

	logger.Infof("server certificate signed locally, edge_id: %s ,serial: %s, dns_names: %v, expires: %s", req.EdgeID, serialNumber.String(), dnsNames, template.NotAfter)

	return &ServerCertResult{
		CertPEM:      certPEM,
		KeyPEM:       keyPEM,
		ChainPEM:     chainPEM,
		SerialNumber: serialNumber.String(),
		ExpiresAt:    template.NotAfter,
	}, nil
}

// buildClientCertCN binds the certificate to its device identity.
func buildClientCertCN(deviceID string) string { return fmt.Sprintf("device_%s", deviceID) }
