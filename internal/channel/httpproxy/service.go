package httpproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	fbMsg "icool.io/yat/api/build/fb/golang/message"
	logger "icool.io/yat/edge/pkg/log"
)

func (p *HTTPProxy) Type() fbMsg.ChannelType {
	return fbMsg.ChannelTypeHTTP
}

func (p *HTTPProxy) Start() error {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return nil
	}
	p.running = true

	httpAddr := p.addr
	httpsAddr := p.httpsAddr
	if httpsAddr == "" && p.httpsPort != 0 {
		httpsAddr = fmt.Sprintf(":%d", p.httpsPort)
	}
	tlsResolver := p.tlsCertResolver
	tlsALPNResolver := p.acmeTLSALPN01CertResolver

	p.httpServer = &http.Server{
		Addr:         httpAddr,
		Handler:      p,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	if p.httpsPort != 0 && tlsResolver != nil {
		p.httpsServer = &http.Server{
			Addr:         httpsAddr,
			Handler:      p,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 60 * time.Second,
			IdleTimeout:  120 * time.Second,
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				NextProtos: mergeTLSNextProtos(nil, "h2", "http/1.1", "acme-tls/1"),
				GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
					if hello == nil {
						return nil, fmt.Errorf("tls: missing client hello")
					}
					if tlsALPNResolver != nil {
						if cert, ok := tlsALPNResolver(hello); ok {
							return cert, nil
						}
					}
					// Reject IP-based SNI and empty SNI early to avoid
					// noisy "certificate not found" error logs from internet
					// background scanners hitting the HTTPS port.
					sni := strings.TrimSpace(hello.ServerName)
					if sni == "" {
						return nil, fmt.Errorf("tls: server name is required")
					}
					if net.ParseIP(sni) != nil {
						return nil, fmt.Errorf("tls: ip address not supported as server name")
					}
					return tlsResolver(sni)
				},
			},
		}
	}
	p.mu.Unlock()

	go func() {
		logger.Infof("HTTP proxy starting on %s", httpAddr)
		if err := p.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Errorf("HTTP proxy error: %v", err)
		}
	}()
	if p.httpsServer != nil {
		go func() {
			logger.Infof("HTTPS proxy starting on %s", httpsAddr)
			ln, err := net.Listen("tcp", httpsAddr)
			if err != nil {
				logger.Errorf("HTTPS proxy listen error: %v", err)
				return
			}
			tlsLn := tls.NewListener(ln, p.httpsServer.TLSConfig)
			if err := p.httpsServer.Serve(tlsLn); err != nil && err != http.ErrServerClosed {
				logger.Errorf("HTTPS proxy error: %v", err)
			}
		}()
	} else if p.httpsPort != 0 {
		logger.Warnf("HTTPS proxy disabled because TLS certificate resolver is not configured, port=%d", p.httpsPort)
	}

	return nil
}

func (p *HTTPProxy) Stop() error {
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return nil
	}
	p.running = false
	httpServer := p.httpServer
	httpsServer := p.httpsServer
	p.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if httpServer != nil {
		if err := httpServer.Shutdown(ctx); err != nil {
			logger.Errorf("HTTP proxy shutdown error: %v", err)
			return err
		}
	}
	if httpsServer != nil {
		if err := httpsServer.Shutdown(ctx); err != nil {
			logger.Errorf("HTTPS proxy shutdown error: %v", err)
			return err
		}
	}

	logger.Info("HTTP proxy stopped")
	return nil
}

func (p *HTTPProxy) SetACMEHTTP01Handler(handler http.Handler) {
	p.mu.Lock()
	p.acmeHTTP01Handler = handler
	p.mu.Unlock()
}

func (p *HTTPProxy) SetACMETLSALPN01CertResolver(resolver func(hello *tls.ClientHelloInfo) (*tls.Certificate, bool)) {
	p.mu.Lock()
	p.acmeTLSALPN01CertResolver = resolver
	p.mu.Unlock()
}

func (p *HTTPProxy) SetTLSCertificateResolver(resolver func(serverName string) (*tls.Certificate, error)) {
	p.mu.Lock()
	p.tlsCertResolver = resolver
	p.mu.Unlock()
}

func (p *HTTPProxy) SetHTTPSDomainRequestHandler(handler func(aliasDomain, assignedDomain string)) {
	p.mu.Lock()
	p.onHTTPSDomainRequest = handler
	p.mu.Unlock()
}

func mergeTLSNextProtos(base []string, extras ...string) []string {
	merged := make([]string, 0, len(base)+len(extras))
	seen := make(map[string]struct{}, len(base)+len(extras))
	for _, proto := range base {
		proto = strings.TrimSpace(proto)
		if proto == "" {
			continue
		}
		if _, ok := seen[proto]; ok {
			continue
		}
		seen[proto] = struct{}{}
		merged = append(merged, proto)
	}
	for _, proto := range extras {
		proto = strings.TrimSpace(proto)
		if proto == "" {
			continue
		}
		if _, ok := seen[proto]; ok {
			continue
		}
		seen[proto] = struct{}{}
		merged = append(merged, proto)
	}
	return merged
}
