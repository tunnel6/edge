package letsencrypt

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

func probeListenerTCP(ctx context.Context, listener net.Listener) error {
	candidates, err := listenerDialCandidates(listener)
	if err != nil {
		return err
	}

	var probeErrs []error
	for _, addr := range candidates {
		d := &net.Dialer{Timeout: 2 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			probeErrs = append(probeErrs, fmt.Errorf("%s: %w", addr, err))
			continue
		}
		_ = conn.Close()
		return nil
	}
	return joinErrors(probeErrs)
}

func probeTLSALPNListener(ctx context.Context, listener net.Listener, serverName string) error {
	candidates, err := listenerDialCandidates(listener)
	if err != nil {
		return err
	}

	var probeErrs []error
	for _, addr := range candidates {
		dialer := &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: 2 * time.Second},
			Config: &tls.Config{
				InsecureSkipVerify: true, // challenge precheck only
				ServerName:         serverName,
				MinVersion:         tls.VersionTLS12,
			},
		}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			probeErrs = append(probeErrs, fmt.Errorf("%s: %w", addr, err))
			continue
		}
		_ = conn.Close()
		return nil
	}
	return joinErrors(probeErrs)
}

func probeHTTP01Challenge(ctx context.Context, listener net.Listener, domain, challengePath, expectedBody string) error {
	domain = normalizeDomain(domain)
	challengePath = strings.TrimSpace(challengePath)
	expectedBody = strings.TrimSpace(expectedBody)
	if domain == "" {
		return fmt.Errorf("http-01 challenge domain is empty")
	}
	if challengePath == "" {
		return fmt.Errorf("http-01 challenge path is empty")
	}
	if expectedBody == "" {
		return fmt.Errorf("http-01 expected challenge body is empty")
	}
	candidates, err := listenerDialCandidates(listener)
	if err != nil {
		return err
	}

	var probeErrs []error
	for _, addr := range candidates {
		challengeURL := "http://" + addr + challengePath
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, challengeURL, nil)
		if err != nil {
			probeErrs = append(probeErrs, fmt.Errorf("%s: %w", addr, err))
			continue
		}
		// Keep domain routing semantics while probing local listener address.
		req.Host = domain

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			probeErrs = append(probeErrs, fmt.Errorf("%s: %w", addr, err))
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 8192))
		_ = resp.Body.Close()
		if readErr != nil {
			probeErrs = append(probeErrs, fmt.Errorf("%s: %w", addr, readErr))
			continue
		}
		if resp.StatusCode != http.StatusOK {
			probeErrs = append(probeErrs, fmt.Errorf("%s: unexpected status code: %d", addr, resp.StatusCode))
			continue
		}
		if strings.TrimSpace(string(body)) != expectedBody {
			probeErrs = append(probeErrs, fmt.Errorf("%s: unexpected challenge response body", addr))
			continue
		}
		return nil
	}
	return joinErrors(probeErrs)
}

func listenerDialCandidates(listener net.Listener) ([]string, error) {
	if listener == nil || listener.Addr() == nil {
		return nil, fmt.Errorf("listener address is unavailable")
	}

	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		return nil, fmt.Errorf("invalid listener address %q: %w", listener.Addr().String(), err)
	}

	host = strings.TrimSpace(host)
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		return []string{
			net.JoinHostPort("127.0.0.1", port),
			net.JoinHostPort("::1", port),
		}, nil
	}

	return []string{net.JoinHostPort(host, port)}, nil
}
