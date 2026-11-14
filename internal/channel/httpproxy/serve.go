package httpproxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	fbMsg "icool.io/yat/api/build/fb/golang/message"
	ct "icool.io/yat/edge/internal/channel/types"
	logger "icool.io/yat/edge/pkg/log"
)

func (p *HTTPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
		p.mu.RLock()
		handler := p.acmeHTTP01Handler
		p.mu.RUnlock()
		if handler != nil {
			logger.Infof(
				"acme http-01 path dispatch, host=%s, path=%s, remote=%s",
				r.Host,
				r.URL.Path,
				r.RemoteAddr,
			)
			handler.ServeHTTP(w, r)
			return
		}
		logger.Warnf("acme http-01 path hit without handler, host=%s, path=%s, remote=%s", r.Host, r.URL.Path, r.RemoteAddr)
	}

	host := r.Host
	if idx := strings.Index(host, ":"); idx > 0 {
		host = host[:idx]
	}

	target := p.resolveTargetByAliasOrSubdomain(host)
	if target == nil {
		http.Error(w, "target not found: "+host, http.StatusBadGateway)
		return
	}
	if !isRequestSchemeAllowed(target, r.TLS != nil) {
		http.Error(w, buildSchemeErrorMessage(target, host, r), http.StatusBadRequest)
		logger.Infof(
			"HTTP_SCHEME_BLOCK|%s|%s|%s|%s|%v",
			target.ID,
			host,
			getScheme(r),
			r.URL.Path,
			target.Type,
		)
		return
	}

	target.IncrRequests()

	startTime := time.Now()
	statusWriter := &statusCaptureWriter{ResponseWriter: w}

	reqBytes, err := p.buildRawHTTPRequest(r)
	if err != nil {
		http.Error(statusWriter, "build request failed", http.StatusInternalServerError)
		target.IncrErrors()
		clientIP := getClientIP(r)
		logger.Infof("HTTP_ACCESS_LOG|%s|%s|%s|%s|%d|%d|%d",
			target.ID, r.Method, r.URL.Path, clientIP, 500, time.Since(startTime).Milliseconds(), len(reqBytes))
		return
	}

	target.AddBytesIn(uint64(len(reqBytes)))

	connectionID := uuid.New().String()

	hc := &httpConnection{
		connectionID: connectionID,
		channelID:    target.ID,
		sessionID:    target.SessionID,
		dataCh:       make(chan []byte, 100),
		finished:     make(chan struct{}),
		w:            statusWriter,
	}
	p.connections.Store(connectionID, hc)
	defer p.connections.Delete(connectionID)

	p.mu.RLock()
	tunnel := p.tunnel
	p.mu.RUnlock()

	if tunnel == nil {
		http.Error(statusWriter, "tunnel not ready", http.StatusServiceUnavailable)
		clientIP := getClientIP(r)
		logger.Infof("HTTP_ACCESS_LOG|%s|%s|%s|%s|%d|%d|%d",
			target.ID, r.Method, r.URL.Path, clientIP, 503, time.Since(startTime).Milliseconds(), len(reqBytes))
		return
	}

	err = tunnel.SendTCPData(target.SessionID, target.ID, connectionID, reqBytes, 0)
	if err != nil {
		http.Error(statusWriter, "forward failed", http.StatusBadGateway)
		target.IncrErrors()
		clientIP := getClientIP(r)
		logger.Infof("HTTP_ACCESS_LOG|%s|%s|%s|%s|%d|%d|%d",
			target.ID, r.Method, r.URL.Path, clientIP, 502, time.Since(startTime).Milliseconds(), len(reqBytes))
		return
	}

	closeFlags := uint8(0x01) // FIN by default
	if err := p.streamResponse(statusWriter, target, hc, r.Context()); err != nil {
		closeFlags = 0x02 // RST on canceled/abnormal response stream
		if err != context.Canceled {
			logger.Debugf("stream response error: %v", err)
		}
	}

	duration := time.Since(startTime)
	if err := tunnel.SendTCPData(target.SessionID, target.ID, connectionID, nil, closeFlags); err != nil {
		logger.Debugf("send HTTP close packet failed: conn=%s, flags=0x%02x, err=%v", connectionID, closeFlags, err)
	}

	clientIP := getClientIP(r)
	statusCode := statusWriter.statusCode
	if statusCode == 0 {
		statusCode = http.StatusOK
	}
	logger.Infof("HTTP_ACCESS_LOG|%s|%s|%s|%s|%d|%d|%d",
		target.ID, r.Method, r.URL.Path, clientIP, statusCode, duration.Milliseconds(), statusWriter.size)
}

func isRequestSchemeAllowed(target *ct.Channel, isTLS bool) bool {
	if target == nil {
		return true
	}
	switch target.Type {
	case fbMsg.ChannelTypeHTTP:
		return !isTLS
	case fbMsg.ChannelTypeHTTPS:
		return isTLS
	default:
		return true
	}
}

func expectedRequestScheme(target *ct.Channel) (string, bool) {
	if target == nil {
		return "", false
	}
	switch target.Type {
	case fbMsg.ChannelTypeHTTP:
		return "http", true
	case fbMsg.ChannelTypeHTTPS:
		return "https", true
	default:
		return "", false
	}
}

func requestPathWithQuery(r *http.Request) string {
	if r == nil || r.URL == nil {
		return "/"
	}
	path := r.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	if r.URL.RawQuery != "" {
		return path + "?" + r.URL.RawQuery
	}
	return path
}

func buildSchemeErrorMessage(target *ct.Channel, host string, r *http.Request) string {
	expectedScheme, ok := expectedRequestScheme(target)
	if !ok {
		return "scheme error"
	}

	host = strings.TrimSpace(host)
	if host == "" {
		host = "unknown-host"
	}
	currentScheme := getScheme(r)
	pathWithQuery := requestPathWithQuery(r)
	expectedURL := fmt.Sprintf("%s://%s%s", expectedScheme, host, pathWithQuery)
	currentURL := fmt.Sprintf("%s://%s%s", currentScheme, host, pathWithQuery)

	return fmt.Sprintf("scheme error: use %s (current request: %s)", expectedURL, currentURL)
}

func (p *HTTPProxy) resolveTargetByIDScopedDomain(host string) *ct.Channel {
	host = normalizeDomain(host)
	if host == "" {
		return nil
	}
	channelID, suffixDomain, ok := splitChannelScopedHost(host)
	if !ok {
		return nil
	}

	assignedDomain := p.getAssignedDomain()
	customDomain := p.getCustomDomain()

	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, target := range p.targets {
		if target == nil || target.ID != channelID {
			continue
		}
		switch {
		case assignedDomain != "" && suffixDomain == assignedDomain:
			return target
		case customDomain != "" && suffixDomain == customDomain:
			return target
		case normalizeDomain(target.AliasDomain) != "" && suffixDomain == normalizeDomain(target.AliasDomain):
			return target
		}
	}
	for _, target := range p.subdomainTargets {
		if target == nil || target.ID != channelID {
			continue
		}
		switch {
		case assignedDomain != "" && suffixDomain == assignedDomain:
			return target
		case customDomain != "" && suffixDomain == customDomain:
			return target
		case normalizeDomain(target.AliasDomain) != "" && suffixDomain == normalizeDomain(target.AliasDomain):
			return target
		}
	}
	return nil
}

func splitChannelScopedHost(host string) (channelID string, domainSuffix string, ok bool) {
	idx := strings.Index(host, ".")
	if idx <= 0 || idx >= len(host)-1 {
		return "", "", false
	}
	channelID = strings.TrimSpace(host[:idx])
	domainSuffix = strings.TrimSpace(host[idx+1:])
	if channelID == "" || domainSuffix == "" {
		return "", "", false
	}
	return channelID, domainSuffix, true
}

func (p *HTTPProxy) buildRawHTTPRequest(r *http.Request) ([]byte, error) {
	requestURI := r.RequestURI
	if requestURI == "" {
		requestURI = r.URL.EscapedPath()
		if r.URL.RawQuery != "" {
			requestURI += "?" + r.URL.RawQuery
		}
	}
	reqLine := fmt.Sprintf("%s %s HTTP/1.1\r\n", r.Method, requestURI)

	var bodyBytes []byte
	if r.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
	}

	headers := make(http.Header)
	for k, v := range r.Header {
		headers[k] = v
	}
	headers.Set("X-Real-IP", getClientIP(r))
	headers.Set("X-Forwarded-For", getClientIP(r))
	headers.Set("X-Forwarded-Proto", getScheme(r))

	if headers.Get("Host") == "" {
		headers.Set("Host", r.Host)
	}
	if len(bodyBytes) > 0 {
		headers.Set("Content-Length", fmt.Sprintf("%d", len(bodyBytes)))
	}

	var buf strings.Builder
	buf.WriteString(reqLine)
	for k, vv := range headers {
		for _, v := range vv {
			buf.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
		}
	}
	buf.WriteString("\r\n")

	reqBytes := []byte(buf.String())
	if len(bodyBytes) > 0 {
		reqBytes = append(reqBytes, bodyBytes...)
	}

	return reqBytes, nil
}

func (p *HTTPProxy) streamResponse(w http.ResponseWriter, target *ct.Channel, hc *httpConnection, ctx context.Context) error {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return p.streamResponseParsed(w, target, hc, ctx)
	}

	conn, bufrw, err := hijacker.Hijack()
	if err != nil {
		return p.streamResponseParsed(w, target, hc, ctx)
	}
	defer conn.Close()

	var capture *streamResponseCapture
	if statusWriter, ok := w.(*statusCaptureWriter); ok {
		capture = &streamResponseCapture{}
		defer capture.applyTo(statusWriter)
	}

	timeoutTimer := time.NewTimer(p.timeout)
	defer timeoutTimer.Stop()

	for {
		select {
		case data := <-hc.dataCh:
			if capture != nil {
				capture.consume(data)
			}
			if _, err := bufrw.Write(data); err != nil {
				return err
			}
			if err := bufrw.Flush(); err != nil {
				return err
			}
			target.AddBytesOut(uint64(len(data)))
			timeoutTimer.Reset(p.timeout)

		case <-hc.finished:
			for {
				select {
				case data := <-hc.dataCh:
					if capture != nil {
						capture.consume(data)
					}
					if _, err := bufrw.Write(data); err != nil {
						return err
					}
					if err := bufrw.Flush(); err != nil {
						return err
					}
					target.AddBytesOut(uint64(len(data)))
				default:
					return nil
				}
			}

		case <-timeoutTimer.C:
			target.IncrErrors()
			return fmt.Errorf("timeout")

		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (p *HTTPProxy) streamResponseParsed(w http.ResponseWriter, target *ct.Channel, hc *httpConnection, ctx context.Context) error {
	pr, pw := io.Pipe()

	go func() {
		defer pw.Close()
		timeoutTimer := time.NewTimer(p.timeout)
		defer timeoutTimer.Stop()

		for {
			select {
			case data := <-hc.dataCh:
				if _, err := pw.Write(data); err != nil {
					return
				}
				timeoutTimer.Reset(p.timeout)

			case <-hc.finished:
				for {
					select {
					case data := <-hc.dataCh:
						if _, err := pw.Write(data); err != nil {
							return
						}
					default:
						return
					}
				}

			case <-timeoutTimer.C:
				pw.CloseWithError(fmt.Errorf("timeout"))
				target.IncrErrors()
				return

			case <-ctx.Done():
				pw.CloseWithError(ctx.Err())
				return
			}
		}
	}()

	resp, err := http.ReadResponse(bufio.NewReader(pr), nil)
	if err != nil {
		pr.Close()
		http.Error(w, "bad gateway", http.StatusBadGateway)
		target.IncrErrors()
		return fmt.Errorf("parse response: %w", err)
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		keyLower := strings.ToLower(key)
		if keyLower == "transfer-encoding" || keyLower == "connection" {
			continue
		}
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}

	w.WriteHeader(resp.StatusCode)

	buf := make([]byte, 32*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				return writeErr
			}
			target.AddBytesOut(uint64(n))
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return nil
			}
			return readErr
		}
	}
}

func (p *HTTPProxy) writeRawResponse(w http.ResponseWriter, target *ct.Channel, rawResp []byte) error {
	if len(rawResp) == 0 {
		http.Error(w, "empty response", http.StatusBadGateway)
		target.IncrErrors()
		return fmt.Errorf("empty response")
	}

	headerEnd := strings.Index(string(rawResp), "\r\n\r\n")
	if headerEnd < 0 {
		http.Error(w, "invalid response", http.StatusBadGateway)
		target.IncrErrors()
		return fmt.Errorf("invalid response")
	}

	headerPart := string(rawResp[:headerEnd])
	body := rawResp[headerEnd+4:]

	lines := strings.Split(headerPart, "\r\n")
	if len(lines) < 1 {
		http.Error(w, "invalid response", http.StatusBadGateway)
		target.IncrErrors()
		return fmt.Errorf("invalid response")
	}

	statusLine := lines[0]
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 {
		http.Error(w, "invalid status line", http.StatusBadGateway)
		target.IncrErrors()
		return fmt.Errorf("invalid status line")
	}

	var statusCode int
	fmt.Sscanf(parts[1], "%d", &statusCode)
	if statusCode == 0 {
		statusCode = 200
	}

	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])
			if strings.ToLower(key) != "content-length" && strings.ToLower(key) != "transfer-encoding" {
				w.Header().Set(key, value)
			}
		}
	}

	w.WriteHeader(statusCode)
	if len(body) > 0 {
		w.Write(body)
		target.AddBytesOut(uint64(len(body)))
	}

	return nil
}

// statusCaptureWriter wraps ResponseWriter to capture status code and response size.
type statusCaptureWriter struct {
	http.ResponseWriter
	statusCode int
	size       int
}

func (w *statusCaptureWriter) WriteHeader(statusCode int) {
	if w.statusCode == 0 {
		w.statusCode = statusCode
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *statusCaptureWriter) Write(data []byte) (int, error) {
	n, err := w.ResponseWriter.Write(data)
	w.size += n
	return n, err
}

func (w *statusCaptureWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("ResponseWriter does not support hijacking")
	}
	return hijacker.Hijack()
}

// streamResponseCapture captures HTTP status code from raw stream data in hijack mode.
type streamResponseCapture struct {
	statusCode   int
	headerParsed bool
	headerBuffer []byte
	bodyBytes    int
	totalBytes   int
}

func (c *streamResponseCapture) consume(data []byte) {
	if len(data) == 0 {
		return
	}
	c.totalBytes += len(data)

	if c.headerParsed {
		c.bodyBytes += len(data)
		return
	}

	c.headerBuffer = append(c.headerBuffer, data...)

	if len(c.headerBuffer) > 64*1024 {
		if c.statusCode == 0 {
			c.statusCode = http.StatusOK
		}
		c.headerParsed = true
		c.bodyBytes += len(c.headerBuffer)
		c.headerBuffer = nil
		return
	}

	headerEnd := bytes.Index(c.headerBuffer, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return
	}

	c.statusCode = parseStatusCodeFromRawHeader(c.headerBuffer[:headerEnd])
	c.headerParsed = true

	bodyStart := headerEnd + 4
	if bodyStart < len(c.headerBuffer) {
		c.bodyBytes += len(c.headerBuffer[bodyStart:])
	}
	c.headerBuffer = nil
}

func (c *streamResponseCapture) applyTo(writer *statusCaptureWriter) {
	if c.statusCode > 0 {
		writer.statusCode = c.statusCode
	} else if writer.statusCode == 0 {
		writer.statusCode = http.StatusOK
	}
	if c.totalBytes > writer.size {
		writer.size = c.totalBytes
	}
}

func parseStatusCodeFromRawHeader(header []byte) int {
	if len(header) == 0 {
		return 0
	}
	firstLine := header
	if idx := bytes.Index(header, []byte("\r\n")); idx >= 0 {
		firstLine = header[:idx]
	}
	parts := strings.Fields(string(firstLine))
	if len(parts) < 2 {
		return 0
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0
	}
	return code
}

func getClientIP(r *http.Request) string {
	var candidates []string

	headerOrder := []string{
		"CF-Connecting-IP",
		"True-Client-IP",
		"X-Original-Forwarded-For",
		"X-Forwarded-For",
		"X-Real-IP",
		"Forwarded",
	}

	for _, key := range headerOrder {
		candidates = append(candidates, parseClientIPHeader(r.Header.Values(key))...)
	}

	remoteIP := extractIPFromRemoteAddr(r.RemoteAddr)
	if remoteIP != "" {
		candidates = append(candidates, remoteIP)
	}

	for _, candidate := range candidates {
		parsed := net.ParseIP(candidate)
		if parsed == nil {
			continue
		}
		if isPublicIP(parsed) {
			return candidate
		}
	}

	for _, candidate := range candidates {
		if net.ParseIP(candidate) != nil {
			return candidate
		}
	}

	return remoteIP
}

func parseClientIPHeader(values []string) []string {
	var result []string
	for _, rawValue := range values {
		if rawValue == "" {
			continue
		}
		for _, item := range strings.Split(rawValue, ",") {
			token := strings.TrimSpace(item)
			if token == "" {
				continue
			}

			lower := strings.ToLower(token)
			if strings.HasPrefix(lower, "for=") {
				token = strings.TrimSpace(token[4:])
				if idx := strings.Index(token, ";"); idx > 0 {
					token = token[:idx]
				}
			}

			token = strings.Trim(token, "\"")
			token = strings.Trim(token, "[]")

			if host, _, err := net.SplitHostPort(token); err == nil {
				token = host
			}

			parsed := net.ParseIP(token)
			if parsed == nil {
				continue
			}
			if ipv4 := parsed.To4(); ipv4 != nil {
				token = ipv4.String()
			} else {
				token = parsed.String()
			}
			result = append(result, token)
		}
	}
	return result
}

func extractIPFromRemoteAddr(remoteAddr string) string {
	if remoteAddr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		remoteAddr = host
	}
	remoteAddr = strings.Trim(remoteAddr, "[]")
	parsed := net.ParseIP(remoteAddr)
	if parsed == nil {
		return ""
	}
	if ipv4 := parsed.To4(); ipv4 != nil {
		return ipv4.String()
	}
	return parsed.String()
}

func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
	}
	if !ip.IsGlobalUnicast() {
		return false
	}
	return !ip.IsPrivate() &&
		!ip.IsLoopback() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() &&
		!ip.IsMulticast() &&
		!ip.IsUnspecified()
}

func getScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}
	return "http"
}
