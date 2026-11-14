package server

import (
	"net"

	fb "icool.io/yat/api/build/fb/golang/message"
)

func (p *Protocol) sendDomainCertificateResponse(conn net.Conn, sessionID string, seq uint32, requestErr error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.builder.Reset()
	errText := ""
	if requestErr != nil {
		errText = requestErr.Error()
	}
	errOffset := p.builder.CreateString(errText)
	fb.EdgeDomainCertificateResponseStart(p.builder)
	fb.EdgeDomainCertificateResponseAddSuccess(p.builder, requestErr == nil)
	fb.EdgeDomainCertificateResponseAddErrorMessage(p.builder, errOffset)
	body := fb.EdgeDomainCertificateResponseEnd(p.builder)
	sid := p.builder.CreateString(sessionID)
	fb.MessageHeaderStart(p.builder)
	fb.MessageHeaderAddType(p.builder, fb.MessageTypeEDGE_DOMAIN_CERTIFICATE_RESPONSE)
	fb.MessageHeaderAddSeq(p.builder, seq)
	fb.MessageHeaderAddSessionId(p.builder, sid)
	header := fb.MessageHeaderEnd(p.builder)
	fb.MessageStart(p.builder)
	fb.MessageAddHeader(p.builder, header)
	fb.MessageAddBodyType(p.builder, fb.MessageBodyEdgeDomainCertificateResponse)
	fb.MessageAddBody(p.builder, body)
	root := fb.MessageEnd(p.builder)
	p.builder.Finish(root)
	return p.writeMessageUnlocked(conn, p.builder.FinishedBytes())
}
