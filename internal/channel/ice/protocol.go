package ice

import (
	"sync"

	flatbuffers "github.com/google/flatbuffers/go"
	message "icool.io/yat/api/build/fb/golang/message"
)

type Protocol struct {
	builder *flatbuffers.Builder
	mu      sync.Mutex
}

func NewProtocol() *Protocol {
	return &Protocol{
		builder: flatbuffers.NewBuilder(512),
	}
}

func (p *Protocol) BuildICEStart(iceSessionID, tunnelID, token, pwd, udpAddr, udpAddrAlt string, gatherTimeoutMs uint32) []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.builder.Reset()

	iceIDOff := p.builder.CreateString(iceSessionID)
	tunnelOff := p.builder.CreateString(tunnelID)
	tokenOff := p.builder.CreateString(token)
	pwdOff := p.builder.CreateString(pwd)
	addrOff := p.builder.CreateString(udpAddr)
	altOff := p.builder.CreateString(udpAddrAlt)

	message.ICEStartStart(p.builder)
	message.ICEStartAddIceSessionId(p.builder, iceIDOff)
	message.ICEStartAddTunnelId(p.builder, tunnelOff)
	message.ICEStartAddToken(p.builder, tokenOff)
	message.ICEStartAddIcePwd(p.builder, pwdOff)
	message.ICEStartAddEdgeUdpAddr(p.builder, addrOff)
	message.ICEStartAddEdgeUdpAddrAlt(p.builder, altOff)
	message.ICEStartAddGatherTimeoutMs(p.builder, gatherTimeoutMs)
	body := message.ICEStartEnd(p.builder)

	return p.finishMessage(message.MessageTypeICE_START, message.MessageBodyICEStart, body)
}

func (p *Protocol) BuildICEPunch(iceSessionID, targetAddr, token, pwd string, attempts, intervalMs, startDelayMs uint32, extraTargets []string) []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.builder.Reset()

	iceIDOff := p.builder.CreateString(iceSessionID)
	addrOff := p.builder.CreateString(targetAddr)
	tokenOff := p.builder.CreateString(token)
	pwdOff := p.builder.CreateString(pwd)

	var extraOff flatbuffers.UOffsetT
	if len(extraTargets) > 0 {
		offsets := make([]flatbuffers.UOffsetT, len(extraTargets))
		for i, addr := range extraTargets {
			offsets[i] = p.builder.CreateString(addr)
		}
		message.ICEPunchStartExtraTargetAddrsVector(p.builder, len(offsets))
		for i := len(offsets) - 1; i >= 0; i-- {
			p.builder.PrependUOffsetT(offsets[i])
		}
		extraOff = p.builder.EndVector(len(offsets))
	}

	message.ICEPunchStart(p.builder)
	message.ICEPunchAddIceSessionId(p.builder, iceIDOff)
	message.ICEPunchAddTargetAddr(p.builder, addrOff)
	message.ICEPunchAddToken(p.builder, tokenOff)
	message.ICEPunchAddIcePwd(p.builder, pwdOff)
	message.ICEPunchAddAttempts(p.builder, attempts)
	message.ICEPunchAddIntervalMs(p.builder, intervalMs)
	message.ICEPunchAddStartDelayMs(p.builder, startDelayMs)
	if len(extraTargets) > 0 {
		message.ICEPunchAddExtraTargetAddrs(p.builder, extraOff)
	}
	body := message.ICEPunchEnd(p.builder)

	return p.finishMessage(message.MessageTypeICE_PUNCH, message.MessageBodyICEPunch, body)
}

func (p *Protocol) BuildICEQuicStart(iceSessionID string, role message.ICEQuicRole, peerAddr, alpn string, connectTimeoutMs uint32) []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.builder.Reset()

	iceIDOff := p.builder.CreateString(iceSessionID)
	addrOff := p.builder.CreateString(peerAddr)
	alpnOff := p.builder.CreateString(alpn)

	message.ICEQuicStartStart(p.builder)
	message.ICEQuicStartAddIceSessionId(p.builder, iceIDOff)
	message.ICEQuicStartAddRole(p.builder, role)
	message.ICEQuicStartAddPeerAddr(p.builder, addrOff)
	message.ICEQuicStartAddAlpn(p.builder, alpnOff)
	message.ICEQuicStartAddConnectTimeoutMs(p.builder, connectTimeoutMs)
	body := message.ICEQuicStartEnd(p.builder)

	return p.finishMessage(message.MessageTypeICE_QUIC_START, message.MessageBodyICEQuicStart, body)
}

func (p *Protocol) BuildICEStateChange(iceSessionID, tunnelID string, state State, strategy PunchStrategy, errMsg string) []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.builder.Reset()

	iceIDOff := p.builder.CreateString(iceSessionID)
	tunnelOff := p.builder.CreateString(tunnelID)
	stateOff := p.builder.CreateString(string(state))
	errOff := p.builder.CreateString(errMsg)

	message.ICEStateChangeStart(p.builder)
	message.ICEStateChangeAddIceSessionId(p.builder, iceIDOff)
	message.ICEStateChangeAddTunnelId(p.builder, tunnelOff)
	message.ICEStateChangeAddState(p.builder, stateOff)
	message.ICEStateChangeAddStrategy(p.builder, toFBStrategy(strategy))
	message.ICEStateChangeAddError(p.builder, errOff)
	body := message.ICEStateChangeEnd(p.builder)

	return p.finishMessage(message.MessageTypeICE_STATE, message.MessageBodyICEStateChange, body)
}

func (p *Protocol) finishMessage(msgType message.MessageType, bodyType message.MessageBody, bodyOffset flatbuffers.UOffsetT) []byte {
	message.MessageHeaderStart(p.builder)
	message.MessageHeaderAddType(p.builder, msgType)
	message.MessageHeaderAddSeq(p.builder, 0)
	message.MessageHeaderAddTimestamp(p.builder, 0)
	header := message.MessageHeaderEnd(p.builder)

	message.MessageStart(p.builder)
	message.MessageAddHeader(p.builder, header)
	message.MessageAddBodyType(p.builder, bodyType)
	message.MessageAddBody(p.builder, bodyOffset)
	msg := message.MessageEnd(p.builder)

	p.builder.Finish(msg)
	buf := p.builder.FinishedBytes()
	out := make([]byte, len(buf))
	copy(out, buf)
	return out
}

func toFBStrategy(s PunchStrategy) message.ICEPunchStrategy {
	switch s {
	case StrategyStandard:
		return message.ICEPunchStrategySTANDARD
	case StrategyPortPredict:
		return message.ICEPunchStrategyPORT_PREDICT
	case StrategyRelay:
		return message.ICEPunchStrategyRELAY
	default:
		return message.ICEPunchStrategySTANDARD
	}
}
