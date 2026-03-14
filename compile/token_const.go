package compile

const (
	TokenIcmp TokenKind = iota
	TokenIcmpBody
	TokenIcmpChecksum
	TokenIcmpCode
	TokenIcmpType
	TokenIcmpV6
	TokenIcmpV6Body
	TokenIcmpV6Checksum
	TokenIcmpV6Code
	TokenIcmpV6Type
	TokenIp
	TokenIpChecksum
	TokenIpDf
	TokenIpDstAddr
	TokenIpFragOff
	TokenIpHdrLength
	TokenIpId
	TokenIpLength
	TokenIpMf
	TokenIpProtocol
	TokenIpSrcAddr
	TokenIpTos
	TokenIpTtl
	TokenIpv6
	TokenIpv6DstAddr
	TokenIpv6FlowLabel
	TokenIpv6HopLimit
	TokenIpv6Length
	TokenIpv6NextHdr
	TokenIpv6SrcAddr
	TokenIpv6TrafficClass
	TokenTcp
	TokenTcpAck
	TokenTcpAckNum
	TokenTcpChecksum
	TokenTcpDstPort
	TokenTcpFin
	TokenTcpHdrLength
	TokenTcpPayload
	TokenTcpPayload16
	TokenTcpPayload32
	TokenTcpPayloadLength
	TokenTcpPsh
	TokenTcpRst
	TokenTcpSeqNum
	TokenTcpSrcPort
	TokenTcpSyn
	TokenTcpUrg
	TokenTcpUrgPtr
	TokenTcpWindow
	TokenUdp
	TokenUdpChecksum
	TokenUdpDstPort
	TokenUdpLength
	TokenUdpPayload
	TokenUdpPayload16
	TokenUdpPayload32
	TokenUdpPayloadLength
	TokenUdpSrcPort
	TokenZero
	TokenEvent
	TokenRandom8
	TokenRandom16
	TokenRandom32
	TokenPacket
	TokenPacket16
	TokenPacket32
	TokenLength
	TokenTimestamp
	TokenTrue
	TokenFalse
	TokenInbound
	TokenOutbound
	TokenFragment
	TokenIfIdx
	TokenSubIfIdx
	TokenLoopback
	TokenImpostor
	TokenProcessId
	TokenLocalAddr
	TokenRemoteAddr
	TokenLocalPort
	TokenRemotePort
	TokenProtocol
	TokenEndpointId
	TokenParentEndpointId
	TokenLayer
	TokenPriority
	TokenFlow
	TokenSocket
	TokenNetwork
	TokenNetworkForward
	TokenReflect
	TokenEventPacket
	TokenEventEstablished
	TokenEventDeleted
	TokenEventBind
	TokenEventConnect
	TokenEventListen
	TokenEventAccept
	TokenEventOpen
	TokenEventClose
	TokenMacroTrue
	TokenMacroFalse
	TokenMacroTcp
	TokenMacroUdp
	TokenMacroIcmp
	TokenMacroIcmpV6
	TokenOpen
	TokenClose
	TokenSquareOpen
	TokenSquareClose
	TokenMinus
	TokenBytes
	TokenEq
	TokenNeq
	TokenLt
	TokenLeq
	TokenGt
	TokenGeq
	TokenNot
	TokenAnd
	TokenOr
	TokenColon
	TokenQuestion
	TokenNumber
	TokenEnd
)

var gTokenInfos = []TokenInfo{
	{"ACCEPT", TokenEventAccept, 0},
	{"BIND", TokenEventBind, 0},
	{"CLOSE", TokenEventClose, 0},
	{"CONNECT", TokenEventConnect, 0},
	{"DELETED", TokenEventDeleted, 0},
	{"ESTABLISHED", TokenEventEstablished, 0},
	{"FALSE", TokenMacroFalse, 0},
	{"FLOW", TokenFlow, 0},
	{"ICMP", TokenMacroIcmp, 0},
	{"ICMPV6", TokenMacroIcmpV6, 0},
	{"LISTEN", TokenEventListen, 0},
	{"NETWORK", TokenNetwork, 0},
	{"NETWORK_FORWARD", TokenNetworkForward, 0},
	{"OPEN", TokenEventOpen, 0},
	{"PACKET", TokenEventPacket, 0},
	{"REFLECT", TokenReflect, 0},
	{"SOCKET", TokenSocket, 0},
	{"TCP", TokenMacroTcp, 0},
	{"TRUE", TokenMacroTrue, 0},
	{"UDP", TokenMacroUdp, 0},
	{"and", TokenAnd, 0},
	{"endpointId", TokenEndpointId, 0},
	{"event", TokenEvent, 0},
	{"false", TokenFalse, 0},
	{"fragment", TokenFragment, 0},
	{"icmp", TokenIcmp, 0},
	{"icmp.Body", TokenIcmpBody, 0},
	{"icmp.Checksum", TokenIcmpChecksum, 0},
	{"icmp.Code", TokenIcmpCode, 0},
	{"icmp.Type", TokenIcmpType, 0},
	{"icmpv6", TokenIcmpV6, 0},
	{"icmpv6.Body", TokenIcmpV6Body, 0},
	{"icmpv6.Checksum", TokenIcmpV6Checksum, 0},
	{"icmpv6.Code", TokenIcmpV6Code, 0},
	{"icmpv6.Type", TokenIcmpV6Type, 0},
	{"ifIdx", TokenIfIdx, 0},
	{"impostor", TokenImpostor, 0},
	{"inbound", TokenInbound, 0},
	{"ip", TokenIp, 0},
	{"ip.Checksum", TokenIpChecksum, 0},
	{"ip.DF", TokenIpDf, 0},
	{"ip.DstAddr", TokenIpDstAddr, 0},
	{"ip.FragOff", TokenIpFragOff, 0},
	{"ip.HdrLength", TokenIpHdrLength, 0},
	{"ip.Id", TokenIpId, 0},
	{"ip.Length", TokenIpLength, 0},
	{"ip.MF", TokenIpMf, 0},
	{"ip.Protocol", TokenIpProtocol, 0},
	{"ip.SrcAddr", TokenIpSrcAddr, 0},
	{"ip.TOS", TokenIpTos, 0},
	{"ip.TTL", TokenIpTtl, 0},
	{"ipv6", TokenIpv6, 0},
	{"ipv6.DstAddr", TokenIpv6DstAddr, 0},
	{"ipv6.FlowLabel", TokenIpv6FlowLabel, 0},
	{"ipv6.HopLimit", TokenIpv6HopLimit, 0},
	{"ipv6.Length", TokenIpv6Length, 0},
	{"ipv6.NextHdr", TokenIpv6NextHdr, 0},
	{"ipv6.SrcAddr", TokenIpv6SrcAddr, 0},
	{"ipv6.TrafficClass", TokenIpv6TrafficClass, 0},
	{"layer", TokenLayer, 0},
	{"length", TokenLength, 0},
	{"localAddr", TokenLocalAddr, 0},
	{"localPort", TokenLocalPort, 0},
	{"loopback", TokenLoopback, 0},
	{"not", TokenNot, 0},
	{"or", TokenOr, 0},
	{"outbound", TokenOutbound, 0},
	{"packet", TokenPacket, 0},
	{"packet16", TokenPacket16, 0},
	{"packet32", TokenPacket32, 0},
	{"parentEndpointId", TokenParentEndpointId, 0},
	{"priority", TokenPriority, 0},
	{"processId", TokenProcessId, 0},
	{"protocol", TokenProtocol, 0},
	{"random16", TokenRandom16, 0},
	{"random32", TokenRandom32, 0},
	{"random8", TokenRandom8, 0},
	{"remoteAddr", TokenRemoteAddr, 0},
	{"remotePort", TokenRemotePort, 0},
	{"subIfIdx", TokenSubIfIdx, 0},
	{"tcp", TokenTcp, 0},
	{"tcp.Ack", TokenTcpAck, 0},
	{"tcp.AckNum", TokenTcpAckNum, 0},
	{"tcp.Checksum", TokenTcpChecksum, 0},
	{"tcp.DstPort", TokenTcpDstPort, 0},
	{"tcp.Fin", TokenTcpFin, 0},
	{"tcp.HdrLength", TokenTcpHdrLength, 0},
	{"tcp.Payload", TokenTcpPayload, 0},
	{"tcp.Payload16", TokenTcpPayload16, 0},
	{"tcp.Payload32", TokenTcpPayload32, 0},
	{"tcp.PayloadLength", TokenTcpPayloadLength, 0},
	{"tcp.Psh", TokenTcpPsh, 0},
	{"tcp.Rst", TokenTcpRst, 0},
	{"tcp.SeqNum", TokenTcpSeqNum, 0},
	{"tcp.SrcPort", TokenTcpSrcPort, 0},
	{"tcp.Syn", TokenTcpSyn, 0},
	{"tcp.Urg", TokenTcpUrg, 0},
	{"tcp.UrgPtr", TokenTcpUrgPtr, 0},
	{"tcp.Window", TokenTcpWindow, 0},
	{"timestamp", TokenTimestamp, 0},
	{"true", TokenTrue, 0},
	{"udp", TokenUdp, 0},
	{"udp.Checksum", TokenUdpChecksum, 0},
	{"udp.DstPort", TokenUdpDstPort, 0},
	{"udp.Length", TokenUdpLength, 0},
	{"udp.Payload", TokenUdpPayload, 0},
	{"udp.Payload16", TokenUdpPayload16, 0},
	{"udp.Payload32", TokenUdpPayload32, 0},
	{"udp.PayloadLength", TokenUdpPayloadLength, 0},
	{"udp.SrcPort", TokenUdpSrcPort, 0},
	{"zero", TokenZero, 0},
}
