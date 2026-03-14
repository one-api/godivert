package compile

import (
	"errors"

	"github.com/one-api/godivert/types"
)

type TokenKind int

// Token is a single lexical element in a filter string.
type Token struct {
	Kind TokenKind
	Pos  uint32    // Position in the filter string where the token starts
	Val  [4]uint32 // Value, used for TokenNumber (e.g., 4x32-bit for IPv6)
}

// TokenInfo maps a filter keyword string to its kind.
type TokenInfo struct {
	Name  string
	Kind  TokenKind
	Flags uint8
}

type Expr struct {
	// The C union is modeled by using both fields, with Kind determining usage.
	Val   [4]uint32 // Used for value nodes (leaf)
	Arg   [3]*Expr  // Used for operator nodes (internal)
	Kind  TokenKind // The TokenKind of the expression node (e.g., TokenAnd, TokenEq, TokenIPDstAddr)
	Count uint8     // Number of arguments/values used (0 to 3)
	Neg   bool      // True if expression is negated (!x)
	Succ  uint16
	Fail  uint16
}

func (kind *TokenKind) ToField() uint32 {
	switch *kind {
	case TokenZero:
		return types.FilterFieldZero
	case TokenEvent:
		return types.FilterFieldEvent
	case TokenRandom8:
		return types.FilterFieldRandom8
	case TokenRandom16:
		return types.FilterFieldRandom16
	case TokenRandom32:
		return types.FilterFieldRandom32
	case TokenPacket:
		return types.FilterFieldPacket
	case TokenPacket16:
		return types.FilterFieldPacket16
	case TokenPacket32:
		return types.FilterFieldPacket32
	case TokenLength:
		return types.FilterFieldLength
	case TokenTimestamp:
		return types.FilterFieldTimestamp
	case TokenTcpPayload:
		return types.FilterFieldTcpPayload
	case TokenTcpPayload16:
		return types.FilterFieldTcpPayload16
	case TokenTcpPayload32:
		return types.FilterFieldTcpPayload32
	case TokenUdpPayload:
		return types.FilterFieldUdpPayload
	case TokenUdpPayload16:
		return types.FilterFieldUdpPayload16
	case TokenUdpPayload32:
		return types.FilterFieldUdpPayload32
	case TokenOutbound:
		return types.FilterFieldOutbound
	case TokenInbound:
		return types.FilterFieldInbound
	case TokenFragment:
		return types.FilterFieldFragment
	case TokenIfIdx:
		return types.FilterFieldIfIdx
	case TokenSubIfIdx:
		return types.FilterFieldSubIfIdx
	case TokenLoopback:
		return types.FilterFieldLoopback
	case TokenImpostor:
		return types.FilterFieldImpostor
	case TokenProcessId:
		return types.FilterFieldProcessId
	case TokenLocalAddr:
		return types.FilterFieldLocalAddr
	case TokenRemoteAddr:
		return types.FilterFieldRemoteAddr
	case TokenLocalPort:
		return types.FilterFieldLocalPort
	case TokenRemotePort:
		return types.FilterFieldRemotePort
	case TokenProtocol:
		return types.FilterFieldProtocol
	case TokenEndpointId:
		return types.FilterFieldEndpointId
	case TokenParentEndpointId:
		return types.FilterFieldParentEndpointId
	case TokenLayer:
		return types.FilterFieldLayer
	case TokenPriority:
		return types.FilterFieldPriority
	case TokenIp:
		return types.FilterFieldIp
	case TokenIpv6:
		return types.FilterFieldIpv6
	case TokenIcmp:
		return types.FilterFieldIcmp
	case TokenIcmpV6:
		return types.FilterFieldIcmpv6
	case TokenTcp:
		return types.FilterFieldTcp
	case TokenUdp:
		return types.FilterFieldUdp
	case TokenIpHdrLength:
		return types.FilterFieldIpHdrLength
	case TokenIpTos:
		return types.FilterFieldIpTos
	case TokenIpLength:
		return types.FilterFieldIpLength
	case TokenIpId:
		return types.FilterFieldIpId
	case TokenIpDf:
		return types.FilterFieldIpDf
	case TokenIpMf:
		return types.FilterFieldIpMf
	case TokenIpFragOff:
		return types.FilterFieldIpFragOff
	case TokenIpTtl:
		return types.FilterFieldIpTtl
	case TokenIpProtocol:
		return types.FilterFieldIpProtocol
	case TokenIpChecksum:
		return types.FilterFieldIpChecksum
	case TokenIpSrcAddr:
		return types.FilterFieldIpSrcAddr
	case TokenIpDstAddr:
		return types.FilterFieldIpDstAddr
	case TokenIpv6TrafficClass:
		return types.FilterFieldIpv6TrafficClass
	case TokenIpv6FlowLabel:
		return types.FilterFieldIpv6FlowLabel
	case TokenIpv6Length:
		return types.FilterFieldIpv6Length
	case TokenIpv6NextHdr:
		return types.FilterFieldIpv6NextHdr
	case TokenIpv6HopLimit:
		return types.FilterFieldIpv6HopLimit
	case TokenIpv6SrcAddr:
		return types.FilterFieldIpv6SrcAddr
	case TokenIpv6DstAddr:
		return types.FilterFieldIpv6DstAddr
	case TokenIcmpType:
		return types.FilterFieldIcmpType
	case TokenIcmpCode:
		return types.FilterFieldIcmpCode
	case TokenIcmpChecksum:
		return types.FilterFieldIcmpChecksum
	case TokenIcmpBody:
		return types.FilterFieldIcmpBody
	case TokenIcmpV6Type:
		return types.FilterFieldIcmpv6Type
	case TokenIcmpV6Code:
		return types.FilterFieldIcmpv6Code
	case TokenIcmpV6Checksum:
		return types.FilterFieldIcmpv6Checksum
	case TokenIcmpV6Body:
		return types.FilterFieldIcmpv6Body
	case TokenTcpSrcPort:
		return types.FilterFieldTcpSrcPort
	case TokenTcpDstPort:
		return types.FilterFieldTcpDstPort
	case TokenTcpSeqNum:
		return types.FilterFieldTcpSeqNum
	case TokenTcpAckNum:
		return types.FilterFieldTcpAckNum
	case TokenTcpHdrLength:
		return types.FilterFieldTcpHdrLength
	case TokenTcpUrg:
		return types.FilterFieldTcpUrg
	case TokenTcpAck:
		return types.FilterFieldTcpAck
	case TokenTcpPsh:
		return types.FilterFieldTcpPsh
	case TokenTcpRst:
		return types.FilterFieldTcpRst
	case TokenTcpSyn:
		return types.FilterFieldTcpSyn
	case TokenTcpFin:
		return types.FilterFieldTcpFin
	case TokenTcpWindow:
		return types.FilterFieldTcpWindow
	case TokenTcpChecksum:
		return types.FilterFieldTcpChecksum
	case TokenTcpUrgPtr:
		return types.FilterFieldTcpUrgPtr
	case TokenTcpPayloadLength:
		return types.FilterFieldTcpPayloadLength
	case TokenUdpSrcPort:
		return types.FilterFieldUdpSrcPort
	case TokenUdpDstPort:
		return types.FilterFieldUdpDstPort
	case TokenUdpLength:
		return types.FilterFieldUdpLength
	case TokenUdpChecksum:
		return types.FilterFieldUdpChecksum
	case TokenUdpPayloadLength:
		return types.FilterFieldUdpPayloadLength
	default:
		return ^uint32(0) // UINT32_MAX
	}
}

var (
	ErrNoMemory         = errors.New("no memory")
	ErrTooDeep          = errors.New("too deep")
	ErrTooLong          = errors.New("too long")
	ErrBadToken         = errors.New("bad token")
	ErrBadTokenForLayer = errors.New("bad token for layer")
	ErrUnexpectedToken  = errors.New("unexpected token")
	ErrIndexOob         = errors.New("index out of bounds")
	ErrOutputTooShort   = errors.New("output too short")
	ErrBadObject        = errors.New("bad object")
	ErrAssertionFailed  = errors.New("assertion failed")
)
