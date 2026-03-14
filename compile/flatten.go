package compile

import (
	"unsafe"

	"github.com/one-api/godivert/types"
)

func FlattenExpr(expr *Expr, label *int, succ, fail int, stack []*Expr) (flattened []*Expr, ipEP int) {
	if succ < 0 || fail < 0 {
		return nil, -1
	}

	switch expr.Kind {
	case TokenAnd:
		stack, succ = FlattenExpr(expr.Arg[1], label, succ, fail, stack)
		stack, succ = FlattenExpr(expr.Arg[0], label, succ, fail, stack)
		flattened = append(flattened, stack...)
		return flattened, succ
	case TokenOr:
		stack, fail = FlattenExpr(expr.Arg[1], label, succ, fail, stack)
		stack, fail = FlattenExpr(expr.Arg[0], label, succ, fail, stack)
		flattened = append(flattened, stack...)
		return flattened, fail
	case TokenQuestion:
		tmpStack, fail1 := FlattenExpr(expr.Arg[2], label, succ, fail, stack)
		tmpStack, succ1 := FlattenExpr(expr.Arg[1], label, succ, fail, tmpStack)
		tmpStack, succ = FlattenExpr(expr.Arg[0], label, succ1, fail1, tmpStack)
		flattened = append(flattened, tmpStack...)
		return flattened, succ
	default:

		SimplifyTest(expr)

		// optimize for TokenTrue, TokenFalse is being simplified in SimplifyTest
		if expr.Kind == TokenEq && expr.Arg[0].Kind == TokenTrue {
			if expr.Arg[1].Val[0] != 0 {
				return stack, succ
			} else {
				return stack, fail
			}
		}

		if *label >= filterMaxLen {
			return nil, -1
		}
		//stack[*label] = expr
		stack = append(stack, expr)
		expr.Succ = uint16(succ)
		expr.Fail = uint16(fail)
		ret := *label
		*label = *label + 1
		return stack, ret
	}
}

func SimplifyTest(test *Expr) {

	varExpr := test.Arg[0]
	val := test.Arg[1]

	var (
		negLb = false
		negUb = false
		neg   = false
	)

	var lb [4]uint32
	var ub [4]uint32

	resultLb := 0
	resultUb := 0
	eq := false
	result := false
	typ := TokenTrue

	switch varExpr.Kind {
	case TokenZero, TokenFalse:
		eq = true
		lb[0], ub[0] = 0, 0
	case TokenTrue:
		eq = true
		lb[0], ub[0] = 1, 1
	case TokenLayer:
		lb[0], ub[0] = 0, uint32(types.LayerMax)
	case TokenPriority:
		negLb = true
		lb[0], ub[0] = types.PriorityMax, types.PriorityMax
	case TokenEvent:
		lb[0], ub[0] = 0, uint32(types.EventMax)
	case TokenIpDf, TokenIpMf:
		typ = TokenIp
		lb[0], ub[0] = 0, 1
	case TokenTcpUrg, TokenTcpAck, TokenTcpPsh, TokenTcpRst, TokenTcpSyn, TokenTcpFin:
		typ = TokenTcp
		lb[0], ub[0] = 0, 1
	case TokenInbound, TokenOutbound, TokenFragment, TokenIp, TokenIpv6, TokenIcmp, TokenIcmpV6, TokenTcp, TokenUdp:
		lb[0], ub[0] = 0, 1
	case TokenIpHdrLength:
		typ = TokenIp
		lb[0], ub[0] = 0, 0x0F
	case TokenTcpHdrLength:
		typ = TokenTcp
		lb[0], ub[0] = 0, 0x0F
	case TokenIpTtl, TokenIpProtocol:
		typ = TokenIp
		lb[0], ub[0] = 0, 0xFF
	case TokenIpv6TrafficClass, TokenIpv6NextHdr, TokenIpv6HopLimit:
		typ = TokenIpv6
		lb[0], ub[0] = 0, 0xFF
	case TokenIcmpType, TokenIcmpCode:
		typ = TokenIcmp
		lb[0], ub[0] = 0, 0xFF
	case TokenIcmpV6Type, TokenIcmpV6Code:
		typ = TokenIcmpV6
		lb[0], ub[0] = 0, 0xFF
	case TokenTcpPayload:
		typ = TokenTcp
		lb[0], ub[0] = 0, 0xFF
	case TokenUdpPayload:
		typ = TokenUdp
		lb[0], ub[0] = 0, 0xFF
	case TokenProtocol, TokenPacket, TokenRandom8:
		lb[0], ub[0] = 0, 0xFF
	case TokenIpFragOff:
		typ = TokenIp
		lb[0], ub[0] = 0, 0x1FFF
	case TokenIpTos, TokenIpLength, TokenIpId, TokenIpChecksum:
		typ = TokenIp
		lb[0], ub[0] = 0, 0xFFFF
	case TokenIpv6Length:
		typ = TokenIpv6
		lb[0], ub[0] = 0, 0xFFFF
	case TokenIcmpChecksum:
		typ = TokenIcmp
		lb[0], ub[0] = 0, 0xFFFF
	case TokenIcmpV6Checksum:
		typ = TokenIcmpV6
		lb[0], ub[0] = 0, 0xFFFF
	case TokenTcpSrcPort, TokenTcpDstPort, TokenTcpWindow, TokenTcpChecksum, TokenTcpUrgPtr, TokenTcpPayloadLength, TokenTcpPayload16:
		typ = TokenTcp
		lb[0], ub[0] = 0, 0xFFFF
	case TokenUdpSrcPort, TokenUdpDstPort, TokenUdpLength, TokenUdpChecksum, TokenUdpPayloadLength, TokenUdpPayload16:
		typ = TokenUdp
		lb[0], ub[0] = 0, 0xFFFF
	case TokenLocalPort, TokenRemotePort, TokenPacket16, TokenRandom16:
		lb[0], ub[0] = 0, 0xFFFF
	case TokenLength:
		lb[0] = uint32(unsafe.Sizeof(types.IPHdr{}))
		ub[0] = types.MtuMax
	case TokenIpv6FlowLabel:
		typ = TokenIpv6
		lb[0], ub[0] = 0, 0x000FFFFF
	case TokenIpSrcAddr, TokenIpDstAddr:
		typ = TokenIp
		lb[0], lb[1] = 0, 0xFFFF
		ub[0], ub[1] = 0xFFFFFFFF, 0xFFFF
	case TokenIpv6SrcAddr, TokenIpv6DstAddr:
		typ = TokenIpv6
		// fallthrough to local/remote addr
		fallthrough
	case TokenLocalAddr, TokenRemoteAddr:
		lb[0], lb[1], lb[2], lb[3] = 0, 0, 0, 0
		ub[0], ub[1], ub[2], ub[3] = 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
	case TokenTimestamp:
		lb[0], lb[1] = 0, 0x80000000
		ub[0], ub[1] = 0xFFFFFFFF, 0x7FFFFFFF
		negLb = true
	case TokenTcpPayload32:
		typ = TokenTcp
		lb[0], ub[0] = 0, 0xFFFFFFFF
	case TokenUdpPayload32:
		typ = TokenUdp
		lb[0], ub[0] = 0, 0xFFFFFFFF
	case TokenIfIdx, TokenSubIfIdx, TokenRandom32, TokenProcessId:
		lb[0], ub[0] = 0, 0xFFFFFFFF
	case TokenEndpointId, TokenParentEndpointId:
		lb[0], lb[1] = 0, 0
		ub[0], ub[1] = 0xFFFFFFFF, 0xFFFFFFFF
	default:
		return
	}

	neg = val.Neg
	resultLb = compare128(neg, val.Val, negLb, lb, true)
	resultUb = compare128(neg, val.Val, negUb, ub, true)

	switch test.Kind {
	case TokenEq:
		if resultLb < 0 || resultUb > 0 {
			result = false
			break
		}
		if eq && resultLb == 0 {
			result = true
			break
		}
		return
	case TokenNeq:
		if resultLb < 0 || resultUb > 0 {
			result = true
			break
		}
		if eq && resultLb == 0 {
			result = false
			break
		}
		return
	case TokenLt:
		if resultUb > 0 {
			result = true
			break
		}
		if resultLb <= 0 {
			result = false
			break
		}
		return
	case TokenLeq:
		if resultUb >= 0 {
			result = true
			break
		}
		if resultLb < 0 {
			result = false
			break
		}
		return
	case TokenGt:
		if resultUb >= 0 {
			result = false
			break
		}
		if resultLb < 0 {
			result = true
			break
		}
		return
	case TokenGeq:
		if resultUb > 0 {
			result = false
			break
		}
		if resultLb <= 0 {
			result = true
			break
		}
		return
	default:
		return
	}

	arg0, err := makeVar(typ)
	if err != nil {
		return
	}
	var arg1 Expr
	if result {
		arg1 = makeOne()
	} else {
		arg1 = makeZero()
	}

	test.Arg[0] = &arg0
	test.Arg[1] = &arg1
	test.Kind = TokenEq
}

func compare128(negA bool, a [4]uint32, negB bool, b [4]uint32, big bool) int {
	var neg int
	if negA && !negB {
		return -1
	}
	if !negA && negB {
		return 1
	}
	if negA {
		neg = -1
	} else {
		neg = 1
	}

	if big {
		if a[3] < b[3] {
			return -neg
		}
		if a[3] > b[3] {
			return neg
		}
		if a[2] < b[2] {
			return -neg
		}
		if a[2] > b[2] {
			return neg
		}
		if a[1] < b[1] {
			return -neg
		}
		if a[1] > b[1] {
			return neg
		}
	}
	if a[0] < b[0] {
		return -neg
	}
	if a[0] > b[0] {
		return neg
	}
	return 0
}

func ValidateField(layer types.Layer, field uint32) bool {
	if field > types.FilterFieldMax {
		return false
	}

	const (
		LNetwork        = 1 << types.LayerNetwork
		LNetworkForward = 1 << types.LayerNetworkForward
		LFlow           = 1 << types.LayerFlow
		LSocket         = 1 << types.LayerSocket
		LReflect        = 1 << types.LayerReflect
	)
	const (
		LNMFSR = LNetwork | LNetworkForward | LFlow | LSocket | LReflect
		LNMFS_ = LNetwork | LNetworkForward | LFlow | LSocket
		L__F_R = LFlow | LReflect
		LN_FS_ = LNetwork | LFlow | LSocket
		L__FS_ = LFlow | LSocket
		L___SR = LSocket | LReflect
		L__FSR = LFlow | LSocket | LReflect
		LNM___ = LNetwork | LNetworkForward
		L__F__ = LFlow
		L___S_ = LSocket
		L____R = LReflect
	)

	var flags = []int{
		LNMFSR, /* FILTER_FIELD_ZERO */
		LN_FS_, /* FILTER_FIELD_INBOUND */
		LN_FS_, /* FILTER_FIELD_OUTBOUND */
		LNM___, /* FILTER_FIELD_IFIDX */
		LNM___, /* FILTER_FIELD_SUBIFIDX */
		LNMFS_, /* FILTER_FIELD_IP */
		LNMFS_, /* FILTER_FIELD_IPV6 */
		LNMFS_, /* FILTER_FIELD_ICMP */
		LNMFS_, /* FILTER_FIELD_TCP */
		LNMFS_, /* FILTER_FIELD_UDP */
		LNMFS_, /* FILTER_FIELD_ICMPV6 */
		LNM___, /* FILTER_FIELD_IP_HDRLENGTH */
		LNM___, /* FILTER_FIELD_IP_TOS */
		LNM___, /* FILTER_FIELD_IP_LENGTH */
		LNM___, /* FILTER_FIELD_IP_ID */
		LNM___, /* FILTER_FIELD_IP_DF */
		LNM___, /* FILTER_FIELD_IP_MF */
		LNM___, /* FILTER_FIELD_IP_FRAGOFF */
		LNM___, /* FILTER_FIELD_IP_TTL */
		LNM___, /* FILTER_FIELD_IP_PROTOCOL */
		LNM___, /* FILTER_FIELD_IP_CHECKSUM */
		LNM___, /* FILTER_FIELD_IP_SRCADDR */
		LNM___, /* FILTER_FIELD_IP_DSTADDR */
		LNM___, /* FILTER_FIELD_IPV6_TRAFFICCLASS */
		LNM___, /* FILTER_FIELD_IPV6_FLOWLABEL */
		LNM___, /* FILTER_FIELD_IPV6_LENGTH */
		LNM___, /* FILTER_FIELD_IPV6_NEXTHDR */
		LNM___, /* FILTER_FIELD_IPV6_HOPLIMIT */
		LNM___, /* FILTER_FIELD_IPV6_SRCADDR */
		LNM___, /* FILTER_FIELD_IPV6_DSTADDR */
		LNM___, /* FILTER_FIELD_ICMP_TYPE */
		LNM___, /* FILTER_FIELD_ICMP_CODE */
		LNM___, /* FILTER_FIELD_ICMP_CHECKSUM */
		LNM___, /* FILTER_FIELD_ICMP_BODY */
		LNM___, /* FILTER_FIELD_ICMPV6_TYPE */
		LNM___, /* FILTER_FIELD_ICMPV6_CODE */
		LNM___, /* FILTER_FIELD_ICMPV6_CHECKSUM */
		LNM___, /* FILTER_FIELD_ICMPV6_BODY */
		LNM___, /* FILTER_FIELD_TCP_SRCPORT */
		LNM___, /* FILTER_FIELD_TCP_DSTPORT */
		LNM___, /* FILTER_FIELD_TCP_SEQNUM */
		LNM___, /* FILTER_FIELD_TCP_ACKNUM */
		LNM___, /* FILTER_FIELD_TCP_HDRLENGTH */
		LNM___, /* FILTER_FIELD_TCP_URG */
		LNM___, /* FILTER_FIELD_TCP_ACK */
		LNM___, /* FILTER_FIELD_TCP_PSH */
		LNM___, /* FILTER_FIELD_TCP_RST */
		LNM___, /* FILTER_FIELD_TCP_SYN */
		LNM___, /* FILTER_FIELD_TCP_FIN */
		LNM___, /* FILTER_FIELD_TCP_WINDOW */
		LNM___, /* FILTER_FIELD_TCP_CHECKSUM */
		LNM___, /* FILTER_FIELD_TCP_URGPTR */
		LNM___, /* FILTER_FIELD_TCP_PAYLOADLENGTH */
		LNM___, /* FILTER_FIELD_UDP_SRCPORT */
		LNM___, /* FILTER_FIELD_UDP_DSTPORT */
		LNM___, /* FILTER_FIELD_UDP_LENGTH */
		LNM___, /* FILTER_FIELD_UDP_CHECKSUM */
		LNM___, /* FILTER_FIELD_UDP_PAYLOADLENGTH */
		LN_FS_, /* FILTER_FIELD_LOOPBACK */
		LNM___, /* FILTER_FIELD_IMPOSTOR */
		L__FSR, /* FILTER_FIELD_PROCESSID */
		LN_FS_, /* FILTER_FIELD_LOCALADDR */
		LN_FS_, /* FILTER_FIELD_REMOTEADDR */
		LN_FS_, /* FILTER_FIELD_LOCALPORT */
		LN_FS_, /* FILTER_FIELD_REMOTEPORT */
		LN_FS_, /* FILTER_FIELD_PROTOCOL */
		L__FS_, /* FILTER_FIELD_ENDPOINTID */
		L__FS_, /* FILTER_FIELD_PARENTENDPOINTID */
		L____R, /* FILTER_FIELD_LAYER */
		L____R, /* FILTER_FIELD_PRIORITY */
		LNMFSR, /* FILTER_FIELD_EVENT */
		LNM___, /* FILTER_FIELD_PACKET */
		LNM___, /* FILTER_FIELD_PACKET16 */
		LNM___, /* FILTER_FIELD_PACKET32 */
		LNM___, /* FILTER_FIELD_TCP_PAYLOAD */
		LNM___, /* FILTER_FIELD_TCP_PAYLOAD16 */
		LNM___, /* FILTER_FIELD_TCP_PAYLOAD32 */
		LNM___, /* FILTER_FIELD_UDP_PAYLOAD */
		LNM___, /* FILTER_FIELD_UDP_PAYLOAD16 */
		LNM___, /* FILTER_FIELD_UDP_PAYLOAD32 */
		LNM___, /* FILTER_FIELD_LENGTH */
		LNMFSR, /* FILTER_FIELD_TIMESTAMP */
		LNM___, /* FILTER_FIELD_RANDOM8 */
		LNM___, /* FILTER_FIELD_RANDOM16 */
		LNM___, /* FILTER_FIELD_RANDOM32 */
		LNM___, /* FILTER_FIELD_FRAGMENT */
	}

	return (flags[field] & (1 << layer)) != 0
}
