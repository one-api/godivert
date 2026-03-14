package compile

import (
	"fmt"
	"math"

	"github.com/one-api/godivert/types"
)

func ParseFilter(tokens []Token, i *int, depth uint32, and bool) (*Expr, error) {
	if depth == 0 {
		return nil, fmt.Errorf("%w at %d", ErrTooDeep, tokens[*i].Pos)
	}
	depth--

	var expr *Expr
	var err error

	if and {
		expr, err = ParseAndOrArg(tokens, i, depth)
	} else {
		expr, err = ParseFilter(tokens, i, depth, true)
	}
	if expr == nil {
		return nil, err
	}

	for {

		switch tokens[*i].Kind {
		case TokenAnd:
			*i = *i + 1
			arg, err := ParseAndOrArg(tokens, i, depth)
			if arg == nil {
				return nil, err
			}
			exprAnd := makeBinOp(TokenAnd, expr, arg)
			expr = &exprAnd
			continue
		case TokenOr:
			*i = *i + 1
			arg, err := ParseFilter(tokens, i, depth, true)
			if arg == nil {
				return nil, err
			}
			exprOr := makeBinOp(TokenOr, expr, arg)
			expr = &exprOr
			continue
		default:
			return expr, nil
		}
	}
}

func ParseAndOrArg(tokens []Token, i *int, depth uint32) (*Expr, error) {
	// check depth
	if depth == 0 {
		return nil, fmt.Errorf("%w at %d", ErrTooDeep, tokens[*i].Pos)
	}
	depth--

	switch tokens[*i].Kind {
	case TokenOpen:
		// consume '('
		*i = *i + 1

		// parse inner filter
		expr, err := ParseFilter(tokens, i, depth, false)
		if expr == nil {
			return nil, err
		}

		// if next is ')', return the sub-expression
		if tokens[*i].Kind == TokenClose {
			*i = *i + 1
			return expr, nil
		}

		// ternary: ? then : else
		if tokens[*i].Kind == TokenQuestion {
			*i = *i + 1

			th, perr := ParseFilter(tokens, i, depth, false)
			if th == nil {
				return nil, perr
			}

			if tokens[*i].Kind != TokenColon {
				return nil, fmt.Errorf("%w at %d", ErrUnexpectedToken, tokens[*i].Pos)
			}
			*i = *i + 1

			el, perr := ParseFilter(tokens, i, depth, false)
			if el == nil {
				return nil, perr
			}

			if tokens[*i].Kind != TokenClose {
				return nil, fmt.Errorf("%w at %d", ErrUnexpectedToken, tokens[*i].Pos)
			}
			*i = *i + 1

			res := makeIfThenElse(expr, th, el)
			return &res, nil
		}

		// unexpected token after '(' ... return error
		return nil, fmt.Errorf("%w at %d", ErrUnexpectedToken, tokens[*i].Pos)

	default:
		// default falls back to ParseTest
		return ParseTest(tokens, i)
	}
}

// ParseTest parses a filter test.
func ParseTest(tokens []Token, i *int) (*Expr, error) {
	// handle leading NOTs
	not := false
	for tokens[*i].Kind == TokenNot {
		not = !not
		*i = *i + 1
	}

	var variable Expr
	var kind TokenKind

	// handle variable / array forms
	switch tokens[*i].Kind {

	case TokenTimestamp, TokenPriority, TokenZero, TokenEvent, TokenRandom8, TokenRandom16, TokenRandom32,
		TokenTrue, TokenFalse, TokenOutbound, TokenInbound, TokenFragment, TokenIfIdx, TokenSubIfIdx,
		TokenLoopback, TokenImpostor, TokenIp, TokenIpv6, TokenIcmp, TokenIcmpV6, TokenTcp, TokenUdp,
		TokenProcessId, TokenLocalAddr, TokenRemoteAddr, TokenLocalPort, TokenRemotePort, TokenProtocol,
		TokenEndpointId, TokenParentEndpointId, TokenLength, TokenLayer, TokenIpHdrLength, TokenIpTos,
		TokenIpLength, TokenIpId, TokenIpDf, TokenIpMf, TokenIpFragOff, TokenIpTtl, TokenIpProtocol,
		TokenIpChecksum, TokenIpSrcAddr, TokenIpDstAddr, TokenIpv6TrafficClass, TokenIpv6FlowLabel,
		TokenIpv6Length, TokenIpv6NextHdr, TokenIpv6HopLimit, TokenIpv6SrcAddr, TokenIpv6DstAddr,
		TokenIcmpType, TokenIcmpCode, TokenIcmpChecksum, TokenIcmpBody, TokenIcmpV6Type, TokenIcmpV6Code,
		TokenIcmpV6Checksum, TokenIcmpV6Body, TokenTcpSrcPort, TokenTcpDstPort, TokenTcpSeqNum,
		TokenTcpAckNum, TokenTcpHdrLength, TokenTcpUrg, TokenTcpAck, TokenTcpPsh, TokenTcpRst, TokenTcpSyn,
		TokenTcpFin, TokenTcpWindow, TokenTcpChecksum, TokenTcpUrgPtr, TokenTcpPayloadLength,
		TokenUdpSrcPort, TokenUdpDstPort, TokenUdpLength, TokenUdpChecksum, TokenUdpPayloadLength:

		var err error
		variable, err = makeVar(tokens[*i].Kind)
		if err != nil {
			return nil, err
		}
		*i = *i + 1

	default:
		var size uint32
		// array-like tokens: handle sizes then common array logic
		switch tokens[*i].Kind {
		case TokenPacket, TokenTcpPayload, TokenUdpPayload:
			size = 1
		case TokenPacket16, TokenTcpPayload16, TokenUdpPayload16:
			size = 2
		case TokenPacket32, TokenTcpPayload32, TokenUdpPayload32:
			size = 4
		default:
			return nil, fmt.Errorf("%w at %d", ErrUnexpectedToken, tokens[*i].Pos)
		}
		size = 4

		kind = tokens[*i].Kind
		*i = *i + 1

		// require '['
		if tokens[*i].Kind != TokenSquareOpen {
			return nil, fmt.Errorf("%w at %d", ErrUnexpectedToken, tokens[*i].Pos)
		}
		*i = *i + 1

		neg := false
		if tokens[*i].Kind == TokenMinus {
			neg = true
			*i = *i + 1
		}

		if tokens[*i].Kind != TokenNumber {
			return nil, fmt.Errorf("%w at %d", ErrUnexpectedToken, tokens[*i].Pos)
		}

		valArr := tokens[*i].Val
		if valArr[3] != 0 || valArr[2] != 0 || valArr[1] != 0 || valArr[0] > types.MtuMax {
			return nil, fmt.Errorf("%w at %d", ErrIndexOob, tokens[*i].Pos)
		}

		idx := valArr[0]
		*i = *i + 1

		// if followed by "bytes" token, do not scale by element size
		if tokens[*i].Kind == TokenBytes {
			*i = *i + 1
		} else {
			idx = idx * size
		}

		if (!neg && idx > math.MaxUint16-uint32(size)) ||
			(neg && idx > math.MaxUint16) || (neg && idx < size) {
			return nil, fmt.Errorf("%w at %d", ErrIndexOob, tokens[*i].Pos)
		}

		// apply neg
		varIndex := int(idx)
		if neg {
			varIndex = -varIndex
		}
		variable = makeArrayVar(kind, varIndex)

		if tokens[*i].Kind != TokenSquareClose {
			return nil, fmt.Errorf("%w at %d", ErrUnexpectedToken, tokens[*i].Pos)
		}
		*i = *i + 1

	}

	// parse operator
	switch tokens[*i].Kind {
	case TokenEq, TokenNeq, TokenLt, TokenLeq, TokenGt, TokenGeq:
		kind = tokens[*i].Kind
	default:
		if not {
			exprZero := makeZero()
			e := makeBinOp(TokenEq, &variable, &exprZero)
			return &e, nil
		} else {
			exprZero := makeZero()
			e := makeBinOp(TokenNeq, &variable, &exprZero)
			return &e, nil
		}
	}

	// if we saw a leading not, invert the comparison operator
	if not {
		switch kind {
		case TokenEq:
			kind = TokenNeq
		case TokenNeq:
			kind = TokenEq
		case TokenLt:
			kind = TokenGeq
		case TokenLeq:
			kind = TokenGt
		case TokenGt:
			kind = TokenLeq
		case TokenGeq:
			kind = TokenLt
		default:
		}
	}

	// consume operator
	*i = *i + 1

	// optional unary minus for the number
	negNum := false
	if tokens[*i].Kind == TokenMinus {
		negNum = true
		*i = *i + 1
	}

	if tokens[*i].Kind != TokenNumber {
		return nil, fmt.Errorf("%w at %d", ErrUnexpectedToken, tokens[*i].Pos)
	}

	// create numeric literal
	valExpr := makeNumber(tokens[*i].Val)
	valExpr.Neg = negNum

	*i = *i + 1

	// construct binary op
	e := makeBinOp(kind, &variable, &valExpr)
	return &e, nil
}

func makeVar(kind TokenKind) (Expr, error) {
	// NOTE: must be in order
	var vars = []Expr{
		{Kind: TokenIcmp},
		{Kind: TokenIcmpBody},
		{Kind: TokenIcmpChecksum},
		{Kind: TokenIcmpCode},
		{Kind: TokenIcmpType},
		{Kind: TokenIcmpV6},
		{Kind: TokenIcmpV6Body},
		{Kind: TokenIcmpV6Checksum},
		{Kind: TokenIcmpV6Code},
		{Kind: TokenIcmpV6Type},
		{Kind: TokenIp},
		{Kind: TokenIpChecksum},
		{Kind: TokenIpDf},
		{Kind: TokenIpDstAddr},
		{Kind: TokenIpFragOff},
		{Kind: TokenIpHdrLength},
		{Kind: TokenIpId},
		{Kind: TokenIpLength},
		{Kind: TokenIpMf},
		{Kind: TokenIpProtocol},
		{Kind: TokenIpSrcAddr},
		{Kind: TokenIpTos},
		{Kind: TokenIpTtl},
		{Kind: TokenIpv6},
		{Kind: TokenIpv6DstAddr},
		{Kind: TokenIpv6FlowLabel},
		{Kind: TokenIpv6HopLimit},
		{Kind: TokenIpv6Length},
		{Kind: TokenIpv6NextHdr},
		{Kind: TokenIpv6SrcAddr},
		{Kind: TokenIpv6TrafficClass},
		{Kind: TokenTcp},
		{Kind: TokenTcpAck},
		{Kind: TokenTcpAckNum},
		{Kind: TokenTcpChecksum},
		{Kind: TokenTcpDstPort},
		{Kind: TokenTcpFin},
		{Kind: TokenTcpHdrLength},
		{Kind: TokenTcpPayloadLength},
		{Kind: TokenTcpPsh},
		{Kind: TokenTcpRst},
		{Kind: TokenTcpSeqNum},
		{Kind: TokenTcpSrcPort},
		{Kind: TokenTcpSyn},
		{Kind: TokenTcpFin},
		{Kind: TokenTcpUrg},
		{Kind: TokenTcpUrgPtr},
		{Kind: TokenTcpWindow},
		{Kind: TokenUdp},
		{Kind: TokenUdpChecksum},
		{Kind: TokenUdpDstPort},
		{Kind: TokenUdpLength},
		{Kind: TokenUdpPayloadLength},
		{Kind: TokenUdpSrcPort},
		{Kind: TokenZero},
		{Kind: TokenEvent},
		{Kind: TokenRandom8},
		{Kind: TokenRandom16},
		{Kind: TokenRandom32},
		{Kind: TokenLength},
		{Kind: TokenTimestamp},
		{Kind: TokenTrue},
		{Kind: TokenFalse},
		{Kind: TokenInbound},
		{Kind: TokenOutbound},
		{Kind: TokenFragment},
		{Kind: TokenIfIdx},
		{Kind: TokenSubIfIdx},
		{Kind: TokenLoopback},
		{Kind: TokenImpostor},
		{Kind: TokenProcessId},
		{Kind: TokenLocalAddr},
		{Kind: TokenRemoteAddr},
		{Kind: TokenLocalPort},
		{Kind: TokenRemotePort},
		{Kind: TokenProtocol},
		{Kind: TokenEndpointId},
		{Kind: TokenParentEndpointId},
		{Kind: TokenLayer},
		{Kind: TokenPriority},
	}

	// Binary search:
	lo := 0
	hi := len(vars) - 1
	for lo <= hi {
		mid := (hi + lo) / 2
		if vars[mid].Kind < kind {
			lo = mid + 1
			continue
		}
		if vars[mid].Kind > kind {
			hi = mid - 1
			continue
		}
		return vars[mid], nil
	}
	return Expr{}, ErrAssertionFailed
}

func makeArrayVar(kind TokenKind, idx int) Expr {
	e := Expr{}
	e.Kind = kind
	e.Val[0] = uint32(idx)
	return e
}

func makeBinOp(kind TokenKind, arg0, arg1 *Expr) Expr {
	return Expr{
		Kind: kind,
		Arg:  [3]*Expr{arg0, arg1},
	}
}

func makeIfThenElse(cond, th, el *Expr) Expr {
	return Expr{
		Kind: TokenQuestion,
		Arg:  [3]*Expr{cond, th, el},
	}
}

func makeZero() Expr {
	return Expr{
		Val:  [4]uint32([]uint32{0, 0, 0, 0}),
		Kind: TokenNumber,
	}
}

func makeOne() Expr {
	return Expr{
		Val:  [4]uint32([]uint32{1, 0, 0, 0}),
		Kind: TokenNumber,
	}
}

func makeNumber(val [4]uint32) Expr {
	return Expr{
		Kind: TokenNumber,
		Val:  [4]uint32{val[0], val[1], val[2], val[3]},
	}
}
