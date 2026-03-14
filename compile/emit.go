package compile

import "github.com/one-api/godivert/types"

func EmitFilter(stack []*Expr, ipEP int) (object []types.Filter) {

	switch ipEP {
	case types.FilterResultAccept, types.FilterResultReject:
		f := types.Filter{}
		f.SetField(types.FilterFieldZero)
		f.SetTest(types.FilterTestEq)
		f.SetSuccess(uint16(ipEP))
		f.SetFailure(uint16(ipEP))
		return []types.Filter{f}
	default:
	}

	object = make([]types.Filter, len(stack))
	length := len(stack)
	for i := 0; i < length; i++ {
		object[i] = EmitTest(stack[length-1-i], uint16(ipEP))
	}
	return object
}

func EmitTest(test *Expr, offset uint16) (object types.Filter) {
	varExpr := test.Arg[0]
	val := test.Arg[1]

	switch test.Kind {
	case TokenEq:
		object.SetTest(types.FilterTestEq)
	case TokenNeq:
		object.SetTest(types.FilterTestNeq)
	case TokenLt:
		object.SetTest(types.FilterTestLt)
	case TokenLeq:
		object.SetTest(types.FilterTestLeq)
	case TokenGt:
		object.SetTest(types.FilterTestGt)
	case TokenGeq:
		object.SetTest(types.FilterTestGeq)
	default:
		return
	}

	object.SetField(varExpr.Kind.ToField())
	if val.Neg {
		object.SetNeg(1)
	} else {
		object.SetNeg(0)
	}
	object.SetArg(0, val.Val[0])
	object.SetArg(1, val.Val[1])
	object.SetArg(2, val.Val[2])
	object.SetArg(3, val.Val[3])

	switch varExpr.Kind {
	case TokenPacket, TokenPacket16, TokenPacket32,
		TokenTcpPayload, TokenTcpPayload16, TokenTcpPayload32,
		TokenUdpPayload, TokenUdpPayload16, TokenUdpPayload32:
		object.SetArg(1, varExpr.Val[0])
	default:
		break
	}

	switch test.Succ {
	case types.FilterResultAccept, types.FilterResultReject:
		object.SetSuccess(test.Succ)
	default:
		object.SetSuccess(offset - test.Succ)
	}

	switch test.Fail {
	case types.FilterResultAccept, types.FilterResultReject:
		object.SetFailure(test.Fail)
	default:
		object.SetFailure(offset - test.Fail)
	}
	return object
}
