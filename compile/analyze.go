package compile

import "github.com/one-api/godivert/types"

func AnalyzeFilter(layer types.Layer, filter []types.Filter) uint64 {
	var flags uint64 = 0

	// False filter?
	if !condExecFilter(filter, types.FilterFieldZero, 0) {
		return 0
	}

	if layer == types.LayerNetwork || layer == types.LayerNetworkForward {
		// Inbound?
		if condExecFilter(filter, types.FilterFieldInbound, 1) &&
			condExecFilter(filter, types.FilterFieldOutbound, 0) {
			flags |= uint64(types.FilterFlagInbound)
		}

		// Outbound?
		if condExecFilter(filter, types.FilterFieldOutbound, 1) &&
			condExecFilter(filter, types.FilterFieldInbound, 0) {
			flags |= uint64(types.FilterFlagOutbound)
		}
	}

	if layer != types.LayerReflect {
		// IPv4?
		if condExecFilter(filter, types.FilterFieldIp, 1) &&
			condExecFilter(filter, types.FilterFieldIpv6, 0) {
			flags |= uint64(types.FilterFlagIp)
		}

		// IPv6?
		if condExecFilter(filter, types.FilterFieldIpv6, 1) &&
			condExecFilter(filter, types.FilterFieldIp, 0) {
			flags |= uint64(types.FilterFlagIpv6)
		}
	}

	// Events:
	switch layer {
	case types.LayerFlow:
		if condExecFilter(filter, types.FilterFieldEvent, uint32(types.EventFlowDeleted)) {
			flags |= uint64(types.FilterFlagEventFlowDeleted)
		}
	case types.LayerSocket:
		if condExecFilter(filter, types.FilterFieldEvent, uint32(types.EventSocketBind)) {
			flags |= uint64(types.FilterFlagEventSocketBind)
		}
		if condExecFilter(filter, types.FilterFieldEvent, uint32(types.EventSocketConnect)) {
			flags |= uint64(types.FilterFlagEventSocketConnect)
		}
		if condExecFilter(filter, types.FilterFieldEvent, uint32(types.EventSocketClose)) {
			flags |= uint64(types.FilterFlagEventSocketClose)
		}
		if condExecFilter(filter, types.FilterFieldEvent, uint32(types.EventSocketListen)) {
			flags |= uint64(types.FilterFlagEventSocketListen)
		}
		if condExecFilter(filter, types.FilterFieldEvent, uint32(types.EventSocketAccept)) {
			flags |= uint64(types.FilterFlagEventSocketAccept)
		}
	default:
		// No-op for other layers
	}

	return flags
}

func condExecFilter(filter []types.Filter, field uint32, arg uint32) bool {
	length := len(filter)
	if length == 0 {
		return true
	}

	result := make([]bool, length)

	for ip := length - 1; ip >= 0; ip-- {
		var resultSucc, resultFail, resultTest bool

		succ := filter[ip].Success()
		if succ == types.FilterResultAccept {
			resultSucc = true
		} else if succ == types.FilterResultReject {
			resultSucc = false
		} else if int(succ) > ip && int(succ) < length {
			resultSucc = result[succ]
		} else {
			resultSucc = true
		}

		fail := filter[ip].Failure()
		if fail == types.FilterResultAccept {
			resultFail = true
		} else if fail == types.FilterResultReject {
			resultFail = false
		} else if int(fail) > ip && int(fail) < length {
			resultFail = result[fail]
		} else {
			resultFail = true
		}

		if resultSucc == resultFail {
			result[ip] = resultSucc
		} else if filter[ip].Field() == field {
			args := filter[ip].Arg()
			if filter[ip].Neg() != 0 || args[1] != 0 || args[2] != 0 || args[3] != 0 {
				result[ip] = true
			} else {
				switch filter[ip].Test() {
				case types.FilterTestEq:
					resultTest = arg == args[0]
				case types.FilterTestNeq:
					resultTest = arg != args[0]
				case types.FilterTestLt:
					resultTest = arg < args[0]
				case types.FilterTestLeq:
					resultTest = arg <= args[0]
				case types.FilterTestGt:
					resultTest = arg > args[0]
				case types.FilterTestGeq:
					resultTest = arg >= args[0]
				default:
					result[ip] = true
					continue
				}
				if resultTest {
					result[ip] = resultSucc
				} else {
					result[ip] = resultFail
				}
			}
		} else {
			// Field not mentioned - assume it passes (doesn't prevent matching)
			result[ip] = true
		}
	}

	return result[0]
}
