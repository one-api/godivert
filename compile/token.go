package compile

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode"

	"github.com/one-api/godivert/types"
)

// TokenLookup search the given name in TokenInfoTable
func TokenLookup(name string, TokenInfoTable []TokenInfo) *TokenInfo {
	lo := 0
	hi := len(TokenInfoTable) - 1
	for lo <= hi {
		mid := (lo + hi) / 2
		cmp := strings.Compare(TokenInfoTable[mid].Name, name)
		if cmp < 0 {
			lo = mid + 1
		} else if cmp > 0 {
			hi = mid - 1
		} else {
			return &TokenInfoTable[mid]
		}
	}
	return nil
}

func isAlNum(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }
func isSpace(r rune) bool { return unicode.IsSpace(r) }

// ParseIPv4Address converts a dotted-decimal IPv4 string
// into a 32-bit integer (network byte order/big-endian).
func ParseIPv4Address(str string) ([4]uint32, error) {
	ip := net.ParseIP(str)
	if ip == nil {
		return [4]uint32{}, errors.New("invalid parameter: failed to parse IPv4 address")
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return [4]uint32{}, errors.New("invalid parameter: not a valid IPv4 address")
	}
	pendingBytes := binary.BigEndian.Uint32([]byte{0x00, 0x00, 0xFF, 0xFF})
	return [4]uint32{0, 0, pendingBytes, binary.BigEndian.Uint32(ip4)}, nil
}

// ParseIPv6Address converts an IPv6 address string into a 4-element array of 32-bit integers (network byte order).
func ParseIPv6Address(str string) ([4]uint32, error) {
	ip := net.ParseIP(str)
	if ip == nil {
		return [4]uint32{}, errors.New("invalid parameter: failed to parse IPv6 address")
	}

	ip16 := ip.To16()
	if ip16 == nil {
		return [4]uint32{}, errors.New("invalid parameter: address is neither valid IPv4 nor IPv6")
	}

	var result [4]uint32
	for i := 0; i < 4; i++ {
		result[3-i] = binary.BigEndian.Uint32(ip16[i*4 : i*4+4])
	}

	return result, nil
}

// TokenizeFilter converts the filter string into a slice of Tokens.
func TokenizeFilter(filter string, layer types.Layer, tokensMax uint) ([]Token, error) {
	var tokens []Token
	var i int

	for {
		if len(tokens) >= int(tokensMax-1) {
			break
		}

		// skip whitespace
		for i < len(filter) && isSpace(rune(filter[i])) {
			i++
			continue
		}

		if i >= len(filter) {
			tokens = append(tokens, Token{Kind: TokenEnd, Pos: uint32(i)})
			return tokens, nil
		}

		newI, token, err := scanConditionToken(filter, i)
		if err != nil {
			return nil, err
		}
		if newI != i {
			tokens = append(tokens, token)
			i = newI
			continue
		}

		newI, token, err = scanNumber(filter, i, layer)
		if err != nil {
			return nil, err
		}
		if newI != i {
			tokens = append(tokens, token)
			i = newI
			continue
		}

		return nil, fmt.Errorf("%w at %d", ErrBadToken, i)
	}

	return tokens, fmt.Errorf("%w at %d", ErrTooLong, i)
}

func scanConditionToken(filter string, i int) (int, Token, error) {
	c := rune(filter[i])
	t := Token{Pos: uint32(i)}
	startI := i
	i++

	switch c {
	case '(':
		t.Kind = TokenOpen
	case ')':
		t.Kind = TokenClose
	case '[':
		t.Kind = TokenSquareOpen
	case ']':
		t.Kind = TokenSquareClose
	case '-':
		t.Kind = TokenMinus
	case '!':
		if i < len(filter) && filter[i] == '=' {
			i++
			t.Kind = TokenNeq
		} else {
			t.Kind = TokenNot
		}
	case '=':
		if i < len(filter) && filter[i] == '=' {
			i++
		}
		t.Kind = TokenEq
	case '<':
		if i < len(filter) && filter[i] == '=' {
			i++
			t.Kind = TokenLeq
		} else {
			t.Kind = TokenLt
		}
	case '>':
		if i < len(filter) && filter[i] == '=' {
			i++
			t.Kind = TokenGeq
		} else {
			t.Kind = TokenGt
		}
	case ':':
		if i < len(filter) && filter[i] == ':' {
			return startI, Token{}, nil
		} else {
			t.Kind = TokenColon
		}
	case '?':
		t.Kind = TokenQuestion
	case '&':
		if i >= len(filter) {
			return startI, Token{}, fmt.Errorf("%w at %d, expected: &, but got end of filter", ErrBadToken, i-1)
		}

		if filter[i] != '&' {
			return startI, Token{}, fmt.Errorf("%w at %d, expected: &, but: %c", ErrBadToken, filter[i], i-1)
		}

		i++
		t.Kind = TokenAnd
	case '|':

		if i >= len(filter) {
			return startI, Token{}, fmt.Errorf("%w at %d, expected: |, but got end of filter", ErrBadToken, i-1)
		}

		if filter[i] != '|' {
			return startI, Token{}, fmt.Errorf("%w at %d, expected: |, but: %c", ErrBadToken, i-1, filter[i])
		}

		i++
		t.Kind = TokenOr
	default: // no condition token, return previous start
		return startI, Token{}, nil
	}

	return i, t, nil
}

func scanNumber(filter string, i int, layer types.Layer) (int, Token, error) {
	c := rune(filter[i])

	if !(isAlNum(c) || c == '.' || c == ':' || c == '_') {
		return i, Token{}, fmt.Errorf("%w in %d: %c", ErrBadToken, i, filter[i])
	}

	start := i
	for i < len(filter) && (isAlNum(rune(filter[i])) || filter[i] == '.' || filter[i] == ':' || filter[i] == '_') {
		i++
	}
	tokenStr := filter[start:i]
	if len(tokenStr) >= tokenMaxLen {
		return i, Token{}, fmt.Errorf("%w, token too long in %d: %s", ErrBadToken, start, tokenStr)
	}

	// Handle trailing colons:
	if len(tokenStr) >= 1 && tokenStr[len(tokenStr)-1] == ':' {
		if len(tokenStr) == 1 || tokenStr[len(tokenStr)-2] != ':' {
			tokenStr = tokenStr[:len(tokenStr)-1]
			i--
		}
	}

	// 1. Check for symbol:
	result := TokenLookup(tokenStr, gTokenInfos)
	if result != nil {
		field := result.Kind.ToField()
		if field <= types.FilterFieldMax && !ValidateField(layer, field) {
			return i, Token{}, fmt.Errorf("%w at pos %d: %c", ErrBadTokenForLayer, start, filter[start])
		}

		if val, ok := expandMacro(result.Kind, layer); ok {
			return i, Token{Kind: TokenNumber, Pos: uint32(start), Val: [4]uint32{val, 0, 0, 0}}, nil
		}

		return i, Token{Kind: result.Kind, Pos: uint32(start)}, nil
	}

	// 2. Check for 'b':
	if tokenStr == "b" {
		return i, Token{Kind: TokenBytes, Pos: uint32(start)}, nil
	}

	// Check for base 10 number with optional 'b' suffix
	if strings.HasSuffix(tokenStr, "b") {
		numStr := tokenStr[:len(tokenStr)-1]
		number, err := strconv.ParseUint(numStr, 10, 32)
		if err == nil {
			i-- // Backtrack 'b'
			return i, Token{Kind: TokenNumber, Pos: uint32(start), Val: [4]uint32{uint32(number), 0, 0, 0}}, nil
		}
	}

	number, err := strconv.ParseUint(tokenStr, 10, 32)
	if err == nil {
		return i, Token{Kind: TokenNumber, Pos: uint32(start), Val: [4]uint32{uint32(number), 0, 0, 0}}, nil
	}

	// Check for base 16 number:
	if strings.HasPrefix(tokenStr, "0x") {
		number, err := strconv.ParseUint(tokenStr[2:], 16, 32)
		if err == nil {
			return i, Token{Kind: TokenNumber, Pos: uint32(start), Val: [4]uint32{uint32(number), 0, 0, 0}}, nil
		}
	}

	// Check for IPv4 address:
	if ipv4Addr, err := ParseIPv4Address(tokenStr); err == nil {
		return i, Token{Kind: TokenNumber, Pos: uint32(start), Val: ipv4Addr}, nil
	}

	// Check for IPv6 address:
	if ipv6Addr, err := ParseIPv6Address(tokenStr); err == nil {
		return i, Token{Kind: TokenNumber, Pos: uint32(start), Val: ipv6Addr}, nil
	}

	return i, Token{}, fmt.Errorf("%w at pos %d: %c", ErrBadToken, start, filter[start])
}

func expandMacro(kind TokenKind, layer types.Layer) (uint32, bool) {
	switch kind {
	case TokenNetwork:
		return uint32(types.LayerNetwork), true
	case TokenNetworkForward:
		return uint32(types.LayerNetworkForward), true
	case TokenFlow:
		return uint32(types.LayerFlow), true
	case TokenSocket:
		return uint32(types.LayerSocket), true
	case TokenReflect:
		return uint32(types.LayerReflect), true
	case TokenEventPacket:
		if layer == types.LayerNetwork || layer == types.LayerNetworkForward {
			return uint32(types.EventNetworkPacket), true
		}
		return 0, false
	case TokenEventEstablished:
		if layer == types.LayerFlow {
			return uint32(types.EventFlowEstablished), true
		}
		return 0, false
	case TokenEventDeleted:
		if layer == types.LayerFlow {
			return uint32(types.EventFlowDeleted), true
		}
		return 0, false
	case TokenEventBind:
		if layer == types.LayerSocket {
			return uint32(types.EventSocketBind), true
		}
		return 0, false
	case TokenEventConnect:
		if layer == types.LayerSocket {
			return uint32(types.EventSocketConnect), true
		}
		return 0, false
	case TokenEventListen:
		if layer == types.LayerSocket {
			return uint32(types.EventSocketListen), true
		}
		return 0, false
	case TokenEventAccept:
		if layer == types.LayerSocket {
			return uint32(types.EventSocketAccept), true
		}
		return 0, false
	case TokenEventOpen:
		if layer == types.LayerReflect {
			return uint32(types.EventReflectOpen), true
		}
		return 0, false
	case TokenEventClose:
		switch layer {
		case types.LayerSocket:
			return uint32(types.EventSocketClose), true
		case types.LayerReflect:
			return uint32(types.EventReflectClose), true
		default:
			return 0, false
		}
	case TokenMacroTrue:
		return 1, true
	case TokenMacroFalse:
		return 0, true
	case TokenMacroTcp:
		return uint32(types.IProtoTcp), true
	case TokenMacroUdp:
		return uint32(types.IProtoUdp), true
	case TokenMacroIcmp:
		return uint32(types.IProtoIcmp), true
	case TokenMacroIcmpV6:
		return uint32(types.IProtoIcmpV6), true
	default:
		return 0, false
	}
}
