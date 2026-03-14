package compile

import (
	"testing"

	"github.com/one-api/godivert/types"
)

func TestTokenizeFilter(t *testing.T) {
	tests := []struct {
		name     string
		filter   string
		layer    types.Layer
		expected []TokenKind
		wantErr  bool
	}{
		// Keywords
		{"true", "true", types.LayerNetwork, []TokenKind{TokenTrue, TokenEnd}, false},
		{"false", "false", types.LayerNetwork, []TokenKind{TokenFalse, TokenEnd}, false},
		{"inbound", "inbound", types.LayerNetwork, []TokenKind{TokenInbound, TokenEnd}, false},
		{"outbound", "outbound", types.LayerNetwork, []TokenKind{TokenOutbound, TokenEnd}, false},
		{"tcp", "tcp", types.LayerNetwork, []TokenKind{TokenTcp, TokenEnd}, false},
		{"udp", "udp", types.LayerNetwork, []TokenKind{TokenUdp, TokenEnd}, false},
		{"ip", "ip", types.LayerNetwork, []TokenKind{TokenIp, TokenEnd}, false},
		{"ipv6", "ipv6", types.LayerNetwork, []TokenKind{TokenIpv6, TokenEnd}, false},
		{"icmp", "icmp", types.LayerNetwork, []TokenKind{TokenIcmp, TokenEnd}, false},
		{"icmpv6", "icmpv6", types.LayerNetwork, []TokenKind{TokenIcmpV6, TokenEnd}, false},
		{"loopback", "loopback", types.LayerNetwork, []TokenKind{TokenLoopback, TokenEnd}, false},
		{"impostor", "impostor", types.LayerNetwork, []TokenKind{TokenImpostor, TokenEnd}, false},
		{"fragment", "fragment", types.LayerNetwork, []TokenKind{TokenFragment, TokenEnd}, false},

		// Operators
		{"and", "true and false", types.LayerNetwork, []TokenKind{TokenTrue, TokenAnd, TokenFalse, TokenEnd}, false},
		{"or", "true or false", types.LayerNetwork, []TokenKind{TokenTrue, TokenOr, TokenFalse, TokenEnd}, false},
		{"not", "!true", types.LayerNetwork, []TokenKind{TokenNot, TokenTrue, TokenEnd}, false},
		{"eq", "==", types.LayerNetwork, []TokenKind{TokenEq, TokenEnd}, false},
		{"neq", "!=", types.LayerNetwork, []TokenKind{TokenNeq, TokenEnd}, false},
		{"lt", "<", types.LayerNetwork, []TokenKind{TokenLt, TokenEnd}, false},
		{"leq", "<=", types.LayerNetwork, []TokenKind{TokenLeq, TokenEnd}, false},
		{"gt", ">", types.LayerNetwork, []TokenKind{TokenGt, TokenEnd}, false},
		{"geq", ">=", types.LayerNetwork, []TokenKind{TokenGeq, TokenEnd}, false},

		// Punctuation
		{"parens", "(true)", types.LayerNetwork, []TokenKind{TokenOpen, TokenTrue, TokenClose, TokenEnd}, false},
		{"brackets", "packet[0]", types.LayerNetwork, []TokenKind{TokenPacket, TokenSquareOpen, TokenNumber, TokenSquareClose, TokenEnd}, false},
		{"ternary", "? :", types.LayerNetwork, []TokenKind{TokenQuestion, TokenColon, TokenEnd}, false},

		// Field Access
		{"tcp_dst_port", "tcp.DstPort", types.LayerNetwork, []TokenKind{TokenTcpDstPort, TokenEnd}, false},
		{"ip_src_addr", "ip.SrcAddr", types.LayerNetwork, []TokenKind{TokenIpSrcAddr, TokenEnd}, false},
		{"ipv6_dst_addr", "ipv6.DstAddr", types.LayerNetwork, []TokenKind{TokenIpv6DstAddr, TokenEnd}, false},

		// Numbers and Addresses
		{"decimal", "1234", types.LayerNetwork, []TokenKind{TokenNumber, TokenEnd}, false},
		{"hex", "0x1234", types.LayerNetwork, []TokenKind{TokenNumber, TokenEnd}, false},
		{"ipv4", "127.0.0.1", types.LayerNetwork, []TokenKind{TokenNumber, TokenEnd}, false},
		{"ipv6_full", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", types.LayerNetwork, []TokenKind{TokenNumber, TokenEnd}, false},
		{"ipv6_short", "::1", types.LayerNetwork, []TokenKind{TokenNumber, TokenEnd}, false},

		// Macros (Uppercase)
		{"macro_tcp", "TCP", types.LayerNetwork, []TokenKind{TokenNumber, TokenEnd}, false},
		{"macro_udp", "UDP", types.LayerNetwork, []TokenKind{TokenNumber, TokenEnd}, false},
		{"macro_true", "TRUE", types.LayerNetwork, []TokenKind{TokenNumber, TokenEnd}, false},
		{"macro_false", "FALSE", types.LayerNetwork, []TokenKind{TokenNumber, TokenEnd}, false},

		// Layer-specific tokens
		{"flow_established", "ESTABLISHED", types.LayerFlow, []TokenKind{TokenNumber, TokenEnd}, false},
		{"socket_bind", "BIND", types.LayerSocket, []TokenKind{TokenNumber, TokenEnd}, false},

		// Whitespace
		{"whitespace", "  tcp   and\tudp\n", types.LayerNetwork, []TokenKind{TokenTcp, TokenAnd, TokenUdp, TokenEnd}, false},

		// Complex Filters
		{
			name:   "complex_web_traffic",
			filter: "(tcp.DstPort == 80 or tcp.DstPort == 443) and outbound and !loopback",
			layer:  types.LayerNetwork,
			expected: []TokenKind{
				TokenOpen, TokenTcpDstPort, TokenEq, TokenNumber, TokenOr,
				TokenTcpDstPort, TokenEq, TokenNumber, TokenClose, TokenAnd,
				TokenOutbound, TokenAnd, TokenNot, TokenLoopback, TokenEnd,
			},
			wantErr: false,
		},
		{
			name:   "complex_ipv6_payload",
			filter: "ipv6 and tcp and tcp.PayloadLength > 0 and tcp.Payload[0] == 0x01",
			layer:  types.LayerNetwork,
			expected: []TokenKind{
				TokenIpv6, TokenAnd, TokenTcp, TokenAnd, TokenTcpPayloadLength, TokenGt, TokenNumber,
				TokenAnd, TokenTcpPayload, TokenSquareOpen, TokenNumber, TokenSquareClose, TokenEq, TokenNumber, TokenEnd,
			},
			wantErr: false,
		},
		{
			name:   "complex_ternary_logic",
			filter: "inbound ? (tcp.SrcPort == 80) : (udp.SrcPort == 53)",
			layer:  types.LayerNetwork,
			expected: []TokenKind{
				TokenInbound, TokenQuestion, TokenOpen, TokenTcpSrcPort, TokenEq, TokenNumber, TokenClose,
				TokenColon, TokenOpen, TokenUdpSrcPort, TokenEq, TokenNumber, TokenClose, TokenEnd,
			},
			wantErr: false,
		},
		{
			name:   "complex_packet_offset",
			filter: "packet[20] == 0x06 and packet32[12] == 0x7F000001",
			layer:  types.LayerNetwork,
			expected: []TokenKind{
				TokenPacket, TokenSquareOpen, TokenNumber, TokenSquareClose, TokenEq, TokenNumber,
				TokenAnd, TokenPacket32, TokenSquareOpen, TokenNumber, TokenSquareClose, TokenEq, TokenNumber, TokenEnd,
			},
			wantErr: false,
		},
		{
			name:   "complex_flow_event",
			filter: "event == ESTABLISHED and (localPort == 80 or remotePort == 80)",
			layer:  types.LayerFlow,
			expected: []TokenKind{
				TokenEvent, TokenEq, TokenNumber, TokenAnd,
				TokenOpen, TokenLocalPort, TokenEq, TokenNumber, TokenOr, TokenRemotePort, TokenEq, TokenNumber, TokenClose, TokenEnd,
			},
			wantErr: false,
		},

		// Errors
		{"invalid_token", "@", types.LayerNetwork, nil, true},
		{"bad_token_for_layer", "ifIdx", types.LayerFlow, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens, err := TokenizeFilter(tt.filter, tt.layer, 100)
			if (err != nil) != tt.wantErr {
				t.Errorf("TokenizeFilter(%q) error = %v, wantErr %v", tt.filter, err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if len(tokens) != len(tt.expected) {
					t.Errorf("TokenizeFilter(%q) returned %d tokens, want %d", tt.filter, len(tokens), len(tt.expected))
					return
				}
				for i, expectedKind := range tt.expected {
					if tokens[i].Kind != expectedKind {
						t.Errorf("Token %d: got %v, want %v", i, tokens[i].Kind, expectedKind)
					}
				}
			}
		})
	}
}

func TestParseIPv4Address(t *testing.T) {
	tests := []struct {
		str     string
		want    [4]uint32
		wantErr bool
	}{
		{"127.0.0.1", [4]uint32{0, 0, 0x0000FFFF, 0x7F000001}, false},
		{"1.2.3.4", [4]uint32{0, 0, 0x0000FFFF, 0x01020304}, false},
		{"255.255.255.255", [4]uint32{0, 0, 0x0000FFFF, 0xFFFFFFFF}, false},
		{"invalid", [4]uint32{}, true},
		{"1.2.3", [4]uint32{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.str, func(t *testing.T) {
			got, err := ParseIPv4Address(tt.str)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseIPv4Address() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseIPv4Address() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseIPv6Address(t *testing.T) {
	tests := []struct {
		str     string
		want    [4]uint32
		wantErr bool
	}{
		{"::1", [4]uint32{1, 0, 0, 0}, false},
		{"2001:db8::ff00:42:8329", [4]uint32{0x00428329, 0x0000ff00, 0, 0x20010db8}, false},
		{"invalid", [4]uint32{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.str, func(t *testing.T) {
			got, err := ParseIPv6Address(tt.str)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseIPv6Address() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseIPv6Address() = %v, want %v", got, tt.want)
			}
		})
	}
}
