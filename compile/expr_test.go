package compile

import (
	"testing"

	"github.com/one-api/godivert/types"
)

func TestParseFilter(t *testing.T) {
	tests := []struct {
		name         string
		filter       string
		expectedExpr *Expr
		wantErr      bool
	}{
		// Simple Expressions
		{
			name:   "true",
			filter: "true",
			expectedExpr: &Expr{
				Kind: TokenNeq,
				Arg: [3]*Expr{
					{Kind: TokenTrue},
					{Kind: TokenNumber, Val: [4]uint32{0, 0, 0, 0}},
					nil,
				},
			},
		},
		{
			name:   "false",
			filter: "false",
			expectedExpr: &Expr{
				Kind: TokenNeq,
				Arg: [3]*Expr{
					{Kind: TokenFalse},
					{Kind: TokenNumber, Val: [4]uint32{0, 0, 0, 0}},
					nil,
				},
			},
		},
		{
			name:   "inbound",
			filter: "inbound",
			expectedExpr: &Expr{
				Kind: TokenNeq,
				Arg: [3]*Expr{
					{Kind: TokenInbound},
					{Kind: TokenNumber, Val: [4]uint32{0, 0, 0, 0}},
					nil,
				},
			},
		},
		{
			name:   "outbound",
			filter: "outbound",
			expectedExpr: &Expr{
				Kind: TokenNeq,
				Arg: [3]*Expr{
					{Kind: TokenOutbound},
					{Kind: TokenNumber, Val: [4]uint32{0, 0, 0, 0}},
					nil,
				},
			},
		},
		{
			name:   "tcp",
			filter: "tcp",
			expectedExpr: &Expr{
				Kind: TokenNeq,
				Arg: [3]*Expr{
					{Kind: TokenTcp},
					{Kind: TokenNumber, Val: [4]uint32{0, 0, 0, 0}},
					nil,
				},
			},
		},
		{
			name:   "udp",
			filter: "udp",
			expectedExpr: &Expr{
				Kind: TokenNeq,
				Arg: [3]*Expr{
					{Kind: TokenUdp},
					{Kind: TokenNumber, Val: [4]uint32{0, 0, 0, 0}},
					nil,
				},
			},
		},

		// Comparisons
		{
			name:   "port_eq",
			filter: "tcp.DstPort == 80",
			expectedExpr: &Expr{
				Kind: TokenEq,
				Arg: [3]*Expr{
					{Kind: TokenTcpDstPort},
					{Kind: TokenNumber, Val: [4]uint32{80, 0, 0, 0}},
					nil,
				},
			},
		},
		{
			name:   "addr_comparison",
			filter: "ip.SrcAddr == 192.168.1.1",
			expectedExpr: &Expr{
				Kind: TokenEq,
				Arg: [3]*Expr{
					{Kind: TokenIpSrcAddr},
					{Kind: TokenNumber, Val: [4]uint32{0, 0, 0x0000FFFF, 0xC0A80101}},
					nil,
				},
			},
		},

		// Logical Operators
		{
			name:   "simple_and",
			filter: "tcp and outbound",
			expectedExpr: &Expr{
				Kind: TokenAnd,
				Arg: [3]*Expr{
					{
						Kind: TokenNeq,
						Arg: [3]*Expr{
							{Kind: TokenTcp},
							{Kind: TokenNumber, Val: [4]uint32{0, 0, 0, 0}},
							nil,
						},
					},
					{
						Kind: TokenNeq,
						Arg: [3]*Expr{
							{Kind: TokenOutbound},
							{Kind: TokenNumber, Val: [4]uint32{0, 0, 0, 0}},
							nil,
						},
					},
					nil,
				},
			},
		},
		{
			name:   "simple_or",
			filter: "tcp or udp",
			expectedExpr: &Expr{
				Kind: TokenOr,
				Arg: [3]*Expr{
					{
						Kind: TokenNeq,
						Arg: [3]*Expr{
							{Kind: TokenTcp},
							{Kind: TokenNumber, Val: [4]uint32{0, 0, 0, 0}},
							nil,
						},
					},
					{
						Kind: TokenNeq,
						Arg: [3]*Expr{
							{Kind: TokenUdp},
							{Kind: TokenNumber, Val: [4]uint32{0, 0, 0, 0}},
							nil,
						},
					},
					nil,
				},
			},
		},
		{
			name:   "and_binds_tighter_than_or",
			filter: "tcp and outbound or udp",
			expectedExpr: &Expr{
				Kind: TokenOr,
				Arg: [3]*Expr{
					{
						Kind: TokenAnd,
						Arg: [3]*Expr{
							{
								Kind: TokenNeq,
								Arg: [3]*Expr{
									{Kind: TokenTcp},
									{Kind: TokenNumber, Val: [4]uint32{0, 0, 0, 0}},
									nil,
								},
							},
							{
								Kind: TokenNeq,
								Arg: [3]*Expr{
									{Kind: TokenOutbound},
									{Kind: TokenNumber, Val: [4]uint32{0, 0, 0, 0}},
									nil,
								},
							},
							nil,
						},
					},
					{
						Kind: TokenNeq,
						Arg: [3]*Expr{
							{Kind: TokenUdp},
							{Kind: TokenNumber, Val: [4]uint32{0, 0, 0, 0}},
							nil,
						},
					},
					nil,
				},
			},
		},
		{
			name:   "parenthesized_mixed",
			filter: "(tcp or udp) and outbound",
			expectedExpr: &Expr{
				Kind: TokenAnd,
				Arg: [3]*Expr{
					{
						Kind: TokenOr,
						Arg: [3]*Expr{
							{
								Kind: TokenNeq,
								Arg: [3]*Expr{
									{Kind: TokenTcp},
									{Kind: TokenNumber, Val: [4]uint32{00, 0, 0, 0}},
									nil,
								},
							},
							{
								Kind: TokenNeq,
								Arg: [3]*Expr{
									{Kind: TokenUdp},
									{Kind: TokenNumber, Val: [4]uint32{0, 0, 0, 0}},
									nil,
								},
							},
							nil,
						},
					},
					{
						Kind: TokenNeq,
						Arg: [3]*Expr{
							{Kind: TokenOutbound},
							{Kind: TokenNumber, Val: [4]uint32{0, 0, 0, 0}},
							nil,
						},
					},
					nil,
				},
			},
		},

		// Negation
		{
			name:   "simple_not",
			filter: "!tcp",
			expectedExpr: &Expr{
				Kind: TokenEq,
				Arg: [3]*Expr{
					{Kind: TokenTcp},
					{Kind: TokenNumber, Val: [4]uint32{0, 0, 0, 0}},
					nil,
				},
			},
		},
		{
			name:   "double_negation",
			filter: "!!tcp",
			expectedExpr: &Expr{
				Kind: TokenNeq,
				Arg: [3]*Expr{
					{Kind: TokenTcp},
					{Kind: TokenNumber, Val: [4]uint32{0, 0, 0, 0}},
					nil,
				},
			},
		},

		// Parentheses
		{
			name:   "single_parens",
			filter: "(true)",
			expectedExpr: &Expr{
				Kind: TokenNeq,
				Arg: [3]*Expr{
					{Kind: TokenTrue},
					{Kind: TokenNumber, Val: [4]uint32{0, 0, 0, 0}},
					nil,
				},
			},
		},
		{
			name:    "mismatched_open",
			filter:  "((true)",
			wantErr: true,
		},
		{
			name:         "mismatched_close",
			filter:       "(true))",
			expectedExpr: nil,
			wantErr:      true,
		},
		{
			name:    "empty_parens",
			filter:  "()",
			wantErr: true,
		},

		// Array Access
		{
			name:   "packet_index",
			filter: "packet[0] == 0x48",
			expectedExpr: &Expr{
				Kind: TokenEq,
				Arg: [3]*Expr{
					{
						Kind: TokenPacket,
						Val:  [4]uint32{0, 0, 0, 0},
					},
					{Kind: TokenNumber, Val: [4]uint32{0x48, 0, 0, 0}},
					nil,
				},
			},
		},

		// Complex/Real-world
		{
			name:   "web_traffic",
			filter: "(tcp.DstPort == 80 or tcp.DstPort == 443) and outbound",
			expectedExpr: &Expr{
				Kind: TokenAnd,
				Arg: [3]*Expr{
					{
						Kind: TokenOr,
						Arg: [3]*Expr{
							{
								Kind: TokenEq,
								Arg: [3]*Expr{
									{Kind: TokenTcpDstPort},
									{Kind: TokenNumber, Val: [4]uint32{80, 0, 0, 0}},
									nil,
								},
							},
							{
								Kind: TokenEq,
								Arg: [3]*Expr{
									{Kind: TokenTcpDstPort},
									{Kind: TokenNumber, Val: [4]uint32{443, 0, 0, 0}},
									nil,
								},
							},
							nil,
						},
					},
					{
						Kind: TokenNeq,
						Arg: [3]*Expr{
							{Kind: TokenOutbound},
							{Kind: TokenNumber, Val: [4]uint32{0, 0, 0, 0}},
							nil,
						},
					},
					nil,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens, err := TokenizeFilter(tt.filter, types.LayerNetwork, 5000)
			if err != nil {
				if tt.wantErr {
					return // Tokenizer failed as expected for some cases.
				}
				t.Fatalf("TokenizeFilter failed: %v", err)
			}

			i := 0
			expr, err := ParseFilter(tokens, &i, 1024, false)
			if (err != nil || i+1 != len(tokens)) != tt.wantErr {
				t.Fatalf("ParseFilter(%q) error=%v, wantErr=%v, len: %d, wantLen: %d", tt.filter, err, tt.wantErr, i, len(tokens))
			}

			if !tt.wantErr {
				if !compareExpr(expr, tt.expectedExpr) {
					t.Errorf("ParseFilter(%q)\ngot:  %+v\nwant: %+v", tt.filter, expr, tt.expectedExpr)
				}
			}
		})
	}
}

// compareExpr recursively compares two Expr structs, ignoring pointer addresses
func compareExpr(a, b *Expr) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	if a.Kind != b.Kind {
		return false
	}
	if a.Val != b.Val {
		return false
	}
	// Count, Neg, Succ, Fail are not strictly checked here as they might be defaults or calculated later
	// But if you want strict equality on those fields too, add checks here.
	// For parsing tests, usually Kind, Val, and Args structure matter most.

	for i := 0; i < 3; i++ {
		if !compareExpr(a.Arg[i], b.Arg[i]) {
			return false
		}
	}

	return true
}
