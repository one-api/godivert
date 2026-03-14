package compile

import (
	"testing"

	"github.com/one-api/godivert/types"
)

type expectedEntry struct {
	varKind TokenKind
	succ    uint16
	fail    uint16
}

func TestFlattenExpr(t *testing.T) {
	tests := []struct {
		filter        string
		expectedStack []expectedEntry
		expectedEntry int
		expectError   bool
	}{
		{
			filter:        "true",
			expectedStack: []expectedEntry{},
			expectedEntry: types.FilterResultAccept,
		},
		{
			filter:        "false",
			expectedStack: []expectedEntry{},
			expectedEntry: types.FilterResultReject,
		},
		{
			filter: "tcp",
			expectedStack: []expectedEntry{
				{varKind: TokenTcp, succ: types.FilterResultAccept, fail: types.FilterResultReject},
			},
			expectedEntry: 0,
		},
		{
			filter: "inbound and tcp",
			expectedStack: []expectedEntry{
				{varKind: TokenTcp, succ: types.FilterResultAccept, fail: types.FilterResultReject},
				{varKind: TokenInbound, succ: 0, fail: types.FilterResultReject},
			},
			expectedEntry: 1,
		},
		{
			filter: "tcp or udp",
			expectedStack: []expectedEntry{
				{varKind: TokenUdp, succ: types.FilterResultAccept, fail: types.FilterResultReject},
				{varKind: TokenTcp, succ: types.FilterResultAccept, fail: 0},
			},
			expectedEntry: 1,
		},
		{
			filter: "tcp and udp",
			expectedStack: []expectedEntry{
				{varKind: TokenUdp, succ: types.FilterResultAccept, fail: types.FilterResultReject},
				{varKind: TokenTcp, succ: 0, fail: types.FilterResultReject},
			},
			expectedEntry: 1,
		},
		{
			filter: "(tcp or udp) and inbound",
			expectedStack: []expectedEntry{
				{varKind: TokenInbound, succ: types.FilterResultAccept, fail: types.FilterResultReject},
				{varKind: TokenUdp, succ: 0, fail: types.FilterResultReject},
				{varKind: TokenTcp, succ: 0, fail: 1},
			},
			expectedEntry: 2,
		},
		{
			filter: "(inbound ? tcp : udp)",
			expectedStack: []expectedEntry{
				{varKind: TokenUdp, succ: types.FilterResultAccept, fail: types.FilterResultReject},
				{varKind: TokenTcp, succ: types.FilterResultAccept, fail: types.FilterResultReject},
				{varKind: TokenInbound, succ: 1, fail: 0},
			},
			expectedEntry: 2,
		},
		{
			filter: "tcp.DstPort == 80",
			expectedStack: []expectedEntry{
				{varKind: TokenTcpDstPort, succ: types.FilterResultAccept, fail: types.FilterResultReject},
			},
			expectedEntry: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.filter, func(t *testing.T) {
			tokens, err := TokenizeFilter(tc.filter, types.LayerNetwork, 100)
			if err != nil {
				t.Fatalf("TokenizeFilter failed: %v", err)
			}

			var i = 0
			expr, err := ParseFilter(tokens, &i, 1024, false)
			if err != nil {
				t.Fatalf("ParseFilter failed: %v", err)
			}

			var label = 0
			stack, resultEntry := FlattenExpr(expr, &label, types.FilterResultAccept, types.FilterResultReject, nil)

			if tc.expectError {
				if resultEntry >= 0 {
					t.Errorf("Expected error, got resultEntry=%d", resultEntry)
				}
				return
			}

			if resultEntry < 0 && tc.expectedEntry >= 0 {
				t.Fatalf("FlattenExpr failed: %d", resultEntry)
			}

			if resultEntry != tc.expectedEntry {
				t.Errorf("Entry point mismatch: got %d, want %d", resultEntry, tc.expectedEntry)
			}

			if len(stack) != len(tc.expectedStack) {
				t.Fatalf("Stack size mismatch: got %d, want %d", len(stack), len(tc.expectedStack))
			}

			for j := 0; j < len(stack); j++ {
				actual := stack[j]
				expected := tc.expectedStack[j]

				actualVarKind := actual.Kind
				if (actual.Kind == TokenEq || actual.Kind == TokenNeq) && actual.Arg[0] != nil {
					actualVarKind = actual.Arg[0].Kind
				}

				if actualVarKind != expected.varKind {
					t.Errorf("stack[%d] varKind mismatch: got %v, want %v", j, actualVarKind, expected.varKind)
				}
				if actual.Succ != expected.succ {
					t.Errorf("stack[%d] Succ mismatch: got %d, want %d", j, actual.Succ, expected.succ)
				}
				if actual.Fail != expected.fail {
					t.Errorf("stack[%d] Fail mismatch: got %d, want %d", j, actual.Fail, expected.fail)
				}
			}
		})
	}
}
