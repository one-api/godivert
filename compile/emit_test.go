package compile

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/one-api/godivert/types"
)

// compileFilterToObject is a helper function that compiles a filter string
// to a Filter object, handling all intermediate steps.
func compileFilterToObject(t *testing.T, filter string) []types.Filter {
	t.Helper()

	// Tokenize
	tokens, err := TokenizeFilter(filter, types.LayerNetwork, 100)
	if err != nil {
		t.Fatalf("TokenizeFilter failed: %v", err)
	}

	// Parse
	var i = 0
	expr, err := ParseFilter(tokens, &i, 1024, false)
	if err != nil {
		t.Fatalf("ParseFilter failed: %v", err)
	}

	// Flatten
	label := 0
	flattened, ipEP := FlattenExpr(expr, &label, types.FilterResultAccept, types.FilterResultReject, nil)
	if ipEP < 0 {
		t.Fatalf("FlattenExpr failed: %d", ipEP)
	}

	// Emit
	object := EmitFilter(flattened, ipEP)

	return object
}

func TestEmitFilterExactValues(t *testing.T) {
	tests := []struct {
		name     string
		filter   string
		expected []types.Filter
	}{
		{
			name:   "true_literal",
			filter: "true",
			expected: []types.Filter{
				makeFilter(types.FilterFieldZero, types.FilterTestEq, types.FilterResultAccept, types.FilterResultAccept, 0, [4]uint32{0, 0, 0, 0}),
			},
		},
		{
			name:   "false_literal",
			filter: "false",
			expected: []types.Filter{
				makeFilter(types.FilterFieldZero, types.FilterTestEq, types.FilterResultReject, types.FilterResultReject, 0, [4]uint32{0, 0, 0, 0}),
			},
		},
		{
			name:   "tcp_port_80_eq",
			filter: "tcp.DstPort == 80",
			expected: []types.Filter{
				makeFilter(types.FilterFieldTcpDstPort, types.FilterTestEq, types.FilterResultAccept, types.FilterResultReject, 0, [4]uint32{80, 0, 0, 0}),
			},
		},
		{
			name:   "tcp_and_udp",
			filter: "tcp and udp",
			expected: []types.Filter{
				makeFilter(types.FilterFieldTcp, types.FilterTestNeq, 1, types.FilterResultReject, 0, [4]uint32{0, 0, 0, 0}),
				makeFilter(types.FilterFieldUdp, types.FilterTestNeq, types.FilterResultAccept, types.FilterResultReject, 0, [4]uint32{0, 0, 0, 0}),
			},
		},
		{
			name:   "tcp_or_udp",
			filter: "tcp or udp",
			expected: []types.Filter{
				makeFilter(types.FilterFieldTcp, types.FilterTestNeq, types.FilterResultAccept, 1, 0, [4]uint32{0, 0, 0, 0}),
				makeFilter(types.FilterFieldUdp, types.FilterTestNeq, types.FilterResultAccept, types.FilterResultReject, 0, [4]uint32{0, 0, 0, 0}),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := compileFilterToObject(t, tt.filter)

			if len(actual) != len(tt.expected) {
				t.Fatalf("Length mismatch: got %d, want %d", len(actual), len(tt.expected))
			}

			for i := range actual {
				if !compareFilters(actual[i], tt.expected[i]) {
					t.Errorf("Filter %d mismatch:\ngot:  %+v\nwant: %+v", i, formatFilter(actual[i]), formatFilter(tt.expected[i]))
				}
			}
		})
	}
}

func makeFilter(field, test uint32, success, failure uint16, neg uint32, arg [4]uint32) types.Filter {
	f := types.Filter{}
	f.SetField(field)
	f.SetTest(test)
	f.SetSuccess(success)
	f.SetFailure(failure)
	f.SetNeg(neg)
	for i, a := range arg {
		f.SetArg(i, a)
	}
	return f
}

func compareFilters(a, b types.Filter) bool {
	if a.Field() != b.Field() ||
		a.Test() != b.Test() ||
		a.Success() != b.Success() ||
		a.Failure() != b.Failure() ||
		a.Neg() != b.Neg() {
		return false
	}
	argA := a.Arg()
	argB := b.Arg()
	for i := 0; i < 4; i++ {
		if argA[i] != argB[i] {
			return false
		}
	}
	return true
}

func formatFilter(f types.Filter) string {
	arg := f.Arg()
	data := map[string]interface{}{
		"Field":   f.Field(),
		"Test":    f.Test(),
		"Success": f.Success(),
		"Failure": f.Failure(),
		"Neg":     f.Neg(),
		"Arg":     fmt.Sprintf("[%d, %d, %d, %d]", arg[0], arg[1], arg[2], arg[3]),
	}
	b, _ := json.Marshal(data)
	return string(b)
}
