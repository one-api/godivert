package compile

import (
	"testing"

	"github.com/one-api/godivert/types"
)

func TestCompileFilter(t *testing.T) {
	tests := []struct {
		name    string
		filter  string
		layer   types.Layer
		wantErr bool
	}{
		{
			name:    "true",
			filter:  "true",
			layer:   types.LayerNetwork,
			wantErr: false,
		},
		{
			name:    "false",
			filter:  "false",
			layer:   types.LayerNetwork,
			wantErr: false,
		},
		{
			name:    "outbound",
			filter:  "outbound",
			layer:   types.LayerNetwork,
			wantErr: false,
		},
		{
			name:    "tcp port 80",
			filter:  "tcp.DstPort == 80",
			layer:   types.LayerNetwork,
			wantErr: false,
		},
		{
			name:    "udp port 53",
			filter:  "udp.SrcPort == 53",
			layer:   types.LayerNetwork,
			wantErr: false,
		},
		{
			name:    "ip src addr",
			filter:  "ip.SrcAddr == 1.2.3.4",
			layer:   types.LayerNetwork,
			wantErr: false,
		},
		{
			name:    "complex",
			filter:  "outbound and (tcp.DstPort == 80 or udp.DstPort == 53)",
			layer:   types.LayerNetwork,
			wantErr: false,
		},
		{
			name:    "invalid token",
			filter:  "invalid",
			layer:   types.LayerNetwork,
			wantErr: true,
		},
		{
			name:    "syntax error",
			filter:  "tcp.DstPort ==",
			layer:   types.LayerNetwork,
			wantErr: true,
		},
		{
			name:    "ipv6 address",
			filter:  "ipv6.DstAddr == ::1",
			layer:   types.LayerNetwork,
			wantErr: false,
		},

		// Nested parentheses tests
		{
			name:    "single_paren",
			filter:  "(true)",
			layer:   types.LayerNetwork,
			wantErr: false,
		},
		{
			name:    "double_nested",
			filter:  "((true))",
			layer:   types.LayerNetwork,
			wantErr: false,
		},
		{
			name:    "triple_nested",
			filter:  "(((true)))",
			layer:   types.LayerNetwork,
			wantErr: false,
		},
		{
			name:    "complex_nested_or",
			filter:  "((tcp && (tcp.DstPort == 80)) || (udp && (udp.DstPort == 53)))",
			layer:   types.LayerNetwork,
			wantErr: false,
		},
		{
			name:    "deeply_nested_and",
			filter:  "((((((tcp && tcp.DstPort == 80)) && outbound) && !fragment) && ip))",
			layer:   types.LayerNetwork,
			wantErr: false,
		},
		{
			name:    "mismatched_parens",
			filter:  "((tcp && tcp.DstPort == 80)",
			layer:   types.LayerNetwork,
			wantErr: true,
		},
		{
			name:    "extra_close_paren",
			filter:  "(tcp && tcp.DstPort == 80))",
			layer:   types.LayerNetwork,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CompileFilter(tt.filter, tt.layer)
			if tt.wantErr != (err != nil) {
				t.Errorf("want error: %v, got: %v", tt.wantErr, err)
			}
		})
	}
}
