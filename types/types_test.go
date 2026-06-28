package types

import (
	"testing"
	"unsafe"
)

func TestWinDivertStructLayouts(t *testing.T) {
	// 1. Verify Address size (must be 80 bytes)
	if size := unsafe.Sizeof(Address{}); size != 80 {
		t.Errorf("Address size expected 80, got %d", size)
	}

	// 2. Verify DataNetwork size (must be 8 bytes)
	if size := unsafe.Sizeof(DataNetwork{}); size != 8 {
		t.Errorf("DataNetwork size expected 8, got %d", size)
	}

	// 3. Verify DataFlow Protocol offset (must be 56)
	df := DataFlow{}
	if offset := unsafe.Offsetof(df.Protocol); offset != 56 {
		t.Errorf("DataFlow.Protocol offset expected 56, got %d", offset)
	}

	// 4. Verify DataSocket Protocol offset (must be 56)
	ds := DataSocket{}
	if offset := unsafe.Offsetof(ds.Protocol); offset != 56 {
		t.Errorf("DataSocket.Protocol offset expected 56, got %d", offset)
	}

	// 5. Verify DataReflect Priority offset (must be 24)
	dr := DataReflect{}
	if offset := unsafe.Offsetof(dr.Priority); offset != 24 {
		t.Errorf("DataReflect.Priority offset expected 24, got %d", offset)
	}
}
