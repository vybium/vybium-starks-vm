package protocols

import (
	"math/big"
	"testing"

	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
)

func TestFRIProtocolCreation(t *testing.T) {
	field, err := core.NewField(big.NewInt(2013265921))
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	rate := field.NewElementFromInt64(2)  // Rate parameter ρ
	omega := field.NewElementFromInt64(7) // Domain generator

	t.Run("Create_FRI_Protocol", func(t *testing.T) {
		fri := NewFRIProtocol(field, rate, omega)

		if fri == nil {
			t.Fatal("FRI protocol is nil")
		}

		// Verify the protocol was initialized
		// Note: Most FRI fields are private, so we can only verify non-nil creation
	})
}

func TestFRIQueryPhaseCreation(t *testing.T) {
	field, err := core.NewField(big.NewInt(2013265921))
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	rate := field.NewElementFromInt64(2)

	t.Run("Create_FRI_Query_Phase", func(t *testing.T) {
		eta := 1
		repetitionParam := 10

		queryPhase := NewFRIQueryPhase(field, rate, eta, repetitionParam)

		if queryPhase == nil {
			t.Fatal("FRI query phase is nil")
		}
	})
}

func TestFRIProtocolParameters(t *testing.T) {
	field, err := core.NewField(big.NewInt(2013265921))
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	omega := field.NewElementFromInt64(7)

	t.Run("FRI_With_Different_Rates", func(t *testing.T) {
		rates := []int64{2, 4, 8}

		for _, r := range rates {
			rateElem := field.NewElementFromInt64(r)
			fri := NewFRIProtocol(field, rateElem, omega)

			if fri == nil {
				t.Errorf("FRI protocol is nil for rate %d", r)
			}
		}
	})
}
