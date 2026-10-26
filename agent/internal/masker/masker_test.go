package masker

import (
	"fmt"
	"strings"
	"testing"
)

func TestMaskerIBANFormats(t *testing.T) {
	m := New("test-secret-salt-12345")

	tests := []struct {
		name     string
		rawIBAN  string
	}{
		{"Compact Swedish IBAN", "SE4550000000058398257466"},
		{"Space-formatted Swedish IBAN", "SE45 5000 0000 0583 9825 7466"},
		{"Space-formatted German IBAN", "DE89 3704 0044 0532 0130 00"},
		{"Compact German IBAN", "DE89370400440532013000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := fmt.Sprintf("Transfer 5000 SEK to account %s before EOD.", tt.rawIBAN)
			masked, stats := m.MaskOutbound(input)

			if stats.ByCategory["EU_IBAN"] != 1 {
				t.Fatalf("expected 1 EU_IBAN redaction, got %d", stats.ByCategory["EU_IBAN"])
			}
			if strings.Contains(masked, tt.rawIBAN) {
				t.Fatalf("raw IBAN leaked in masked output: %s", masked)
			}

			// Verify deterministic unmasking
			unmasked := m.UnmaskInbound(masked)
			if unmasked != input {
				t.Fatalf("unmasked mismatch!\nExpected: %s\nGot:      %s", input, unmasked)
			}
		})
	}
}

func TestMaskerPersonnummerFormats(t *testing.T) {
	m := New("test-secret-salt-12345")

	tests := []struct {
		name string
		pnr  string
	}{
		{"12-digit Personnummer", "19880412-5531"},
		{"12-digit 2000s Personnummer", "20050815-1234"},
		{"10-digit Personnummer", "880412-5531"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := fmt.Sprintf("Customer KYC record: Personnummer %s verified.", tt.pnr)
			masked, stats := m.MaskOutbound(input)

			if stats.ByCategory["SE_PERSONNUMMER"] != 1 {
				t.Fatalf("expected 1 SE_PERSONNUMMER redaction, got %d", stats.ByCategory["SE_PERSONNUMMER"])
			}
			if strings.Contains(masked, tt.pnr) {
				t.Fatalf("raw personnummer leaked in masked output: %s", masked)
			}

			unmasked := m.UnmaskInbound(masked)
			if unmasked != input {
				t.Fatalf("unmasked mismatch!\nExpected: %s\nGot:      %s", input, unmasked)
			}
		})
	}
}

func TestMaskerCollisionHandlingAndDeterminism(t *testing.T) {
	m := New("test-secret-salt-12345")

	// 1. Determinism: Same input produces the exact same pseudonym
	input1 := "User email: test.user@example.com, key: sk-ant-api03-abcdef1234567890"
	masked1, _ := m.MaskOutbound(input1)
	masked2, _ := m.MaskOutbound(input1)
	if masked1 != masked2 {
		t.Fatalf("masking is non-deterministic: %s != %s", masked1, masked2)
	}

	// 2. High volume to test collision-resistance and reverse map integrity
	var inputs []string
	for i := 0; i < 200; i++ {
		raw := fmt.Sprintf("Account %d: user_%d@company.se, PNR: 1980%02d01-%04d, IBAN: SE455000000005839825%04d",
			i, i, (i%12)+1, 1000+i, 1000+i)
		inputs = append(inputs, raw)
	}

	for _, raw := range inputs {
		masked, stats := m.MaskOutbound(raw)
		if stats.TotalRedactions != 3 {
			t.Fatalf("expected 3 redactions, got %d for %s", stats.TotalRedactions, raw)
		}
		unmasked := m.UnmaskInbound(masked)
		if unmasked != raw {
			t.Fatalf("collision or corruption in reverse mapping!\nExpected: %s\nGot:      %s", raw, unmasked)
		}
	}
}

func TestStreamUnmaskerCrossChunkBoundary(t *testing.T) {
	m := New("stream-secret-salt")
	rawEmail := "alice.bobsson@enterprise.se"
	rawIBAN := "SE45 5000 0000 0583 9825 7466"

	input := fmt.Sprintf("Pay to %s or contact %s immediately.", rawIBAN, rawEmail)
	masked, _ := m.MaskOutbound(input)

	// Stream through StreamUnmasker with 3-byte chunks to stress boundary conditions
	su := m.NewStreamUnmasker()
	var restored strings.Builder
	chunkSize := 3
	for i := 0; i < len(masked); i += chunkSize {
		end := i + chunkSize
		if end > len(masked) {
			end = len(masked)
		}
		chunk := masked[i:end]
		restored.WriteString(su.ProcessChunk(chunk))
	}
	restored.WriteString(su.Flush())

	if restored.String() != input {
		t.Fatalf("StreamUnmasker output mismatch!\nExpected: %s\nGot:      %s", input, restored.String())
	}
}
