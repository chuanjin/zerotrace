package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStorageAuditChainIntegrityAndTampering(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "zerotrace-storage-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	accountID := "1234 5678 9012 3456"
	e2eeKeyHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	store, err := New(tmpDir, accountID, e2eeKeyHex)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Append 5 authentic events
	for i := 1; i <= 5; i++ {
		ev := AuditEvent{
			SessionID:        fmt.Sprintf("session-%d", i),
			Provider:         "anthropic",
			Model:            "claude-3-7-sonnet",
			Repo:             "my-org/core-backend",
			TokensIn:         100 * i,
			TokensCacheRead:  50 * i,
			TokensCacheWrite: 20 * i,
			TokensOut:        80 * i,
			CostUSD:          0.005 * float64(i),
			SavedUSD:         0.0,
			CacheWastedUSD:   0.001 * float64(i),
			CacheChurnAlert:  false,
			LatencyMs:        int64(150 * i),
			Status:           "OK",
			PIIRedactions:    2,
			PIICategories: map[string]int{
				"EMAIL":           1,
				"SE_PERSONNUMMER": 1,
			},
		}
		rawPrompt := fmt.Sprintf("Analyze sensitive prompt chunk #%d", i)
		_, err := store.Append(ev, rawPrompt)
		if err != nil {
			t.Fatalf("failed to append event %d: %v", i, err)
		}
	}

	// 2. Verify clean authentic audit chain
	count, head, err := VerifyAuditChain(tmpDir)
	if err != nil {
		t.Fatalf("expected audit chain to verify cleanly, got error: %v", err)
	}
	if count != 5 {
		t.Fatalf("expected 5 verified records, got %d", count)
	}
	if head == "" {
		t.Fatal("expected non-empty head hash")
	}

	// Helper to load, modify, and re-verify JSONL
	day := time.Now().UTC().Format("2006-01-02")
	logPath := filepath.Join(tmpDir, fmt.Sprintf("audit-%s.jsonl", day))
	originalJSONL, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}

	readEvents := func(content string) []AuditEvent {
		var list []AuditEvent
		for _, line := range splitNonEmptyLines(content) {
			var ev AuditEvent
			_ = json.Unmarshal([]byte(line), &ev)
			list = append(list, ev)
		}
		return list
	}

	writeEvents := func(events []AuditEvent) {
		var sb strings.Builder
		for _, ev := range events {
			b, _ := json.Marshal(ev)
			sb.Write(b)
			sb.WriteByte('\n')
		}
		_ = os.WriteFile(logPath, []byte(sb.String()), 0600)
	}

	// 3. Test Tampering: Alter EncryptedPayload (prompt tampering)
	events := readEvents(string(originalJSONL))
	events[2].EncryptedPayload = store.EncryptPayload("Tampered prompt payload injection")
	writeEvents(events)
	_, _, err = VerifyAuditChain(tmpDir)
	if err == nil || !strings.Contains(err.Error(), "tampered record at seq 3: hash mismatch") {
		t.Fatalf("expected tampering error for modified payload, got: %v", err)
	}

	// 4. Test Tampering: Alter CostUSD
	events = readEvents(string(originalJSONL))
	events[1].CostUSD = 0.000001
	writeEvents(events)
	_, _, err = VerifyAuditChain(tmpDir)
	if err == nil || !strings.Contains(err.Error(), "tampered record at seq 2: hash mismatch") {
		t.Fatalf("expected tampering error for modified CostUSD, got: %v", err)
	}

	// 5. Test Tampering: Alter Repo metadata
	events = readEvents(string(originalJSONL))
	events[0].Repo = "hacker/fake-repo"
	writeEvents(events)
	_, _, err = VerifyAuditChain(tmpDir)
	if err == nil || !strings.Contains(err.Error(), "tampered record at seq 1: hash mismatch") {
		t.Fatalf("expected tampering error for modified Repo, got: %v", err)
	}

	// 6. Test Tampering: Alter PIICategories
	events = readEvents(string(originalJSONL))
	events[3].PIICategories = map[string]int{"EMAIL": 0}
	writeEvents(events)
	_, _, err = VerifyAuditChain(tmpDir)
	if err == nil || !strings.Contains(err.Error(), "tampered record at seq 4: hash mismatch") {
		t.Fatalf("expected tampering error for modified PIICategories, got: %v", err)
	}

	// 7. Test Tampering: Delete a middle record
	events = readEvents(string(originalJSONL))
	deletedMiddle := append(events[:2], events[3:]...)
	writeEvents(deletedMiddle)
	_, _, err = VerifyAuditChain(tmpDir)
	if err == nil || !strings.Contains(err.Error(), "chain broken at seq 4") {
		t.Fatalf("expected chain broken error for deleted record, got: %v", err)
	}

	// 8. Test Tampering: Reorder records (swap 1 and 2)
	events = readEvents(string(originalJSONL))
	events[0], events[1] = events[1], events[0]
	writeEvents(events)
	_, _, err = VerifyAuditChain(tmpDir)
	if err == nil || !strings.Contains(err.Error(), "chain broken") {
		t.Fatalf("expected chain broken error for reordered records, got: %v", err)
	}

	// 9. Test Tampering: Insert foreign record
	events = readEvents(string(originalJSONL))
	inserted := append([]AuditEvent{events[0]}, append([]AuditEvent{events[0]}, events[1:]...)...)
	writeEvents(inserted)
	_, _, err = VerifyAuditChain(tmpDir)
	if err == nil || !strings.Contains(err.Error(), "chain broken") {
		t.Fatalf("expected chain broken error for inserted duplicate record, got: %v", err)
	}

	// Restore original file and verify it's clean again
	_ = os.WriteFile(logPath, originalJSONL, 0600)
	countFinal, _, err := VerifyAuditChain(tmpDir)
	if err != nil || countFinal != 5 {
		t.Fatalf("restored chain failed to verify: count=%d, err=%v", countFinal, err)
	}
}
