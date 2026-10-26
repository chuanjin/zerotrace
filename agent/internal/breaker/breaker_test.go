package breaker

import (
	"math"
	"testing"
)

func almostEqual(a, b float64) bool {
	return math.Abs(a-b) < 1e-6
}

func TestBreakerBudgetReservationAndReconciliation(t *testing.T) {
	// Session max: $1.00, Daily max: $5.00, Max retries: 3
	b := New(1.00, 5.00, 3)
	sessionID := "test-sess-recon"

	// 1. Initial pre-call reservation ($0.10)
	res1 := b.EvaluatePreCall(sessionID, "prompt 1", 0.10)
	if !res1.Allowed || !almostEqual(res1.SessionCost, 0.10) {
		t.Fatalf("expected call 1 to be allowed with cost 0.10, got allowed=%v, cost=%f", res1.Allowed, res1.SessionCost)
	}

	// 2. Settle with higher actual cost ($0.25 actual vs $0.10 estimated)
	b.SettlePostCall(sessionID, 0.10, 0.25)
	if st := b.sessions[sessionID]; !almostEqual(st.TotalCostUSD, 0.25) {
		t.Fatalf("expected settled session cost 0.25, got %f", st.TotalCostUSD)
	}

	// 3. Second call reservation ($0.20), but upstream failed (e.g. 500 error)
	res2 := b.EvaluatePreCall(sessionID, "prompt 2", 0.20)
	if !res2.Allowed || !almostEqual(res2.SessionCost, 0.45) {
		t.Fatalf("expected cost 0.45 after reservation, got %f", res2.SessionCost)
	}
	// Release on error
	b.ReleasePreCall(sessionID, 0.20)
	if st := b.sessions[sessionID]; !almostEqual(st.TotalCostUSD, 0.25) {
		t.Fatalf("expected restored cost 0.25 after release, got %f", st.TotalCostUSD)
	}

	// 4. Third call reservation ($0.30) settles lower ($0.10 actual vs $0.30 estimated)
	res3 := b.EvaluatePreCall(sessionID, "prompt 3", 0.30)
	if !res3.Allowed {
		t.Fatal("expected call 3 to be allowed")
	}
	b.SettlePostCall(sessionID, 0.30, 0.10)
	if st := b.sessions[sessionID]; !almostEqual(st.TotalCostUSD, 0.35) {
		t.Fatalf("expected settled session cost 0.35, got %f", st.TotalCostUSD)
	}

	// 5. Trip Session Budget when trying to reserve more than remaining ($0.70 when limit is $1.00)
	res4 := b.EvaluatePreCall(sessionID, "prompt 4", 0.70)
	if res4.Allowed || res4.Code != "SESSION_BUDGET_EXCEEDED" {
		t.Fatalf("expected SESSION_BUDGET_EXCEEDED, got allowed=%v, code=%s", res4.Allowed, res4.Code)
	}
}

func TestBreakerDoomLoopDetection(t *testing.T) {
	b := New(10.0, 50.0, 2) // Trip on 3rd identical attempt
	sessionID := "test-sess-loop"
	payload := `{"error": "file not found: config.yaml"}`

	res1 := b.EvaluatePreCall(sessionID, payload, 0.01)
	if !res1.Allowed || res1.IdenticalHits != 1 {
		t.Fatalf("turn 1 failed: allowed=%v hits=%d", res1.Allowed, res1.IdenticalHits)
	}

	res2 := b.EvaluatePreCall(sessionID, payload, 0.01)
	if !res2.Allowed || res2.IdenticalHits != 2 {
		t.Fatalf("turn 2 failed: allowed=%v hits=%d", res2.Allowed, res2.IdenticalHits)
	}

	res3 := b.EvaluatePreCall(sessionID, payload, 0.01)
	if res3.Allowed || res3.Code != "DOOM_LOOP_DETECTED" {
		t.Fatalf("turn 3 should trip DOOM_LOOP_DETECTED, got allowed=%v code=%s", res3.Allowed, res3.Code)
	}
}
