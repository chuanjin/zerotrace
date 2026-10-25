package hook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHookInstallAndUninstall(t *testing.T) {
	tmpHome, err := os.MkdirTemp("", "zerotrace-hook-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpHome)

	zshrc := filepath.Join(tmpHome, ".zshrc")
	origContent := "export PATH=\"$HOME/.local/bin:$PATH\"\nalias ll='ls -la'\n"
	if err := os.WriteFile(zshrc, []byte(origContent), 0644); err != nil {
		t.Fatal(err)
	}

	// 1. Install hook
	updated, err := Install(tmpHome, "127.0.0.1:9000")
	if err != nil || len(updated) != 1 {
		t.Fatalf("Install failed: %v (updated=%v)", err, updated)
	}

	afterInstall, _ := os.ReadFile(zshrc)
	if !strings.Contains(string(afterInstall), `export ANTHROPIC_BASE_URL="http://127.0.0.1:9000/anthropic"`) {
		t.Fatalf("zshrc missing ANTHROPIC_BASE_URL after install:\n%s", string(afterInstall))
	}

	// 2. Idempotent re-install (should not duplicate blocks)
	_, _ = Install(tmpHome, "127.0.0.1:9000")
	afterReinstall, _ := os.ReadFile(zshrc)
	if strings.Count(string(afterReinstall), "ANTHROPIC_BASE_URL") != 1 {
		t.Fatalf("expected exactly 1 ANTHROPIC_BASE_URL after re-install, got:\n%s", string(afterReinstall))
	}

	// 3. Clean uninstall restores original content
	cleaned, err := Uninstall(tmpHome)
	if err != nil || len(cleaned) != 1 {
		t.Fatalf("Uninstall failed: %v (cleaned=%v)", err, cleaned)
	}
	afterUninstall, _ := os.ReadFile(zshrc)
	if string(afterUninstall) != origContent {
		t.Errorf("expected exact restoration of original .zshrc.\nGot:\n%q\nWant:\n%q", string(afterUninstall), origContent)
	}
}
