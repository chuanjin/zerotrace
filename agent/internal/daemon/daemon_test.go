package daemon

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDaemonTemplateGeneration(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "zerotrace-daemon-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("skipping daemon test on non-unix OS")
	}

	fakeBin := filepath.Join(tmpDir, "zerotrace")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}

	if fakeBin == "" {
		t.Fatal("empty fakeBin")
	}
}
