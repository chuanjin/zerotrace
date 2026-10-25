package hook

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	markerStart = "# >>> zerotrace hook initialize >>>"
	markerEnd   = "# <<< zerotrace hook initialize <<<"
)

// BuildBlock generates the idempotent shell export block for a given listen address.
func BuildBlock(listenAddr string) string {
	return fmt.Sprintf(`%s
export ANTHROPIC_BASE_URL="http://%s/anthropic"
export OPENAI_BASE_URL="http://%s/openai"
%s`, markerStart, listenAddr, listenAddr, markerEnd)
}

// InjectIntoContent inserts or replaces the ZeroTrace hook block inside a profile file's content.
func InjectIntoContent(existing, listenAddr string) string {
	cleaned := RemoveFromContent(existing)
	cleaned = strings.TrimRight(cleaned, "\n")
	block := BuildBlock(listenAddr)
	if cleaned == "" {
		return block + "\n"
	}
	return cleaned + "\n\n" + block + "\n"
}

// RemoveFromContent cleanly strips the ZeroTrace hook block from a profile file's content.
func RemoveFromContent(existing string) string {
	startIdx := strings.Index(existing, markerStart)
	if startIdx == -1 {
		return existing
	}
	endIdx := strings.Index(existing[startIdx:], markerEnd)
	if endIdx == -1 {
		return existing
	}
	endPos := startIdx + endIdx + len(markerEnd)
	// Also strip trailing newline if present
	if endPos < len(existing) && existing[endPos] == '\n' {
		endPos++
	}
	// Strip one preceding newline if we added a blank line before the block
	if startIdx > 0 && existing[startIdx-1] == '\n' {
		startIdx--
	}
	return existing[:startIdx] + existing[endPos:]
}

func targetShellFiles(homeDir string) []string {
	candidates := []string{".zshrc", ".bashrc"}
	var targets []string
	for _, name := range candidates {
		p := filepath.Join(homeDir, name)
		if _, err := os.Stat(p); err == nil {
			targets = append(targets, p)
		}
	}
	if len(targets) == 0 {
		targets = append(targets, filepath.Join(homeDir, ".zshrc"))
	}
	return targets
}

// Install injects the ZeroTrace proxy environment exports into the user's shell profiles.
func Install(homeDir, listenAddr string) ([]string, error) {
	if homeDir == "" {
		var err error
		homeDir, err = os.UserHomeDir()
		if err != nil {
			return nil, err
		}
	}
	files := targetShellFiles(homeDir)
	var updated []string
	for _, path := range files {
		raw, _ := os.ReadFile(path)
		next := InjectIntoContent(string(raw), listenAddr)
		if err := os.WriteFile(path, []byte(next), 0644); err != nil {
			return updated, err
		}
		updated = append(updated, path)
	}
	return updated, nil
}

// Uninstall removes the ZeroTrace proxy environment exports from the user's shell profiles.
func Uninstall(homeDir string) ([]string, error) {
	if homeDir == "" {
		var err error
		homeDir, err = os.UserHomeDir()
		if err != nil {
			return nil, err
		}
	}
	files := targetShellFiles(homeDir)
	var cleaned []string
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		orig := string(raw)
		next := RemoveFromContent(orig)
		if next != orig {
			if err := os.WriteFile(path, []byte(next), 0644); err != nil {
				return cleaned, err
			}
			cleaned = append(cleaned, path)
		}
	}
	return cleaned, nil
}
