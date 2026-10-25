package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

const systemdServiceName = "zerotrace.service"
const launchdPlistName = "eu.zerotrace.agent.plist"

// Install registers and starts ZeroTrace as a user-level service (systemd on Linux, launchd on macOS).
func Install(binPath string) (string, error) {
	if binPath == "" {
		var err error
		binPath, err = os.Executable()
		if err != nil {
			return "", fmt.Errorf("failed to determine executable path: %w", err)
		}
	}
	binPath, err := filepath.EvalSymlinks(binPath)
	if err != nil {
		return "", err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	switch runtime.GOOS {
	case "linux":
		unitDir := filepath.Join(home, ".config", "systemd", "user")
		if err := os.MkdirAll(unitDir, 0755); err != nil {
			return "", err
		}
		unitPath := filepath.Join(unitDir, systemdServiceName)
		unitContent := fmt.Sprintf(`[Unit]
Description=ZeroTrace AI & Cloud FinOps Proxy Daemon
After=network.target

[Service]
ExecStart=%s serve
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
`, binPath)
		if err := os.WriteFile(unitPath, []byte(unitContent), 0644); err != nil {
			return "", err
		}
		_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
		if err := exec.Command("systemctl", "--user", "enable", "--now", systemdServiceName).Run(); err != nil {
			return unitPath, fmt.Errorf("failed to enable systemd unit: %w", err)
		}
		return unitPath, nil

	case "darwin":
		agentsDir := filepath.Join(home, "Library", "LaunchAgents")
		if err := os.MkdirAll(agentsDir, 0755); err != nil {
			return "", err
		}
		plistPath := filepath.Join(agentsDir, launchdPlistName)
		plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>eu.zerotrace.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>serve</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/tmp/zerotrace.err</string>
    <key>StandardOutPath</key>
    <string>/tmp/zerotrace.out</string>
</dict>
</plist>
`, binPath)
		if err := os.WriteFile(plistPath, []byte(plistContent), 0644); err != nil {
			return "", err
		}
		_ = exec.Command("launchctl", "unload", plistPath).Run()
		if err := exec.Command("launchctl", "load", "-w", plistPath).Run(); err != nil {
			return plistPath, fmt.Errorf("failed to load launchd agent: %w", err)
		}
		return plistPath, nil

	default:
		return "", fmt.Errorf("unsupported OS for daemon install: %s", runtime.GOOS)
	}
}

// Uninstall stops and removes the user-level background service.
func Uninstall() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	switch runtime.GOOS {
	case "linux":
		_ = exec.Command("systemctl", "--user", "stop", systemdServiceName).Run()
		_ = exec.Command("systemctl", "--user", "disable", systemdServiceName).Run()
		unitPath := filepath.Join(home, ".config", "systemd", "user", systemdServiceName)
		if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
			return unitPath, err
		}
		_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
		return unitPath, nil

	case "darwin":
		plistPath := filepath.Join(home, "Library", "LaunchAgents", launchdPlistName)
		_ = exec.Command("launchctl", "unload", plistPath).Run()
		if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
			return plistPath, err
		}
		return plistPath, nil

	default:
		return "", fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}
