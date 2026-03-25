package startup

import (
	"context"
	"testing"

	"github.com/kubev2v/vm-migration-detective/pkg/types"
)

// MockGuestfs implements GuestfsInterface for testing
type MockGuestfs struct {
	files       map[string][]byte
	directories map[string][]string
	symlinks    map[string]string
}

// NewMockGuestfs creates a new mock guestfs instance
func NewMockGuestfs() *MockGuestfs {
	return &MockGuestfs{
		files:       make(map[string][]byte),
		directories: make(map[string][]string),
		symlinks:    make(map[string]string),
	}
}

func (m *MockGuestfs) AddFile(path string, content []byte) {
	m.files[path] = content
}

func (m *MockGuestfs) AddDirectory(path string, files []string) {
	m.directories[path] = files
}

func (m *MockGuestfs) AddSymlink(path, target string) {
	m.symlinks[path] = target
}

func (m *MockGuestfs) ReadFile(path string) ([]byte, error) {
	if content, exists := m.files[path]; exists {
		return content, nil
	}
	return nil, &testError{msg: "file not found"}
}

func (m *MockGuestfs) ListDir(path string) ([]string, error) {
	if files, exists := m.directories[path]; exists {
		return files, nil
	}
	return nil, &testError{msg: "directory not found"}
}

func (m *MockGuestfs) Exists(path string) bool {
	_, existsFile := m.files[path]
	_, existsDir := m.directories[path]
	_, existsLink := m.symlinks[path]
	return existsFile || existsDir || existsLink
}

func (m *MockGuestfs) IsDir(path string) bool {
	_, exists := m.directories[path]
	return exists
}

func (m *MockGuestfs) ReadLink(path string) (string, error) {
	if target, exists := m.symlinks[path]; exists {
		return target, nil
	}
	return "", &testError{msg: "not a symlink"}
}

func (m *MockGuestfs) IsSymlink(path string) bool {
	_, exists := m.symlinks[path]
	return exists
}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

// MockLogger implements Logger interface for testing
type MockLogger struct{}

func (l *MockLogger) Errorf(format string, args ...interface{})                    {}
func (l *MockLogger) Warnf(format string, args ...interface{})                     {}
func (l *MockLogger) Infof(format string, args ...interface{})                     {}
func (l *MockLogger) Debugf(format string, args ...interface{})                    {}
func (l *MockLogger) WithError(err error) interface{ Warnf(string, ...interface{}) } { return l }
func (l *MockLogger) WithField(key string, value interface{}) interface{ Warnf(string, ...interface{}) } {
	return l
}
func (l *MockLogger) WithFields(fields interface{}) interface{ Warnf(string, ...interface{}) } {
	return l
}

func TestAnalyzeSystemdServices(t *testing.T) {
	mockGuestfs := NewMockGuestfs()
	mockLogger := &MockLogger{}

	// Setup mock systemd unit
	unitContent := `[Unit]
Description=OpenSSH server daemon
After=network.target sshd-keygen.service

[Service]
Type=notify
ExecStart=/usr/sbin/sshd -D $OPTIONS
ExecReload=/bin/kill -HUP $MAINPID

[Install]
WantedBy=multi-user.target
`
	mockGuestfs.AddFile("/etc/systemd/system/sshd.service", []byte(unitContent))
	mockGuestfs.AddDirectory("/etc/systemd/system/", []string{"sshd.service"})
	mockGuestfs.AddDirectory("/etc/systemd/system/multi-user.target.wants/", []string{"sshd.service"})
	mockGuestfs.AddSymlink("/etc/systemd/system/multi-user.target.wants/sshd.service", "/etc/systemd/system/sshd.service")

	analyzer := NewStartupAnalyzer(mockGuestfs, mockLogger)

	result := make(chan []types.StartupService, 1)
	go analyzer.analyzeSystemdServices(result)
	services := <-result

	if len(services) != 1 {
		t.Errorf("Expected 1 service, got %d", len(services))
	}

	service := services[0]
	if service.Name != "sshd" {
		t.Errorf("Expected service name 'sshd', got '%s'", service.Name)
	}
	if service.Type != "systemd" {
		t.Errorf("Expected service type 'systemd', got '%s'", service.Type)
	}
	if service.Status != "enabled" {
		t.Errorf("Expected service status 'enabled', got '%s'", service.Status)
	}
	if service.Description != "OpenSSH server daemon" {
		t.Errorf("Expected description 'OpenSSH server daemon', got '%s'", service.Description)
	}
}

func TestAnalyzeStartupServices(t *testing.T) {
	mockGuestfs := NewMockGuestfs()
	mockLogger := &MockLogger{}

	analyzer := NewStartupAnalyzer(mockGuestfs, mockLogger)

	result, err := analyzer.AnalyzeStartupServices(context.Background())
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if result == nil {
		t.Error("Expected non-nil result")
	}

	// Should return empty results for empty filesystem
	if len(result.SystemdServices) != 0 ||
		len(result.SysVServices) != 0 ||
		len(result.CronJobs) != 0 ||
		len(result.BootScripts) != 0 {
		t.Error("Expected empty results for empty filesystem")
	}
}