package startup

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kubev2v/vm-migration-detective/pkg/types"
	"github.com/sirupsen/logrus"
)

// Logger interface for logging
type Logger interface {
	Errorf(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Debugf(format string, args ...interface{})
	WithError(err error) *logrus.Entry
	WithField(key string, value interface{}) *logrus.Entry
	WithFields(fields logrus.Fields) *logrus.Entry
}

// GuestfsInterface defines the interface for filesystem operations on VM snapshots
type GuestfsInterface interface {
	ReadFile(path string) ([]byte, error)
	ListDir(path string) ([]string, error)
	Exists(path string) bool
	IsDir(path string) bool
	ReadLink(path string) (string, error)
	IsSymlink(path string) bool
}

// StartupAnalyzer handles analysis of startup services in VM snapshots
type StartupAnalyzer struct {
	guestfs GuestfsInterface
	logger  Logger
}

// NewStartupAnalyzer creates a new StartupAnalyzer instance
func NewStartupAnalyzer(guestfs GuestfsInterface, logger Logger) *StartupAnalyzer {
	return &StartupAnalyzer{
		guestfs: guestfs,
		logger:  logger,
	}
}

// AnalyzeStartupServices analyzes all startup services in the VM snapshot
func (s *StartupAnalyzer) AnalyzeStartupServices(ctx context.Context) (*types.VirtInspectorStartupServices, error) {
	services := &types.VirtInspectorStartupServices{}

	// Use channels to analyze different service types in parallel
	systemdCh := make(chan []types.StartupService, 1)
	sysvCh := make(chan []types.StartupService, 1)
	cronCh := make(chan []types.StartupCronJob, 1)
	scriptsCh := make(chan []types.StartupScript, 1)

	// Start parallel analysis
	go s.analyzeSystemdServices(systemdCh)
	go s.analyzeSysVServices(sysvCh)
	go s.analyzeCronJobs(cronCh)
	go s.analyzeBootScripts(scriptsCh)

	// Collect results
	services.SystemdServices = <-systemdCh
	services.SysVServices = <-sysvCh
	services.CronJobs = <-cronCh
	services.BootScripts = <-scriptsCh

	return services, nil
}

// analyzeSystemdServices discovers and analyzes systemd services
func (s *StartupAnalyzer) analyzeSystemdServices(resultCh chan<- []types.StartupService) {
	defer close(resultCh)

	var services []types.StartupService
	systemdPaths := []string{
		"/etc/systemd/system/",
		"/lib/systemd/system/",
		"/usr/lib/systemd/system/",
	}

	for _, basePath := range systemdPaths {
		if !s.guestfs.Exists(basePath) {
			continue
		}

		files, err := s.guestfs.ListDir(basePath)
		if err != nil {
			s.logger.Errorf("Failed to list %s: %v", basePath, err)
			continue
		}

		for _, file := range files {
			if !strings.HasSuffix(file, ".service") || file == "." || file == ".." {
				continue
			}

			fullPath := filepath.Join(basePath, file)
			service, err := s.parseSystemdUnit(fullPath)
			if err != nil {
				s.logger.Warnf("Failed to parse systemd unit %s: %v", fullPath, err)
				continue
			}

			// Check if enabled by looking for symlinks in target directories
			service.Status = s.getSystemdServiceStatus(service.Name)
			services = append(services, service)
		}
	}

	resultCh <- services
}

// parseSystemdUnit parses a systemd unit file
func (s *StartupAnalyzer) parseSystemdUnit(unitPath string) (types.StartupService, error) {
	content, err := s.guestfs.ReadFile(unitPath)
	if err != nil {
		return types.StartupService{}, err
	}

	service := types.StartupService{
		Name: strings.TrimSuffix(filepath.Base(unitPath), ".service"),
		Type: "systemd",
		Path: unitPath,
	}

	// Parse INI-style unit file
	lines := strings.Split(string(content), "\n")
	inUnitSection := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "[Unit]" {
			inUnitSection = true
			continue
		} else if strings.HasPrefix(line, "[") {
			inUnitSection = false
			continue
		}

		if inUnitSection && strings.HasPrefix(line, "Description=") {
			service.Description = strings.TrimPrefix(line, "Description=")
		}
	}

	return service, nil
}

// getSystemdServiceStatus determines if a systemd service is enabled
func (s *StartupAnalyzer) getSystemdServiceStatus(serviceName string) string {
	// Check common target directories for enable symlinks
	targetDirs := []string{
		"/etc/systemd/system/multi-user.target.wants/",
		"/etc/systemd/system/default.target.wants/",
		"/etc/systemd/system/graphical.target.wants/",
		"/etc/systemd/system/sysinit.target.wants/",
		"/etc/systemd/system/basic.target.wants/",
	}

	serviceFile := serviceName + ".service"

	for _, targetDir := range targetDirs {
		if !s.guestfs.Exists(targetDir) {
			continue
		}
		linkPath := filepath.Join(targetDir, serviceFile)
		if s.guestfs.IsSymlink(linkPath) {
			return "enabled"
		}
	}

	// Check for masked services (symlink to /dev/null)
	maskPath := "/etc/systemd/system/" + serviceFile
	if s.guestfs.IsSymlink(maskPath) {
		if target, err := s.guestfs.ReadLink(maskPath); err == nil && target == "/dev/null" {
			return "masked"
		}
	}

	return "unknown"
}

// analyzeSysVServices discovers and analyzes SysV init services
func (s *StartupAnalyzer) analyzeSysVServices(resultCh chan<- []types.StartupService) {
	defer close(resultCh)

	var services []types.StartupService

	// First, scan /etc/init.d/ for available scripts
	initdPath := "/etc/init.d/"
	if !s.guestfs.Exists(initdPath) {
		resultCh <- services
		return
	}

	scripts, err := s.guestfs.ListDir(initdPath)
	if err != nil {
		s.logger.Errorf("Failed to list %s: %v", initdPath, err)
		resultCh <- services
		return
	}

	for _, script := range scripts {
		// Skip common non-service files
		if script == "." || script == ".." || script == "README" || script == "skeleton" {
			continue
		}

		scriptPath := filepath.Join(initdPath, script)
		service, err := s.parseSysVScript(scriptPath)
		if err != nil {
			s.logger.Warnf("Failed to parse SysV script %s: %v", scriptPath, err)
			continue
		}

		// Check runlevel directories for enable status
		service.Runlevels, service.Status, service.Priority = s.getSysVServiceStatus(script)
		services = append(services, service)
	}

	resultCh <- services
}

// parseSysVScript parses a SysV init script
func (s *StartupAnalyzer) parseSysVScript(scriptPath string) (types.StartupService, error) {
	content, err := s.guestfs.ReadFile(scriptPath)
	if err != nil {
		return types.StartupService{}, err
	}

	service := types.StartupService{
		Name: filepath.Base(scriptPath),
		Type: "sysvinit",
		Path: scriptPath,
	}

	// Parse LSB headers for metadata
	lines := strings.Split(string(content), "\n")
	inLSBBlock := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.Contains(line, "### BEGIN INIT INFO") {
			inLSBBlock = true
			continue
		} else if strings.Contains(line, "### END INIT INFO") {
			break
		}

		if inLSBBlock {
			if strings.HasPrefix(line, "# Short-Description:") {
				service.Description = strings.TrimSpace(strings.TrimPrefix(line, "# Short-Description:"))
			} else if strings.HasPrefix(line, "# Description:") && service.Description == "" {
				service.Description = strings.TrimSpace(strings.TrimPrefix(line, "# Description:"))
			}
		}
	}

	return service, nil
}

// getSysVServiceStatus determines the status of a SysV service
func (s *StartupAnalyzer) getSysVServiceStatus(scriptName string) ([]int, string, int) {
	var runlevels []int
	status := "unknown"
	priority := 0

	// Check /etc/rc*.d/ directories for symlinks
	for runlevel := 0; runlevel <= 6; runlevel++ {
		rcDir := "/etc/rc" + strconv.Itoa(runlevel) + ".d/"
		if !s.guestfs.Exists(rcDir) {
			continue
		}

		links, err := s.guestfs.ListDir(rcDir)
		if err != nil {
			continue
		}

		for _, link := range links {
			if strings.HasPrefix(link, "S") && strings.Contains(link, scriptName) {
				// Found start link (S##scriptname)
				runlevels = append(runlevels, runlevel)
				status = "enabled"

				// Extract priority from S##
				if len(link) >= 3 {
					if p, err := strconv.Atoi(link[1:3]); err == nil {
						priority = p
					}
				}
			}
		}
	}

	if len(runlevels) == 0 {
		// Check if any K links exist (disabled but present)
		for runlevel := 0; runlevel <= 6; runlevel++ {
			rcDir := "/etc/rc" + strconv.Itoa(runlevel) + ".d/"
			if !s.guestfs.Exists(rcDir) {
				continue
			}

			links, err := s.guestfs.ListDir(rcDir)
			if err != nil {
				continue
			}

			for _, link := range links {
				if strings.HasPrefix(link, "K") && strings.Contains(link, scriptName) {
					status = "disabled"
					break
				}
			}
			if status == "disabled" {
				break
			}
		}
	}

	return runlevels, status, priority
}

// analyzeCronJobs discovers cron jobs that run at boot time
func (s *StartupAnalyzer) analyzeCronJobs(resultCh chan<- []types.StartupCronJob) {
	defer close(resultCh)

	var cronJobs []types.StartupCronJob

	// System-wide cron sources
	cronSources := []struct {
		path string
		user string
	}{
		{"/etc/crontab", "root"},
		{"/etc/anacrontab", "root"},
	}

	// Scan /etc/cron.d/ directory
	cronDPath := "/etc/cron.d/"
	if s.guestfs.Exists(cronDPath) {
		files, err := s.guestfs.ListDir(cronDPath)
		if err == nil {
			for _, file := range files {
				if file != "." && file != ".." {
					cronSources = append(cronSources, struct {
						path string
						user string
					}{filepath.Join(cronDPath, file), "various"})
				}
			}
		}
	}

	// Parse each cron source
	for _, source := range cronSources {
		if !s.guestfs.Exists(source.path) {
			continue
		}

		jobs, err := s.parseCronFile(source.path, source.user)
		if err != nil {
			s.logger.Warnf("Failed to parse cron file %s: %v", source.path, err)
			continue
		}

		cronJobs = append(cronJobs, jobs...)
	}

	resultCh <- cronJobs
}

// parseCronFile parses a cron file for boot-time entries
func (s *StartupAnalyzer) parseCronFile(cronPath, defaultUser string) ([]types.StartupCronJob, error) {
	content, err := s.guestfs.ReadFile(cronPath)
	if err != nil {
		return nil, err
	}

	var jobs []types.StartupCronJob
	lines := strings.Split(string(content), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse cron line - handle both system crontab (with user) and user crontab formats
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		// Check for @reboot entries (boot-time execution)
		if fields[0] == "@reboot" {
			user := defaultUser
			command := strings.Join(fields[1:], " ")

			// If this is a system crontab, second field might be username
			if cronPath == "/etc/crontab" || strings.HasPrefix(cronPath, "/etc/cron.d/") {
				if len(fields) >= 7 {
					user = fields[1]
					command = strings.Join(fields[2:], " ")
				}
			}

			jobs = append(jobs, types.StartupCronJob{
				Schedule: "@reboot",
				Command:  command,
				User:     user,
				Source:   cronPath,
			})
			continue
		}

		// Check for special schedule entries
		if len(fields) >= 6 {
			if strings.HasPrefix(fields[0], "@") {
				schedule := fields[0]
				user := defaultUser
				command := strings.Join(fields[1:], " ")

				if cronPath == "/etc/crontab" || strings.HasPrefix(cronPath, "/etc/cron.d/") {
					if len(fields) >= 7 {
						user = fields[1]
						command = strings.Join(fields[2:], " ")
					}
				}

				jobs = append(jobs, types.StartupCronJob{
					Schedule: schedule,
					Command:  command,
					User:     user,
					Source:   cronPath,
				})
			}
		}
	}

	return jobs, nil
}

// analyzeBootScripts discovers boot-time scripts
func (s *StartupAnalyzer) analyzeBootScripts(resultCh chan<- []types.StartupScript) {
	defer close(resultCh)

	var scripts []types.StartupScript

	// Common boot script locations
	bootScriptPaths := []struct {
		path       string
		name       string
		scriptType string
	}{
		{"/etc/rc.local", "rc.local", "rc.local"},
		{"/etc/rc.d/rc.local", "rc.local", "rc.local"},
		{"/etc/init.d/rc.local", "rc.local", "rc.local"},
		{"/etc/profile", "profile", "profile"},
		{"/etc/bash.bashrc", "bash.bashrc", "profile"},
		{"/etc/bashrc", "bashrc", "profile"},
	}

	for _, bootScript := range bootScriptPaths {
		if !s.guestfs.Exists(bootScript.path) {
			continue
		}

		// Check if script is executable (for rc.local)
		if bootScript.scriptType == "rc.local" {
			content, err := s.guestfs.ReadFile(bootScript.path)
			if err != nil {
				continue
			}

			// Parse script content to see if it has actual commands
			if s.hasExecutableContent(string(content)) {
				scripts = append(scripts, types.StartupScript{
					Name: bootScript.name,
					Path: bootScript.path,
					Type: bootScript.scriptType,
				})
			}
		} else {
			// Profile scripts always included if they exist
			scripts = append(scripts, types.StartupScript{
				Name: bootScript.name,
				Path: bootScript.path,
				Type: bootScript.scriptType,
			})
		}
	}

	resultCh <- scripts
}

// hasExecutableContent checks if a script has meaningful executable content
func (s *StartupAnalyzer) hasExecutableContent(content string) bool {
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip comments, empty lines, and shebang
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip common non-executable patterns
		if strings.HasPrefix(line, "exit 0") || line == "exit" {
			continue
		}

		// If we find any other content, consider it executable
		return true
	}

	return false
}