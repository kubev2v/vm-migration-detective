package types

// VirtInspectorStartupServices represents startup services detected in the VM
type VirtInspectorStartupServices struct {
	SystemdServices []StartupService `xml:"systemd_service" json:"systemd_services,omitempty"`
	SysVServices    []StartupService `xml:"sysv_service" json:"sysv_services,omitempty"`
	CronJobs        []StartupCronJob `xml:"cron_job" json:"cron_jobs,omitempty"`
	BootScripts     []StartupScript  `xml:"boot_script" json:"boot_scripts,omitempty"`
}

// StartupService represents a system service that starts with the OS
type StartupService struct {
	Name        string `xml:"name" json:"name"`
	Type        string `xml:"type" json:"type"`         // "systemd", "sysvinit"
	Status      string `xml:"status" json:"status"`     // "enabled", "disabled", "unknown", "masked"
	Path        string `xml:"path" json:"path"`         // File path where found
	Description string `xml:"description" json:"description,omitempty"`
	Runlevels   []int  `xml:"runlevels" json:"runlevels,omitempty"` // SysV runlevels
	Priority    int    `xml:"priority" json:"priority,omitempty"`    // Start priority
}

// StartupCronJob represents a cron job that runs at boot time
type StartupCronJob struct {
	Schedule string `xml:"schedule" json:"schedule"` // "@reboot" or actual schedule
	Command  string `xml:"command" json:"command"`
	User     string `xml:"user" json:"user,omitempty"`
	Source   string `xml:"source" json:"source"` // File path where found
}

// StartupScript represents boot-time scripts like rc.local
type StartupScript struct {
	Name string `xml:"name" json:"name"`
	Path string `xml:"path" json:"path"`
	Type string `xml:"type" json:"type"` // "rc.local", "profile", etc.
}