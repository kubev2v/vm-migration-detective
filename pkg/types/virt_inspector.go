package types

// VirtInspectorXML represents the XML structure returned by virt-inspector
type VirtInspectorXML struct {
	Operatingsystems []VirtInspectorOS `xml:"operatingsystem" json:"operatingsystems"`
}

// VirtInspectorOS represents an operating system entry in virt-inspector XML
type VirtInspectorOS struct {
	Name              string                    `xml:"name" json:"name"`
	Distro            string                    `xml:"distro" json:"distro"`
	MajorVersion      string                    `xml:"major_version" json:"major_version"`
	MinorVersion      string                    `xml:"minor_version" json:"minor_version"`
	Architecture      string                    `xml:"arch" json:"architecture"`
	Hostname          string                    `xml:"hostname" json:"hostname,omitempty"`
	Product           string                    `xml:"product_name" json:"product,omitempty"`
	Root              string                    `xml:"root" json:"root,omitempty"`
	PackageFormat     string                    `xml:"package_format" json:"package_format,omitempty"`
	PackageManagement string                    `xml:"package_management" json:"package_management,omitempty"`
	OSInfo            string                    `xml:"osinfo" json:"osinfo,omitempty"`
	Applications      VirtInspectorApplications `xml:"applications" json:"applications,omitempty"`
	Filesystems       VirtInspectorFilesystems  `xml:"filesystems" json:"filesystems,omitempty"`
	Mountpoints       VirtInspectorMountpoints  `xml:"mountpoints" json:"mountpoints,omitempty"`
	Drives            VirtInspectorDrives       `xml:"drives" json:"drives,omitempty"`
	StartupServices   VirtInspectorStartupServices `xml:"startup_services" json:"startup_services,omitempty"`
}

// VirtInspectorApplications represents the applications section
type VirtInspectorApplications struct {
	Application []VirtInspectorApplication `xml:"application" json:"applications"`
}

// VirtInspectorApplication represents an installed application
type VirtInspectorApplication struct {
	Name        string `xml:"name" json:"name"`
	Version     string `xml:"version" json:"version,omitempty"`
	Epoch       int    `xml:"epoch" json:"epoch,omitempty"`
	Release     string `xml:"release" json:"release,omitempty"`
	Arch        string `xml:"arch" json:"arch,omitempty"`
	URL         string `xml:"url" json:"url,omitempty"`
	Summary     string `xml:"summary" json:"summary,omitempty"`
	Description string `xml:"description" json:"description,omitempty"`
}

// VirtInspectorFilesystems represents the filesystems section
type VirtInspectorFilesystems struct {
	Filesystem []VirtInspectorFilesystem `xml:"filesystem" json:"filesystems"`
}

// VirtInspectorFilesystem represents a filesystem
type VirtInspectorFilesystem struct {
	Device string `xml:"dev,attr" json:"device"`
	Type   string `xml:"type" json:"type"`
	UUID   string `xml:"uuid" json:"uuid,omitempty"`
}

// VirtInspectorMountpoints represents the mountpoints section
type VirtInspectorMountpoints struct {
	Mountpoint []VirtInspectorMountpoint `xml:"mountpoint" json:"mountpoints"`
}

// VirtInspectorMountpoint represents a mountpoint
type VirtInspectorMountpoint struct {
	Device     string `xml:"dev,attr" json:"device"`
	MountPoint string `xml:",chardata" json:"mount_point"`
}

// VirtInspectorDrives represents the drives section
type VirtInspectorDrives struct {
	Drive []VirtInspectorDrive `xml:"drive" json:"drives"`
}

// VirtInspectorDrive represents a drive
type VirtInspectorDrive struct {
	Name string `xml:"name,attr" json:"name"`
}
