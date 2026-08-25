package inspection

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/kubev2v/vm-migration-detective/internal/cmdbuilder"
	"github.com/kubev2v/vm-migration-detective/internal/vddk"
	"github.com/kubev2v/vm-migration-detective/internal/vsphere"
	"github.com/kubev2v/vm-migration-detective/pkg/types"
	"github.com/sirupsen/logrus"
)

// virtV2vProgressLine matches virt-v2v-inspector's own high-level phase markers,
// e.g. "[   0.0] Setting up the source: ..." — always a whole number of seconds
// plus exactly one decimal digit (tenths). This must NOT also match the guest's
// own kernel boot log lines that -v -x also passes through, which use the same
// "[ N.NNNNNN]" bracket style but with microsecond (6-digit) precision, e.g.
// "[    0.235524] DMA: preallocated ...". Matching those too would flood the
// agent log with hundreds of kernel dmesg lines per inspection.
var virtV2vProgressLine = regexp.MustCompile(`^\[\s*\d+\.\d\]`)

// VirtV2vInspector handles VM inspection operations using virt-v2v-inspector
type VirtV2vInspector struct {
	virtV2vInspectorPath string
	logger               *logrus.Logger
}

// NewVirtV2vInspector creates a new VirtV2vInspector instance. The process runs
// until its caller's context is cancelled.
func NewVirtV2vInspector(virtV2vInspectorPath string, logger *logrus.Logger) *VirtV2vInspector {
	if virtV2vInspectorPath == "" {
		virtV2vInspectorPath = "virt-v2v-inspector" // Use system PATH
	}
	return &VirtV2vInspector{
		virtV2vInspectorPath: virtV2vInspectorPath,
		logger:               logger,
	}
}

// Inspect uses virt-v2v-inspector to inspect a VM snapshot directly via VDDK
func (i *VirtV2vInspector) Inspect(
	ctx context.Context,
	vmMoref string,
	snapshotMoref string,
	vcenterURL string,
	username string,
	password string,
	diskInfo *types.SnapshotDiskInfo, // Snapshot disk info from vm_service
	sslVerify string, // SSL verification option for vpx:// URL (e.g., "no_verify=1" or "cacert=/path/to/ca-bundle.crt")
) (*types.VirtV2VInspectorXML, error) {
	i.logger.WithFields(logrus.Fields{
		"vm_moref":       vmMoref,
		"snapshot_moref": snapshotMoref,
		"vcenter_url":    vcenterURL,
	}).Info("Running virt-v2v-inspector on snapshot")

	// Build libvirt connection URL for vSphere
	// Format: vpx://username@vcenter/compute-resource-path?ssl-verify
	// The path must point to a compute resource (host/cluster), not the datacenter or VM
	// The VM name is specified as a positional argument after "--"
	// Username is in URL (needed by virt-v2v-inspector to pass to VDDK)
	// Password is provided via -ip file (secure)
	// Extract hostname from vCenter URL
	vcenterHost := extractHostname(vcenterURL)

	// URL-encode username to handle special characters like @
	// The @ symbol in the username needs to be percent-encoded as %40
	// because @ is used as a delimiter between username and hostname in URLs
	encodedUsername := url.QueryEscape(username)

	// Use the compute resource path from diskInfo (e.g., "/Datacenter/Cluster/host.example.com")
	// This is required for vpx:// URLs - they need a compute resource, not just a datacenter
	computeResourcePath := diskInfo.ComputeResourcePath
	if computeResourcePath == "" {
		return nil, fmt.Errorf("compute resource path is required for vpx:// URL")
	}

	// Build vpx:// URL with username
	// virt-v2v-inspector extracts the username from this URL to pass to VDDK internally
	// Password is kept secure in separate file via -ip parameter
	// Add SSL verification parameter (provided by caller)
	libvirtURL := fmt.Sprintf("vpx://%s@%s%s?%s",
		encodedUsername, bracketIPv6(vcenterHost), computeResourcePath, sslVerify)

	// Create a password file for VDDK authentication
	// VDDK uses -io vddk-password=+file to read password securely
	passwordFile, err := i.createPasswordFile(password)
	if err != nil {
		return nil, fmt.Errorf("failed to create password file: %w", err)
	}
	defer func() { _ = os.Remove(passwordFile) }()

	// Strip VDDK paths from LD_LIBRARY_PATH so libguestfs/supermin doesn't pick them up.
	thumbprint, err := getVCenterThumbprint(vcenterHost)
	if err != nil {
		i.logger.WithError(err).Warn("Failed to get thumbprint, proceeding without SSL verification")
	}
	vddkLibDir := vddk.GetLibDir()
	vddkLibPath := vddk.GetLibPath()

	diskUnlock := resolveDiskUnlock(i.logger)

	cmdArgs := cmdbuilder.New().
		WithLogger(i.logger).
		FilterEnv("LD_LIBRARY_PATH", func(val string) string {
			var kept []string
			for _, p := range strings.Split(val, ":") {
				if p != vddkLibPath && !strings.Contains(p, "vmware-vix-disklib") {
					kept = append(kept, p)
				}
			}
			return strings.Join(kept, ":")
		}).
		SetEnv("LIBGUESTFS_DEBUG", "1").
		Add("-v", "-x").
		Flag("-i", "libvirt").
		Flag("-ic", libvirtURL).
		Flag("-ip", passwordFile)

	nbdkitPlugin := "vddk"
	if info, err := os.Stat(vddkLibDir); err != nil || !info.IsDir() {
		nbdkitPlugin = "nfc"
	}
	cmdArgs.Flag("-it", nbdkitPlugin).
		FlagIf(thumbprint != "", "-io", fmt.Sprintf("%s-thumbprint=%s", nbdkitPlugin, thumbprint)).
		FlagIf(nbdkitPlugin == "vddk" && vddkLibDir != "", "-io", fmt.Sprintf("vddk-libdir=%s", vddkLibDir)).
		// virt-v2v-inspector estimates conversion output size; it doesn't need to
		// actually relabel SELinux contexts or trim filesystems to compute that
		// estimate, and both are expensive I/O passes over the whole guest disk.
		Add("--no-selinux-relabel", "--no-fstrim")

	baseDiskPaths, err := resolveBaseDiskPaths(diskInfo.BaseDiskPaths, func() ([]string, error) {
		return queryBaseDiskPathsFromVSphere(ctx, vcenterURL, username, password, vmMoref, i.logger)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to determine base disk paths for virt-v2v-inspector: %w", err)
	}
	for _, baseDiskPath := range baseDiskPaths {
		if baseDiskPath != "" {
			cmdArgs.Flag("-io", fmt.Sprintf("%s-file=%s", nbdkitPlugin, baseDiskPath))
		}
	}

	if args := diskUnlock.Args(); len(args) > 0 {
		cmdArgs.Add(args...)
	}

	// libvirt's vpx:// driver looks up domains by VM display name, not moref —
	// passing vmMoref here always fails with "Domain not found".
	if diskInfo.VMName == "" {
		return nil, fmt.Errorf("VM name is required for virt-v2v-inspector (vmMoref %s has no name)", vmMoref)
	}
	cmdArgs.Add("--", diskInfo.VMName)

	// XML goes to stdout, debug/error output to stderr. Stderr is streamed
	// line-by-line so phase markers appear in real time; stdout is buffered.
	stdout, stderr, err := cmdArgs.RunStreamedSeparate(ctx, i.virtV2vInspectorPath, func(line string) {
		if virtV2vProgressLine.MatchString(line) {
			i.logger.WithField("vm_moref", vmMoref).Info(line)
		}
	})
	if ctx.Err() != nil {
		return nil, fmt.Errorf("virt-v2v-inspector command was cancelled: %w", ctx.Err())
	}

	stdoutStr := string(stdout)
	stderrStr := string(stderr)
	if len(stderr) > 0 && i.logger != nil {
		i.logger.WithField("stderr", stderrStr).Debug("virt-v2v-inspector stderr output")
	}

	if err != nil {
		exitCode := cmdbuilder.ExitCode(err)

		// Check if this is likely an encrypted disk error (check both stdout and stderr)
		combinedOutput := stdoutStr + stderrStr
		if encrypted, reason := isEncryptedDiskError(combinedOutput); encrypted {
			i.logger.WithFields(logrus.Fields{
				"stdout":          stdoutStr,
				"stderr":          stderrStr,
				"exit_code":       exitCode,
				"executable":      i.virtV2vInspectorPath,
				"args":            cmdArgs.MaskedArgs(),
				"matched_pattern": reason,
			}).Error("virt-v2v-inspector failed - disk appears to be encrypted")

			switch diskUnlock.method {
			case unlockClevis:
				return nil, fmt.Errorf("disk encryption detected: virt-v2v-inspector could not unlock disk using clevis/NBDE. Exit code: %d", exitCode)
			case unlockKeyFiles:
				return nil, fmt.Errorf("disk encryption detected: virt-v2v-inspector could not unlock disk using %d LUKS key file(s) from %s. Exit code: %d", len(diskUnlock.keys), defaultLUKSKeyDir, exitCode)
			default:
				return nil, fmt.Errorf("disk encryption detected: virt-v2v-inspector cannot access encrypted disks. The VM disk appears to be encrypted and cannot be inspected without decryption. Exit code: %d", exitCode)
			}
		}

		i.logger.WithFields(logrus.Fields{
			"stdout":     stdoutStr,
			"stderr":     stderrStr,
			"exit_code":  exitCode,
			"executable": i.virtV2vInspectorPath,
			"args":       cmdArgs.MaskedArgs(),
		}).Error("virt-v2v-inspector failed")

		// Extract meaningful error lines from stderr for the error message.
		// Full output is already logged above.
		if summary := extractErrorSummary(stderrStr); summary != "" {
			return nil, fmt.Errorf("virt-v2v-inspector failed (exit code %d): %s", exitCode, summary)
		}
		return nil, fmt.Errorf("virt-v2v-inspector failed (exit code %d): %w", exitCode, err)
	}

	// Use stdout for XML parsing (stderr contains debug logs)
	inspectionData, err := parseV2VInspectionXML(stdout)
	if err != nil {
		if i.logger != nil {
			i.logger.WithFields(logrus.Fields{
				"error":  err,
				"stdout": stdoutStr,
				"stderr": stderrStr,
			}).Error("Failed to parse virt-v2v-inspector XML output")
		}
		return nil, fmt.Errorf("failed to parse virt-v2v-inspector output: %w", err)
	}

	i.logger.Info("virt-v2v-inspector snapshot inspection completed successfully")
	return inspectionData, nil
}

// extractHostname extracts hostname from a URL
func extractHostname(urlStr string) string {
	if urlStr == "" {
		return ""
	}

	// Try parsing as URL
	parsedURL, err := url.Parse(urlStr)
	if err == nil && parsedURL.Hostname() != "" {
		return parsedURL.Hostname()
	}

	// If parsing fails, assume it's already a hostname
	return urlStr
}

// resolveBaseDiskPaths returns existing when non-empty, otherwise the result of
// query. Separated from the vSphere call so the empty/populated/error branches
// are unit-testable without a live vCenter.
func resolveBaseDiskPaths(existing []string, query func() ([]string, error)) ([]string, error) {
	if len(existing) > 0 {
		return existing, nil
	}
	return query()
}

// queryBaseDiskPathsFromVSphere traverses the backing chain to get base disk
// paths. Mirrors VirtInspector.getBaseDiskPathsFromVSphere so virt-v2v-inspector
// works when the caller did not pre-populate diskInfo.BaseDiskPaths.
func queryBaseDiskPathsFromVSphere(ctx context.Context, vcenterURL, username, password, vmMoref string, logger *logrus.Logger) ([]string, error) {
	vsphereClient, err := vsphere.NewClient(ctx, vcenterURL, username, password, true, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to vSphere: %w", err)
	}
	defer vsphereClient.Close()

	baseDiskPaths, err := vsphereClient.GetBaseDiskPaths(ctx, vmMoref)
	if err != nil {
		return nil, fmt.Errorf("failed to get base disk paths: %w", err)
	}
	return baseDiskPaths, nil
}

// createPasswordFile creates a temporary file with the password
// virt-v2v-inspector expects -ip to be a file path, not the password directly
func (i *VirtV2vInspector) createPasswordFile(password string) (string, error) {
	tmpFile, err := os.CreateTemp("", "v2v-password-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary password file: %w", err)
	}

	// Write password to file
	if _, err := tmpFile.WriteString(password); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return "", fmt.Errorf("failed to write password to file: %w", err)
	}

	// Close the file
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpFile.Name())
		return "", fmt.Errorf("failed to close password file: %w", err)
	}

	// Set restrictive permissions (read-only for owner)
	if err := os.Chmod(tmpFile.Name(), 0600); err != nil {
		_ = os.Remove(tmpFile.Name())
		return "", fmt.Errorf("failed to set password file permissions: %w", err)
	}

	return tmpFile.Name(), nil
}

// parseV2VInspectionXML parses virt-v2v-inspector XML output and returns the native XML structure
func parseV2VInspectionXML(xmlData []byte) (*types.VirtV2VInspectorXML, error) {
	var xmlRoot types.VirtV2VInspectorXML
	err := xml.Unmarshal(xmlData, &xmlRoot)
	if err != nil {
		return nil, fmt.Errorf("XML parsing error: %w", err)
	}

	return &xmlRoot, nil
}
