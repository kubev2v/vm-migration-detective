package inspection

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kubev2v/vm-migration-detective/internal/cmdbuilder"
	"github.com/kubev2v/vm-migration-detective/pkg/types"
	"github.com/sirupsen/logrus"
)

// VirtV2vInspector handles VM inspection operations using virt-v2v-inspector
type VirtV2vInspector struct {
	virtV2vInspectorPath string
	timeout              time.Duration
	logger               *logrus.Logger
}

// NewVirtV2vInspector creates a new VirtV2vInspector instance
func NewVirtV2vInspector(virtV2vInspectorPath string, timeout time.Duration, logger *logrus.Logger) *VirtV2vInspector {
	if virtV2vInspectorPath == "" {
		virtV2vInspectorPath = "virt-v2v-inspector" // Use system PATH
	}
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	return &VirtV2vInspector{
		virtV2vInspectorPath: virtV2vInspectorPath,
		timeout:              timeout,
		logger:               logger,
	}
}

// Inspect uses virt-v2v-inspector to inspect a VM snapshot via nbdkit-vddk,
// mirroring the approach used by VirtInspector.
// It retries once on cold-start VDDK failures (same known bug as VirtInspector).
func (i *VirtV2vInspector) Inspect(
	ctx context.Context,
	vmMoref string,
	snapshotMoref string,
	vcenterURL string,
	username string,
	password string,
	diskInfo *types.SnapshotDiskInfo,
) (*types.VirtV2VInspectorXML, error) {
	result, err := i.attemptInspect(ctx, vmMoref, snapshotMoref, vcenterURL, username, password, diskInfo)
	if err != nil && strings.Contains(err.Error(), "cold-start") {
		if i.logger != nil {
			i.logger.WithError(err).Warn("virt-v2v-inspector failed with cold-start symptoms, retrying once")
		}
		time.Sleep(2 * time.Second)
		result, err = i.attemptInspect(ctx, vmMoref, snapshotMoref, vcenterURL, username, password, diskInfo)
		if err == nil && i.logger != nil {
			i.logger.Info("virt-v2v-inspector succeeded on retry (VDDK cold-start issue worked around)")
		}
	}
	return result, err
}

func (i *VirtV2vInspector) attemptInspect(
	ctx context.Context,
	vmMoref string,
	snapshotMoref string,
	vcenterURL string,
	username string,
	password string,
	diskInfo *types.SnapshotDiskInfo,
) (*types.VirtV2VInspectorXML, error) {
	i.logger.WithFields(logrus.Fields{
		"vm_moref":       vmMoref,
		"snapshot_moref": snapshotMoref,
		"vcenter_url":    vcenterURL,
	}).Info("Running virt-v2v-inspector using nbdkit-vddk (VDDK + snapshot)")

	// Query vSphere to get base disk paths by traversing the backing chain
	baseDiskPaths, err := getBaseDiskPathsFromVSphere(ctx, vcenterURL, username, password, diskInfo.VMMoref, i.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to query base disk paths from vSphere: %w", err)
	}

	// Build vpx:// URL with username
	// virt-v2v-inspector extracts the username from this URL to pass to VDDK internally
	// Password is kept secure in separate file via -ip parameter
	// Add SSL verification parameter (provided by caller)
	libvirtURL := fmt.Sprintf("vpx://%s@%s%s?%s",
		encodedUsername, bracketIPv6(vcenterHost), computeResourcePath, sslVerify)
	i.logger.WithFields(logrus.Fields{
		"disk_count":      len(baseDiskPaths),
		"base_disk_paths": baseDiskPaths,
	}).Info("Queried base disk paths from vSphere")

	openCtx, cancel := context.WithTimeout(ctx, i.timeout)
	defer cancel()

	// Start one nbdkit session per disk
	var nbdkitSessions []*NBDKitSession
	var nbdURLs []string

	for idx, baseDiskPath := range baseDiskPaths {
		i.logger.WithFields(logrus.Fields{
			"disk_index":     idx,
			"base_disk_path": baseDiskPath,
		}).Debug("Starting NBDkit session for disk")

		session, err := OpenWithNBDKitVDDK(
			openCtx,
			diskInfo.VMMoref,
			diskInfo.SnapshotMoref,
			baseDiskPath,
			vcenterURL,
			username,
			password,
			i.logger,
		)
		if err != nil {
			for _, s := range nbdkitSessions {
				s.Close()
			}
			return nil, fmt.Errorf("failed to start NBDkit session for disk %d: %w", idx, err)
		}
		nbdkitSessions = append(nbdkitSessions, session)
		nbdURLs = append(nbdURLs, session.NBDURL)

		if err := session.WaitForReady(30 * time.Second); err != nil {
			i.logger.WithError(err).WithField("disk_index", idx).Error("NBD server not ready")
			for _, s := range nbdkitSessions {
				s.Close()
			}
			return nil, fmt.Errorf("NBD server not ready for disk %d: %w", idx, err)
		}
	}
	defer func() {
		for _, s := range nbdkitSessions {
			s.Close()
		}
	}()

	inspectCtx, cancel2 := context.WithTimeout(ctx, i.timeout)
	defer cancel2()

	i.logger.WithFields(logrus.Fields{
		"nbd_urls":   nbdURLs,
		"disk_count": len(nbdURLs),
	}).Info("Running virt-v2v-inspector on NBD")

	diskUnlock := resolveDiskUnlock(i.logger)

	cmdArgs := cmdbuilder.New().
		WithLogger(i.logger).
		UnsetEnv("LD_LIBRARY_PATH").
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
		FlagIf(nbdkitPlugin == "vddk" && vddkLibDir != "", "-io", fmt.Sprintf("vddk-libdir=%s", vddkLibDir))

	for _, baseDiskPath := range diskInfo.BaseDiskPaths {
		if baseDiskPath != "" {
			cmdArgs.Flag("-io", fmt.Sprintf("%s-file=%s", nbdkitPlugin, baseDiskPath))
		}
	}
	cmdArgs.Flag("-i", "disk").
		Flag("-if", "raw")

	if args := diskUnlock.Args(); len(args) > 0 {
		cmdArgs.Add(args...)
	}

	// Disk images are positional arguments when using -i disk
	cmdArgs.Add("--")
	for _, url := range nbdURLs {
		cmdArgs.Add(url)
	}

	// XML goes to stdout; debug messages (-v -x) go to stderr.
	// Stream stderr in real time so progress is visible during the inspection run.
	stdoutBytes, stderrBytes, err := cmdArgs.RunSeparateStream(inspectCtx, i.virtV2vInspectorPath, os.Stderr)
	if inspectCtx.Err() != nil {
		if inspectCtx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("virt-v2v-inspector command timed out after %v", i.timeout)
		}
		return nil, fmt.Errorf("virt-v2v-inspector command was cancelled: %w", inspectCtx.Err())
	}

	stdoutStr := string(stdoutBytes)
	// stderrBytes is kept only for encrypted-disk pattern detection; the content
	// was already streamed live to os.Stderr so we do not log it again.
	combinedStr := stdoutStr + string(stderrBytes)
	if err != nil {
		exitCode := cmdbuilder.ExitCode(err)

		// Check if this is likely an encrypted disk error
		if encrypted, reason := isEncryptedDiskError(combinedStr); encrypted {
			i.logger.WithFields(logrus.Fields{
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

		// Detect cold-start VDDK failure from stderr (content was already streamed
		// live to os.Stderr, so we only embed a short sentinel — not the full output).
		if isColdStartOutput(string(stderrBytes)) {
			i.logger.WithFields(logrus.Fields{
				"exit_code":  exitCode,
				"executable": i.virtV2vInspectorPath,
				"args":       cmdArgs.MaskedArgs(),
			}).Error("virt-v2v-inspector failed with cold-start symptoms")
			return nil, fmt.Errorf("virt-v2v-inspector cold-start failure (exit code %d): %w", exitCode, err)
		}

		i.logger.WithFields(logrus.Fields{
			"exit_code":  exitCode,
			"executable": i.virtV2vInspectorPath,
			"args":       cmdArgs.MaskedArgs(),
		}).Error("virt-v2v-inspector failed")

		if stdoutStr != "" {
			return nil, fmt.Errorf("virt-v2v-inspector failed (exit code %d): %w\nStdout: %s", exitCode, err, stdoutStr)
		}
		return nil, fmt.Errorf("virt-v2v-inspector failed (exit code %d): %w", exitCode, err)
	}

	// Extract XML from stdout (debug messages are on stderr now).
	// Keep the marker search as a safety net in case any debug lines slip through.
	xmlStart := strings.Index(stdoutStr, "<?xml")
	if xmlStart == -1 {
		xmlStart = strings.Index(stdoutStr, "<v2v-inspection")
	}
	if xmlStart == -1 {
		xmlStart = strings.Index(stdoutStr, "<operatingsystem")
	}
	if xmlStart == -1 {
		xmlStart = strings.Index(stdoutStr, "<inspection")
	}

	var xmlData []byte
	if xmlStart >= 0 {
		xmlData = []byte(stdoutStr[xmlStart:])
		xmlEnd := strings.LastIndex(string(xmlData), "</v2v-inspection>")
		if xmlEnd > 0 {
			xmlEnd += len("</v2v-inspection>")
			xmlData = xmlData[:xmlEnd]
		} else {
			xmlEnd = strings.LastIndex(string(xmlData), "</operatingsystem>")
			if xmlEnd > 0 {
				xmlEnd += len("</operatingsystem>")
				xmlData = xmlData[:xmlEnd]
			}
		}
		if i.logger != nil {
			xmlPreview := string(xmlData)
			if len(xmlPreview) > 1000 {
				xmlPreview = xmlPreview[:1000] + "... (truncated)"
			}
			i.logger.WithField("xml_extracted", xmlPreview).Debug("Extracted XML from stdout")
		}
	} else {
		xmlData = stdoutBytes
		if i.logger != nil {
			i.logger.Warn("No XML markers found in stdout, attempting to parse entire stdout")
		}
	}

	inspectionData, err := parseV2VInspectionXML(xmlData)
	if err != nil {
		if i.logger != nil {
			i.logger.WithFields(logrus.Fields{
				"error":  err,
				"stdout": stdoutStr,
			}).Error("Failed to parse virt-v2v-inspector XML output")
		}
		return nil, fmt.Errorf("failed to parse virt-v2v-inspector output: %w", err)
	}

	i.logger.Info("virt-v2v-inspector snapshot inspection completed successfully")
	return inspectionData, nil
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
