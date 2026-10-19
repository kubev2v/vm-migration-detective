package inspection

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
)

// ErrFileTooLarge is returned when the guest file exceeds the size limit
var ErrFileTooLarge = errors.New("file size exceeds limit")

var devicePrefixes = []string{"sd", "vd", "hd", "xvd"}

// ParseDeviceParts extracts the disk letter and partition string from a Linux device path.
// For "/dev/sdb2" returns ('b', "2", true). For "/dev/xvda" returns ('a', "", true).
// Returns (0, "", false) if device is empty or doesn't match a known prefix.
func ParseDeviceParts(device string) (diskLetter byte, partition string, ok bool) {
	if device == "" {
		return 0, "", false
	}
	dev := strings.TrimPrefix(device, "/dev/")
	for _, prefix := range devicePrefixes {
		if strings.HasPrefix(dev, prefix) {
			rest := dev[len(prefix):]
			if len(rest) == 0 {
				return 0, "", false
			}
			letter := rest[0]
			if letter < 'a' || letter > 'z' {
				return 0, "", false
			}
			return letter, rest[1:], true
		}
	}
	return 0, "", false
}

// DiskDeviceToIndex parses a Linux device path from virt-inspector (e.g., "/dev/sda2")
// and returns the disk index (sda=0, sdb=1, sdc=2, ...).
// Returns 0 if the device string is empty or unparseable (safe fallback to first disk).
func DiskDeviceToIndex(rootDevice string) int {
	letter, _, ok := ParseDeviceParts(rootDevice)
	if !ok {
		return 0
	}
	return int(letter - 'a')
}

// CopyFileWithSizeCheck extracts a file from guest VM using guestfish copy-out.
// Uses explicit mount point (-m device:/) instead of auto-inspect (-i) to avoid
// hanging on multi-disk VMs.
//
// Parameters:
//   - ctx: Context for cancellation and timeout enforcement
//   - nbdURL: NBD connection URL (e.g., "nbd+unix:///?socket=/tmp/nbdkit-xyz.sock")
//   - mountDevice: Guest device to mount (e.g., "/dev/sda2" from virt-inspector Root field)
//   - guestPath: Path to file in guest filesystem (e.g., "/Windows/System32/winevt/Logs/System.evtx")
//   - destDir: Destination directory on host (e.g., "/tmp/bsod-check-12345")
//   - maxSizeBytes: Maximum file size allowed (0 = no limit)
//   - logger: Logger instance
//
// Returns:
//   - File size in bytes
//   - Error if file doesn't exist, too large, timeout exceeded, or can't be copied
func CopyFileWithSizeCheck(
	ctx context.Context,
	nbdURL string,
	mountDevice string,
	guestPath string,
	destDir string,
	maxSizeBytes int64,
	logger *logrus.Logger,
) (int64, error) {
	if !strings.HasPrefix(guestPath, "/") {
		return 0, fmt.Errorf("guest path must be absolute: %s", guestPath)
	}
	if strings.ContainsAny(guestPath, ";\n\r&|`$(){}[]<>*?!~'\"\\") {
		return 0, fmt.Errorf("guest path contains potentially unsafe characters: %s", guestPath)
	}
	if mountDevice == "" {
		return 0, fmt.Errorf("mount device must be specified (e.g., /dev/sda2)")
	}

	destInfo, err := os.Stat(destDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, fmt.Errorf("destination directory does not exist: %s", destDir)
		}
		return 0, fmt.Errorf("failed to validate destination directory: %w", err)
	}
	if !destInfo.IsDir() {
		return 0, fmt.Errorf("destination path is not a directory: %s", destDir)
	}

	mountArg := mountDevice + ":/"

	if logger != nil {
		logger.WithFields(logrus.Fields{
			"nbd_url":        nbdURL,
			"mount_device":   mountDevice,
			"guest_path":     guestPath,
			"dest_dir":       destDir,
			"max_size_bytes": maxSizeBytes,
		}).Info("Starting guestfish file extraction with size check")
	}

	// Step 1: Check file size via guestfish filesize
	sizeCmd := exec.CommandContext(ctx, "guestfish",
		"--ro",
		"--format=raw",
		"-a", nbdURL,
		"-m", mountArg,
		"filesize", guestPath,
	)

	sizeOutput, err := sizeCmd.CombinedOutput()
	if err != nil {
		if logger != nil {
			logger.WithError(err).WithFields(logrus.Fields{
				"output": string(sizeOutput),
			}).Error("guestfish filesize failed")
		}
		return 0, fmt.Errorf("guestfish filesize failed: %w (output: %s)", err, strings.TrimSpace(string(sizeOutput)))
	}

	var fileSize int64
	sizeStr := strings.TrimSpace(string(sizeOutput))
	if _, err := fmt.Sscanf(sizeStr, "%d", &fileSize); err != nil {
		return 0, fmt.Errorf("failed to parse file size from guestfish output %q: %w", sizeStr, err)
	}

	if logger != nil {
		logger.WithFields(logrus.Fields{
			"guest_path": guestPath,
			"size_bytes": fileSize,
			"size_mb":    fileSize / (1024 * 1024),
		}).Debug("File size check completed")
	}

	if maxSizeBytes > 0 && fileSize > maxSizeBytes {
		if logger != nil {
			logger.WithFields(logrus.Fields{
				"guest_path":     guestPath,
				"size_bytes":     fileSize,
				"size_mb":        fileSize / (1024 * 1024),
				"max_size_bytes": maxSizeBytes,
				"max_size_mb":    maxSizeBytes / (1024 * 1024),
			}).Warn("File size exceeds limit")
		}
		return fileSize, fmt.Errorf("%w: file size %d bytes exceeds limit of %d bytes", ErrFileTooLarge, fileSize, maxSizeBytes)
	}

	// Step 2: Copy file via guestfish copy-out
	copyCmd := exec.CommandContext(ctx, "guestfish",
		"--ro",
		"--format=raw",
		"-a", nbdURL,
		"-m", mountArg,
		"copy-out", guestPath, destDir,
	)

	if copyOutput, err := copyCmd.CombinedOutput(); err != nil {
		if logger != nil {
			logger.WithError(err).WithFields(logrus.Fields{
				"output": string(copyOutput),
			}).Error("guestfish copy-out failed")
		}
		return fileSize, fmt.Errorf("guestfish copy-out failed: %w (output: %s)", err, strings.TrimSpace(string(copyOutput)))
	}

	// Verify copied file exists and matches expected size
	destPath := filepath.Join(destDir, filepath.Base(guestPath))
	destStat, err := os.Stat(destPath)
	if err != nil {
		return fileSize, fmt.Errorf("copied file not found at %s: %w", destPath, err)
	}
	if destStat.Size() != fileSize {
		return fileSize, fmt.Errorf("partial copy: got %d bytes, expected %d", destStat.Size(), fileSize)
	}

	if logger != nil {
		logger.WithFields(logrus.Fields{
			"guest_path": guestPath,
			"dest_dir":   destDir,
			"size_bytes": fileSize,
			"size_mb":    fileSize / (1024 * 1024),
		}).Info("File extraction with size check completed successfully")
	}

	return fileSize, nil
}
