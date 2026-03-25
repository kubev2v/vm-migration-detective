package startup

import (
	"fmt"
	"os/exec"
	"strings"
)

// LibguestfsWrapper implements GuestfsInterface using guestfish commands
type LibguestfsWrapper struct {
	nbdURL string
}

// NewLibguestfsWrapper creates a new libguestfs wrapper for the given NBD URL
func NewLibguestfsWrapper(nbdURL string) *LibguestfsWrapper {
	return &LibguestfsWrapper{nbdURL: nbdURL}
}

// ReadFile reads a file from the VM filesystem
func (g *LibguestfsWrapper) ReadFile(path string) ([]byte, error) {
	cmd := exec.Command("guestfish", "--ro", "-a", g.nbdURL, "-i", "cat", path)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("guestfish cat %s failed: %w", path, err)
	}
	return output, nil
}

// ListDir lists directory contents
func (g *LibguestfsWrapper) ListDir(path string) ([]string, error) {
	cmd := exec.Command("guestfish", "--ro", "-a", g.nbdURL, "-i", "ls", path)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("guestfish ls %s failed: %w", path, err)
	}

	if len(output) == 0 {
		return []string{}, nil
	}

	files := strings.Split(strings.TrimSpace(string(output)), "\n")
	// Filter out empty strings
	var result []string
	for _, file := range files {
		if file != "" {
			result = append(result, file)
		}
	}
	return result, nil
}

// Exists checks if a path exists
func (g *LibguestfsWrapper) Exists(path string) bool {
	cmd := exec.Command("guestfish", "--ro", "-a", g.nbdURL, "-i", "exists", path)
	return cmd.Run() == nil
}

// IsDir checks if a path is a directory
func (g *LibguestfsWrapper) IsDir(path string) bool {
	cmd := exec.Command("guestfish", "--ro", "-a", g.nbdURL, "-i", "is-dir", path)
	return cmd.Run() == nil
}

// ReadLink reads a symbolic link
func (g *LibguestfsWrapper) ReadLink(path string) (string, error) {
	cmd := exec.Command("guestfish", "--ro", "-a", g.nbdURL, "-i", "readlink", path)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("guestfish readlink %s failed: %w", path, err)
	}
	return strings.TrimSpace(string(output)), nil
}

// IsSymlink checks if a path is a symbolic link
func (g *LibguestfsWrapper) IsSymlink(path string) bool {
	cmd := exec.Command("guestfish", "--ro", "-a", g.nbdURL, "-i", "is-symlink", path)
	return cmd.Run() == nil
}