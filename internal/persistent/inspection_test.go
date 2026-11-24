package persistent

import "testing"

func TestRemapDeviceForSingleDisk(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty string", "", "/dev/sda1"},
		{"sda2 stays sda2", "/dev/sda2", "/dev/sda2"},
		{"sdb2 becomes sda2", "/dev/sdb2", "/dev/sda2"},
		{"sdc1 becomes sda1", "/dev/sdc1", "/dev/sda1"},
		{"vda1 stays sda1", "/dev/vda1", "/dev/sda1"},
		{"vdb3 becomes sda3", "/dev/vdb3", "/dev/sda3"},
		{"hda1 stays sda1", "/dev/hda1", "/dev/sda1"},
		{"xvdb2 becomes sda2", "/dev/xvdb2", "/dev/sda2"},
		{"sda no partition", "/dev/sda", "/dev/sda"},
		{"sdb no partition", "/dev/sdb", "/dev/sda"},
		{"unknown format passed through", "/dev/nvme0n1p2", "/dev/nvme0n1p2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := remapDeviceForSingleDisk(tt.input)
			if result != tt.expected {
				t.Errorf("remapDeviceForSingleDisk(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
