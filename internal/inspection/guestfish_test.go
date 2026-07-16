package inspection

import "testing"

func TestParseDeviceParts(t *testing.T) {
	tests := []struct {
		name       string
		device     string
		wantLetter byte
		wantPart   string
		wantOK     bool
	}{
		{"empty", "", 0, "", false},
		{"sda2", "/dev/sda2", 'a', "2", true},
		{"sdb1", "/dev/sdb1", 'b', "1", true},
		{"sdc no partition", "/dev/sdc", 'c', "", true},
		{"vda1", "/dev/vda1", 'a', "1", true},
		{"xvdb2", "/dev/xvdb2", 'b', "2", true},
		{"hda1", "/dev/hda1", 'a', "1", true},
		{"sd no letter", "/dev/sd", 0, "", false},
		{"nvme not matched", "/dev/nvme0n1p2", 0, "", false},
		{"no dev prefix", "sda2", 'a', "2", true},
		{"garbage", "foobar", 0, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			letter, part, ok := ParseDeviceParts(tt.device)
			if letter != tt.wantLetter || part != tt.wantPart || ok != tt.wantOK {
				t.Errorf("ParseDeviceParts(%q) = (%c, %q, %v), want (%c, %q, %v)",
					tt.device, letter, part, ok, tt.wantLetter, tt.wantPart, tt.wantOK)
			}
		})
	}
}

func TestDiskDeviceToIndex(t *testing.T) {
	tests := []struct {
		name     string
		device   string
		expected int
	}{
		{"empty string", "", 0},
		{"sda no partition", "/dev/sda", 0},
		{"sda2", "/dev/sda2", 0},
		{"sdb1", "/dev/sdb1", 1},
		{"sdc", "/dev/sdc", 2},
		{"sdz", "/dev/sdz", 25},
		{"vda1", "/dev/vda1", 0},
		{"vdb3", "/dev/vdb3", 1},
		{"hda1", "/dev/hda1", 0},
		{"xvda1", "/dev/xvda1", 0},
		{"xvdb2", "/dev/xvdb2", 1},
		{"without dev prefix", "sda2", 0},
		{"unknown device format", "/dev/nvme0n1p2", 0},
		{"garbage input", "foobar", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DiskDeviceToIndex(tt.device)
			if result != tt.expected {
				t.Errorf("DiskDeviceToIndex(%q) = %d, want %d", tt.device, result, tt.expected)
			}
		})
	}
}
