package inspection

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kubev2v/vm-migration-detective/pkg/types"
	"github.com/sirupsen/logrus"
)

func TestResolveBaseDiskPaths_UsesExistingWhenPresent(t *testing.T) {
	called := false
	got, err := resolveBaseDiskPaths([]string{"[ds] vm/vm.vmdk"}, func() ([]string, error) {
		called = true
		return nil, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called {
		t.Fatal("query must not run when BaseDiskPaths already populated")
	}
	if len(got) != 1 || got[0] != "[ds] vm/vm.vmdk" {
		t.Fatalf("expected existing paths returned, got %v", got)
	}
}

func TestResolveBaseDiskPaths_QueriesWhenEmpty(t *testing.T) {
	got, err := resolveBaseDiskPaths(nil, func() ([]string, error) {
		return []string{"[ds] vm/disk1.vmdk", "[ds] vm/disk2.vmdk"}, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected queried paths, got %v", got)
	}
}

func TestResolveBaseDiskPaths_PropagatesQueryError(t *testing.T) {
	_, err := resolveBaseDiskPaths(nil, func() ([]string, error) {
		return nil, errors.New("vsphere boom")
	})
	if err == nil {
		t.Fatal("expected query error to propagate")
	}
}

func TestVirtV2vProgressLine(t *testing.T) {
	cases := []struct {
		line  string
		match bool
	}{
		{"[   0.0] Setting up the source: -i libvirt -ic vpx://user@host -it vddk vm-name", true},
		{"[  12.3] Opening the overlay", true},
		{"[0.0] no leading spaces", true},
		{"[  59.1] Checking filesystem integrity before conversion", true},
		{"[ 472.4] Detecting if this guest uses BIOS or UEFI to boot", true},
		{"[ 494.2] Inspecting the source", true},
		{"[ 755.4] Detecting the boot device", true},
		{"[ 755.5] Converting Red Hat Enterprise Linux 9.4 (Plow) (rhel9.4) to run on KVM", true},
		{"virt-v2v-inspector: debug: info: virt-v2v-inspector: virt-v2v 2.12.0", false},
		{"libguestfs: closing guestfs handle 0x56312ebac020 (state 0)", false},
		// Guest kernel dmesg lines the internal appliance also emits under -v -x,
		// using the same bracket style but microsecond precision — must not leak
		// into live logs (this was a real bug: the earlier regex matched these).
		{"[    0.235524] DMA: preallocated 512 KiB GFP_KERNEL|GFP_DMA32 pool for atomic allocations", false},
		{"[   31.607393] 8021q: 802.1Q VLAN Support v1.8", false},
		{"[    1.142210] ata2: SATA link down (SStatus 0 SControl 300)", false},
		{"[   35.977196] SGI XFS with ACLs, security attributes, realtime, scrub, repair, quota, no debug enabled", false},
		{"", false},
	}
	for _, c := range cases {
		got := virtV2vProgressLine.MatchString(c.line)
		if got != c.match {
			t.Errorf("virtV2vProgressLine.MatchString(%q) = %v, want %v", c.line, got, c.match)
		}
	}
}

// TestInspect_MissingVMName_ReturnsError guards against regressing to
// libvirt's vpx:// driver requiring a VM display name, not its vSphere
// moref, as the domain lookup argument. diskInfo.BaseDiskPaths is
// pre-populated so the vSphere base-disk query is skipped, and the
// vcenterURL host uses the RFC 2606 .invalid TLD so the thumbprint lookup
// fails fast without any real network dependency.
func TestInspect_MissingVMName_ReturnsError(t *testing.T) {
	inspector := NewVirtV2vInspector("", logrus.New())
	diskInfo := &types.SnapshotDiskInfo{
		ComputeResourcePath: "/dc/cluster/host",
		BaseDiskPaths:       []string{"[ds] vm/vm.vmdk"},
		VMName:              "",
	}

	_, err := inspector.Inspect(context.Background(), "vm-100845", "snap-1",
		"https://vcenter.does-not-exist.invalid/sdk", "user", "pass", diskInfo, "no_verify=1")

	if err == nil {
		t.Fatal("expected error when diskInfo.VMName is empty")
	}
	if !strings.Contains(err.Error(), "VM name is required") {
		t.Fatalf("expected VM-name-required error, got: %v", err)
	}
}
