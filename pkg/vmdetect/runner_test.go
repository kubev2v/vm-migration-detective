package vmdetect

import (
	"context"
	"errors"
	"testing"

	"github.com/kubev2v/vm-migration-detective/internal/persistent"
	"github.com/kubev2v/vm-migration-detective/pkg/types"
)

func TestNewDetectorLocalPathSkipsVSphereCreds(t *testing.T) {
	detector, err := NewDetector(DetectorConfig{})
	if err != nil {
		t.Fatalf("NewDetector with empty config: %v", err)
	}
	if detector == nil {
		t.Fatal("expected detector")
	}
}

func TestNewDetectorPartialVSphereConfigFails(t *testing.T) {
	_, err := NewDetector(DetectorConfig{VDDKLibDir: "/opt/vddk"})
	if err == nil {
		t.Fatal("expected error when VDDK is set without vSphere credentials")
	}
}

func TestDetectLocalRequiresCtxAndDisks(t *testing.T) {
	detector, err := NewDetector(DetectorConfig{})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := detector.DetectLocal(DetectLocalParams{DiskPaths: []string{"/disk.vhdx"}}); err == nil {
		t.Fatal("expected error when Ctx is nil")
	}
	if _, err := detector.DetectLocal(DetectLocalParams{Ctx: context.Background()}); err == nil {
		t.Fatal("expected error when DiskPaths is empty")
	}
}

func TestLocalInspectorArgsFormatBeforeDisk(t *testing.T) {
	got := localInspectorArgs(
		[]string{"/hyperv/disk0.vhdx", "/hyperv/disk1.vhd"},
		[]string{"vhdx", "vpc"},
	)
	want := []string{
		"--format=vhdx", "-a", "/hyperv/disk0.vhdx",
		"--format=vpc", "-a", "/hyperv/disk1.vhd",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

// mockInspector implements persistent.InspectorInterface for Detect tests.
type mockInspector struct {
	virtData     *types.VirtInspectorXML
	virtErr      error
	v2vData      *types.VirtV2VInspectorXML
	v2vErr       error
	v2vCalled    bool
	v2vSSLVerify string
}

func (m *mockInspector) InspectWithVirt(ctx context.Context, vm, snap string, di *types.SnapshotDiskInfo) (*types.VirtInspectorXML, error) {
	return m.virtData, m.virtErr
}

func (m *mockInspector) InspectWithVirtV2v(ctx context.Context, vm, snap string, di *types.SnapshotDiskInfo, sslVerify string) (*types.VirtV2VInspectorXML, error) {
	m.v2vCalled = true
	m.v2vSSLVerify = sslVerify
	return m.v2vData, m.v2vErr
}

func (m *mockInspector) InspectLocal(ctx context.Context, args []string) (*types.VirtInspectorXML, error) {
	return m.virtData, m.virtErr
}

func (m *mockInspector) GetDB() persistent.DB { return nil }

func (m *mockInspector) ExtractFileFromGuest(ctx context.Context, vm, snap string, di *types.SnapshotDiskInfo, guestPath, destDir, rootDevice string) error {
	return nil
}

// minimal virt-inspector XML so the OSInfo extraction path is exercised.
func sampleVirtXML() *types.VirtInspectorXML {
	x := &types.VirtInspectorXML{}
	x.Operatingsystems = []types.OS{{Name: "linux", Distro: "rhel"}}
	return x
}

func newTestDetector(m *mockInspector, sslVerify string) *Detector {
	return &Detector{
		inspector: m,
		sslVerify: sslVerify,
	}
}

func TestDetect_V2VDisabled_DoesNotCallV2V(t *testing.T) {
	m := &mockInspector{virtData: sampleVirtXML()}
	d := newTestDetector(m, "no_verify=1")

	// diskInfo is normally fetched from vSphere; inject via the test hook (Step 3).
	res, err := d.detectWithDiskInfo(context.Background(), "vm-1", "snap-1", &types.SnapshotDiskInfo{ComputeResourcePath: "/dc/cluster/host"}, CheckSelection{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.v2vCalled {
		t.Fatal("InspectWithVirtV2v must not be called when RunVirtV2v is false")
	}
	if res.V2VOSInfo != nil {
		t.Fatal("V2VOSInfo must be nil when v2v disabled")
	}
}

func TestDetect_V2VSuccess_PopulatesV2VOSInfo(t *testing.T) {
	v2v := &types.VirtV2VInspectorXML{}
	v2v.OS = types.VirtV2VInspectorOS{Name: "linux", Distro: "rhel", Arch: "x86_64", ProductName: "RHEL", Osinfo: "rhel9"}
	m := &mockInspector{virtData: sampleVirtXML(), v2vData: v2v}
	d := newTestDetector(m, "no_verify=1")

	res, err := d.detectWithDiskInfo(context.Background(), "vm-1", "snap-1", &types.SnapshotDiskInfo{ComputeResourcePath: "/dc/cluster/host"}, CheckSelection{RunVirtV2v: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !m.v2vCalled {
		t.Fatal("InspectWithVirtV2v must be called when RunVirtV2v is true")
	}
	if m.v2vSSLVerify != "no_verify=1" {
		t.Fatalf("sslVerify not forwarded, got %q", m.v2vSSLVerify)
	}
	if res.V2VOSInfo == nil || res.V2VOSInfo.Architecture != "x86_64" || res.V2VOSInfo.Product != "RHEL" || res.V2VOSInfo.OSInfo != "rhel9" {
		t.Fatalf("V2VOSInfo mapping wrong: %+v", res.V2VOSInfo)
	}
	for _, c := range res.AllConcerns {
		if c.ID == "virt-v2v-dry-run-failed" {
			t.Fatal("no failure concern expected on success")
		}
	}
}

func TestDetect_V2VFailure_AddsConcernAndFailsPassed(t *testing.T) {
	m := &mockInspector{virtData: sampleVirtXML(), v2vErr: errors.New("dry-run boom")}
	d := newTestDetector(m, "no_verify=1")

	res, err := d.detectWithDiskInfo(context.Background(), "vm-1", "snap-1", &types.SnapshotDiskInfo{ComputeResourcePath: "/dc/cluster/host"}, CheckSelection{RunVirtV2v: true})
	if err != nil {
		t.Fatalf("v2v failure must not fail Detect itself: %v", err)
	}
	if res.Passed {
		t.Fatal("Passed must be false when v2v dry-run fails")
	}
	found := false
	for _, c := range res.AllConcerns {
		if c.ID == "virt-v2v-dry-run-failed" {
			found = true
			if c.Category != ConcernCategoryCritical {
				t.Fatalf("expected Critical category, got %s", c.Category)
			}
		}
	}
	if !found {
		t.Fatal("expected virt-v2v-dry-run-failed concern")
	}
}
