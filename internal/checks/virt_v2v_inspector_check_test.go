package checks

import (
	"context"
	"errors"
	"testing"

	"github.com/kubev2v/vm-migration-detective/internal/persistent"
	"github.com/kubev2v/vm-migration-detective/pkg/types"
)

type fakeV2VInspector struct {
	v2vErr            error
	v2vCalled         bool
	v2vSSLVerifyCount int
}

func (f *fakeV2VInspector) InspectWithVirt(ctx context.Context, vm, snap string, di *types.SnapshotDiskInfo) (*types.VirtInspectorXML, error) {
	return nil, nil
}

func (f *fakeV2VInspector) InspectWithVirtV2v(ctx context.Context, vm, snap string, di *types.SnapshotDiskInfo, sslVerify string) (*types.VirtV2VInspectorXML, error) {
	f.v2vCalled = true
	f.v2vSSLVerifyCount++
	return nil, f.v2vErr
}

func (f *fakeV2VInspector) InspectLocal(ctx context.Context, args []string) (*types.VirtInspectorXML, error) {
	return nil, nil
}

func (f *fakeV2VInspector) GetDB() persistent.DB { return nil }

func (f *fakeV2VInspector) ExtractFileFromGuest(ctx context.Context, vmMoref string, snapshotMoref string, diskInfo *types.SnapshotDiskInfo, guestPath string, destDir string, rootDevice string) error {
	return nil
}

func TestVirtV2VInspectorCheck_ToolFailureBecomesConcern(t *testing.T) {
	fake := &fakeV2VInspector{v2vErr: errors.New("virt-v2v-inspector failed (exit code 1): unsupported guest OS")}
	params := InspectionParams{Ctx: context.Background(), VMMoref: "vm-1", SnapshotMoref: "snap-1", DiskInfo: &types.SnapshotDiskInfo{}, Inspector: fake}
	result := NewVirtV2VInspectorCheck().Run(params)
	if result.Passed {
		t.Fatalf("expected Passed=false")
	}
	if result.Error != nil {
		t.Fatalf("expected a Concern, not an Error, for a tool-reported failure, got Error=%v", *result.Error)
	}
	if len(result.Concerns) != 1 || result.Concerns[0].ID != "virt-v2v-dry-run-failed" {
		t.Fatalf("expected one concern with ID virt-v2v-dry-run-failed, got %+v", result.Concerns)
	}
}

func TestVirtV2VInspectorCheck_InfraFailureBecomesError(t *testing.T) {
	fake := &fakeV2VInspector{v2vErr: errors.New("failed to connect to vSphere: dial tcp: i/o timeout")}
	params := InspectionParams{Ctx: context.Background(), VMMoref: "vm-1", SnapshotMoref: "snap-1", DiskInfo: &types.SnapshotDiskInfo{}, Inspector: fake}
	result := NewVirtV2VInspectorCheck().Run(params)
	if result.Error == nil {
		t.Fatalf("expected an Error (check did not complete), not a Concern, for an infra failure")
	}
	if len(result.Concerns) != 0 {
		t.Fatalf("expected no concerns for an infra failure, got %+v", result.Concerns)
	}
}

func TestVirtV2VInspectorCheck_CallsInspectWithSSLVerifyArg(t *testing.T) {
	fake := &fakeV2VInspector{}
	params := InspectionParams{Ctx: context.Background(), VMMoref: "vm-1", SnapshotMoref: "snap-1", DiskInfo: &types.SnapshotDiskInfo{}, Inspector: fake}
	NewVirtV2VInspectorCheck().Run(params)
	if fake.v2vSSLVerifyCount != 1 {
		t.Fatalf("expected InspectWithVirtV2v to be called with an sslVerify arg, got %d calls", fake.v2vSSLVerifyCount)
	}
}

func TestVirtV2VInspectorCheck_Success(t *testing.T) {
	fake := &fakeV2VInspector{}
	params := InspectionParams{Ctx: context.Background(), VMMoref: "vm-1", SnapshotMoref: "snap-1", DiskInfo: &types.SnapshotDiskInfo{}, Inspector: fake}
	result := NewVirtV2VInspectorCheck().Run(params)
	if !result.Passed || result.Error != nil || len(result.Concerns) != 0 {
		t.Fatalf("expected a clean pass, got %+v", result)
	}
}
