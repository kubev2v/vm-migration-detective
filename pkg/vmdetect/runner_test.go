package vmdetect

import (
	"context"
	"testing"
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

func TestDetectNBDValidation(t *testing.T) {
	detector, err := NewDetector(DetectorConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := detector.DetectNBD(DetectNBDParams{NBDURLs: []string{"nbd://10.0.0.1:10809"}}); err == nil {
		t.Fatal("expected error when Ctx is nil")
	}
	if _, err := detector.DetectNBD(DetectNBDParams{Ctx: context.Background()}); err == nil {
		t.Fatal("expected error when NBDURLs is empty")
	}
	if _, err := detector.DetectNBD(DetectNBDParams{Ctx: context.Background(), NBDURLs: []string{"nbds://10.0.0.1:10809"}}); err == nil {
		t.Fatal("expected error when nbds:// lacks TLSCertificates")
	}
}
