package inspection

import (
	"errors"
	"testing"

	"github.com/kubev2v/vm-migration-detective/internal/tlsconfig"
)

func TestResolveNBDKitThumbprint_UsesConfiguredThumbprintWithoutComputing(t *testing.T) {
	cfg := &tlsconfig.Config{Insecure: false, Thumbprint: "AA:BB"}
	called := false
	computeFn := func(string, *tlsconfig.Config) (string, error) {
		called = true
		return "should-not-be-used", nil
	}

	got, err := resolveNBDKitThumbprint(cfg, "vcenter.example.com", nil, computeFn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "AA:BB" {
		t.Fatalf("expected configured thumbprint AA:BB, got %q", got)
	}
	if called {
		t.Fatal("computeFn must not be called when a thumbprint is already configured")
	}
}

func TestResolveNBDKitThumbprint_InsecureMode_ComputesAndUsesThumbprint(t *testing.T) {
	cfg := &tlsconfig.Config{Insecure: true}
	computeFn := func(string, *tlsconfig.Config) (string, error) {
		return "CC:DD", nil
	}

	got, err := resolveNBDKitThumbprint(cfg, "vcenter.example.com", nil, computeFn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "CC:DD" {
		t.Fatalf("expected computed thumbprint CC:DD in insecure mode, got %q", got)
	}
}

func TestResolveNBDKitThumbprint_InsecureMode_ComputeFailureIsNonFatal(t *testing.T) {
	cfg := &tlsconfig.Config{Insecure: true}
	computeFn := func(string, *tlsconfig.Config) (string, error) {
		return "", errors.New("dial failed")
	}

	got, err := resolveNBDKitThumbprint(cfg, "vcenter.example.com", nil, computeFn)
	if err != nil {
		t.Fatalf("expected no error in insecure mode when computation fails, got %v", err)
	}
	if got != "" {
		t.Fatalf("expected empty thumbprint when computation fails, got %q", got)
	}
}

func TestResolveNBDKitThumbprint_NonInsecureMode_ComputeFailureIsFatal(t *testing.T) {
	cfg := &tlsconfig.Config{Insecure: false}
	computeFn := func(string, *tlsconfig.Config) (string, error) {
		return "", errors.New("dial failed")
	}

	_, err := resolveNBDKitThumbprint(cfg, "vcenter.example.com", nil, computeFn)
	if err == nil {
		t.Fatal("expected an error when thumbprint computation fails outside insecure mode")
	}
}
