package inspection

import "testing"

func TestIsEncryptedDiskError_GarbledOutput(t *testing.T) {
	// When virt-inspector is killed mid-execution, it can produce garbled output
	// containing "invalid or incomplete multibyte" sequences. Combined with a
	// generic error signal, this triggers a false positive for disk encryption.
	output := "error: invalid or incomplete multibyte or wide character\nfailed to read disk"
	encrypted, reason := isEncryptedDiskError(output)
	if !encrypted {
		t.Error("expected garbled kill output to match encryption heuristic")
	}
	if reason != "invalid multibyte sequence" {
		t.Errorf("expected reason 'invalid multibyte sequence', got %q", reason)
	}
}

func TestIsEncryptedDiskError_RealEncryption(t *testing.T) {
	output := "error: virt-inspector: disk encryption detected: LUKS encrypted volume found"
	encrypted, _ := isEncryptedDiskError(output)
	if !encrypted {
		t.Error("expected real encryption output to be detected")
	}
}

func TestIsEncryptedDiskError_CleanOutput(t *testing.T) {
	output := "inspection completed successfully"
	encrypted, _ := isEncryptedDiskError(output)
	if encrypted {
		t.Error("expected clean output not to match encryption heuristic")
	}
}
