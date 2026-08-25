package inspection

import (
	"strings"
	"testing"
)

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

func TestIsEncryptedDiskError_VerboseDebugFalsePositive(t *testing.T) {
	// Verbose -v -x output contains kernel boot messages, TLS cipher config,
	// and kernel module names that must NOT trigger the encryption detector.
	output := `error: some unrelated error
[    0.429261] Key type big_key registered
[    0.429582] Key type encrypted registered
[    0.429836] ima: No TPM chip found, activating TPM-bypass
nbdkit[in]: debug: lib/ssl: cipher list ECDHE+AESGCM:RSA+AESGCM:ECDHE+AES:RSA+AES
supermin: internal insmod crypto_engine.ko
supermin: internal insmod virtio_crypto.ko
nbdkit[in]: debug: aes-256-gcm negotiated`
	encrypted, reason := isEncryptedDiskError(output)
	if encrypted {
		t.Errorf("verbose debug output must not trigger encryption detection, matched: %q", reason)
	}
}

func TestExtractErrorSummary(t *testing.T) {
	cases := []struct {
		name     string
		stderr   string
		contains []string // substrings that must appear in the result
		empty    bool     // expect empty result
	}{
		{
			name:   "empty stderr",
			stderr: "",
			empty:  true,
		},
		{
			name: "virt-v2v error line extracted",
			stderr: `[   0.0] Setting up the source
libguestfs: trace: get_verbose
virt-v2v: error: no operating system was found on /dev/sda
libguestfs: closing handle`,
			contains: []string{"virt-v2v: error: no operating system was found"},
		},
		{
			name: "libguestfs error line extracted",
			stderr: `libguestfs: trace: launch
libguestfs: debug: blah blah
libguestfs: error: could not create appliance
libguestfs: trace: close`,
			contains: []string{"libguestfs: error: could not create appliance"},
		},
		{
			name: "multiple error lines joined",
			stderr: `virt-v2v: error: inspection could not detect the source guest
libguestfs: error: lvs: /dev/sda: unrecognised disk label`,
			contains: []string{
				"virt-v2v: error: inspection could not detect",
				"libguestfs: error: lvs:",
			},
		},
		{
			name: "deduplicates identical lines",
			stderr: `libguestfs: error: same error
libguestfs: error: same error`,
			contains: []string{"libguestfs: error: same error"},
		},
		{
			name: "fallback to last lines when no markers",
			stderr: `some debug output
more debug
the actual problem is here
final line`,
			contains: []string{"the actual problem is here", "final line"},
		},
		{
			name: "virt-v2v-inspector error line extracted",
			stderr: `debug: info: starting
virt-v2v-inspector: error: cannot open guest: connection refused
debug: closing`,
			contains: []string{"virt-v2v-inspector: error: cannot open guest"},
		},
		{
			name:     "truncates long output",
			stderr:   "libguestfs: error: " + strings.Repeat("x", 600),
			contains: []string{"libguestfs: error:"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractErrorSummary(tc.stderr)
			if tc.empty {
				if got != "" {
					t.Fatalf("expected empty, got %q", got)
				}
				return
			}
			if got == "" {
				t.Fatal("expected non-empty result")
			}
			for _, sub := range tc.contains {
				if !strings.Contains(got, sub) {
					t.Errorf("result %q does not contain %q", got, sub)
				}
			}
			if len(got) > maxErrorSummaryLen+10 {
				t.Errorf("result too long: %d chars", len(got))
			}
		})
	}
}

func TestExtractErrorSummary_DedupCount(t *testing.T) {
	stderr := `libguestfs: error: same error
libguestfs: error: same error
libguestfs: error: same error`
	got := extractErrorSummary(stderr)
	if count := strings.Count(got, "same error"); count != 1 {
		t.Errorf("expected 1 occurrence of 'same error', got %d in %q", count, got)
	}
}
